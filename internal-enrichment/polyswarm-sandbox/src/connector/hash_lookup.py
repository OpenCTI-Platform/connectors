"""Sandbox reports by hash: lookup of existing reports and detonate-by-hash.

Mixed into ``PolySwarmConnector``. Two features live here:

- Lookup (the lookup itself is read only, on by default). A StixFile observable has a hash and no
  file, so the latest existing PolySwarm sandbox report for its SHA-256 is
  fetched for each configured provider and turned into exactly the output a
  detonation produces (via the connector's shared result path). An Artifact
  can reuse the same reports instead of being uploaded again.
- Detonate by hash (off by default, spends sandbox credits). When no usable
  report exists, the sample PolySwarm already holds for the hash is detonated.
  Nothing is uploaded from OpenCTI.

Only a hash is ever sent to PolySwarm by this module. Producing the reports is
not free of side effects: a PDF report is generated in the PolySwarm account
for each report found (when PDF reports are on), and an LLM report is created
when those are on. These may count against report quota.
"""

from datetime import datetime, timedelta, timezone
from typing import Any

from connector.polyswarm_client import PolySwarmAPIError, PolySwarmClient
from connector.scan_processor import ScanProcessor

_HASH_PREFERENCE = (("SHA-256", 64), ("SHA-1", 40), ("MD5", 32))


class HashLookupMixin:
    """Lookup by hash and detonate-by-hash, using the connector's own helpers."""

    # -- helpers

    @staticmethod
    def _entity_hashes(entity: dict[str, Any]) -> dict[str, str]:
        """Hashes of an entity as {"SHA-256": ..., "SHA-1": ..., "MD5": ...}."""
        hashes = entity.get("hashes") or {}
        found: dict[str, str] = {}
        if isinstance(hashes, dict):
            items = hashes.items()
        else:
            items = [
                (h.get("algorithm"), h.get("hash"))
                for h in hashes
                if isinstance(h, dict)
            ]
        for algo, value in items:
            if algo and value:
                found[
                    str(algo)
                    .upper()
                    .replace("SHA256", "SHA-256")
                    .replace("SHA1", "SHA-1")
                ] = str(value)
        return found

    def _report_usable(self, task: dict | None) -> bool:
        """A finished (successful) report that is not older than the age limit."""
        if not task or not PolySwarmClient.is_sandbox_success(
            str(task.get("status", ""))
        ):
            return False
        max_age = self.config.polyswarm.sandbox_lookup_max_age_days
        if not isinstance(max_age, int) or isinstance(max_age, bool) or max_age <= 0:
            return True
        try:
            created = datetime.fromisoformat(
                str(task.get("created", "")).replace("Z", "+00:00")
            )
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
        except ValueError:
            return False
        return datetime.now(timezone.utc) - created <= timedelta(days=max_age)

    def _lookup_reports(
        self, sha256: str, providers: list[str]
    ) -> tuple[dict[str, dict], list[str]]:
        """Latest usable report per provider, and the providers that have none."""
        found: dict[str, dict] = {}
        missing: list[str] = []
        for provider in providers:
            task = self.polyswarm_client.get_latest_sandbox_task(sha256, provider)
            if self._report_usable(task):
                found[provider] = task
            else:
                missing.append(provider)
        return found, missing

    def _send_info_note(
        self,
        entity: dict[str, Any],
        title: str,
        detail: str,
        next_steps: list[str] | None = None,
    ) -> None:
        """Attach a plain (non-error) note to the observable."""
        try:
            note = self.stix_builder.create_info_note(
                entity=entity, title=title, detail=detail, next_steps=next_steps
            )
            author = self.stix_builder._create_author()
            bundle = self.helper.stix2_create_bundle([author, note])
            self.helper.send_stix2_bundle(
                bundle, update=True, cleanup_inconsistent_bundle=True
            )
            self.helper.connector_logger.info(f"[CONNECTOR] Note created: {title}")
        except (ValueError, TypeError, RuntimeError, KeyError, AttributeError) as e:
            self.helper.connector_logger.warning(
                f"[CONNECTOR] Failed to create note: {type(e).__name__}: {e}"
            )

    def _deliver_reports(
        self,
        entity: dict[str, Any],
        results: dict[str, dict | None],
        task_ids: dict[str, str],
        lookup_hash: str,
        filename: str,
        stix_objects: list,
        scan_id: str | None = None,
        scan_res: dict | None = None,
        llm_task_ids: dict[str, str] | None = None,
    ) -> None:
        """Shared result path: process, attach reports, build and send the bundle."""
        llm_task_ids = {} if llm_task_ids is None else llm_task_ids
        scan_mapped = None
        if scan_res and not scan_res.get("failed"):
            scan_mapped = ScanProcessor.process(scan_res, scan_id=scan_id)
        sandbox_processed, sandbox_failures = self._process_sandbox_results(results)
        llm_reports = self._phase_reports(
            entity,
            scan_id,
            scan_res,
            scan_mapped,
            task_ids,
            results,
            llm_task_ids,
            filename,
            lookup_hash,
        )
        self._phase_stix(
            entity,
            scan_mapped,
            None,
            sandbox_processed,
            sandbox_failures,
            llm_reports,
            stix_objects,
        )

    def _fire_llm_for_existing(
        self,
        found: dict[str, dict],
        scan_id: str | None = None,
        scan_res: dict | None = None,
    ) -> dict[str, str]:
        """Start the opt-in LLM reports for reports that already exist."""
        llm_task_ids: dict[str, str] = {}
        if self.config.polyswarm.llm_report_enabled is not True:
            return llm_task_ids
        for provider, task in found.items():
            llm_id = self.polyswarm_client.create_llm_report(
                sandbox_task_id=task.get("id"), provider=provider
            )
            if llm_id:
                llm_task_ids[provider] = llm_id
        if scan_id and scan_res and not scan_res.get("failed"):
            llm_id = self.polyswarm_client.create_llm_report(instance_id=scan_id)
            if llm_id:
                llm_task_ids["scan"] = llm_id
        return llm_task_ids

    # -- Artifact: reuse an existing report instead of uploading again

    def _try_reuse_existing_reports(
        self,
        entity: dict[str, Any],
        lookup_hash: str | None,
        filename: str,
        stix_objects: list,
    ) -> bool:
        """Use existing reports for an Artifact when every provider has one.

        Returns True when the enrichment was completed from existing reports
        and an existing finished scan (nothing was uploaded). Returns False to let the normal upload path
        run: reuse is off, the sandbox is off, the Artifact has no SHA-256,
        at least one provider has no usable report, or there is no finished
        scan of the hash.
        """
        ps = self.config.polyswarm
        if (
            ps.sandbox_reuse_report is not True
            or ps.sandbox_enabled is not True
            or not lookup_hash
        ):
            return False
        try:
            providers = self._get_sandbox_providers()
            found, missing = self._lookup_reports(lookup_hash, providers)
        except PolySwarmAPIError as e:
            if e.is_quota_exhausted:
                # A second request (the upload) would hit the same 429. End the
                # enrichment so the quota note is attached instead.
                raise
            self.helper.connector_logger.warning(
                f"[CONNECTOR] {self._enrich_ctx} Report lookup failed, uploading "
                f"instead: {e.category}"
            )
            return False
        if missing or not found:
            self.helper.connector_logger.info(
                f"[CONNECTOR] {self._enrich_ctx} No usable report for "
                f"{missing or providers}, uploading"
            )
            return False

        scan_id, scan_res = self.polyswarm_client.get_scan_by_hash(lookup_hash)
        if not scan_res or scan_res.get("failed"):
            self.helper.connector_logger.info(
                f"[CONNECTOR] {self._enrich_ctx} No finished scan for the hash, uploading"
            )
            return False
        self.helper.connector_logger.info(
            f"[CONNECTOR] {self._enrich_ctx} Existing report and scan found for "
            f"{list(found)}, not uploading again"
        )
        llm_task_ids = self._fire_llm_for_existing(found, scan_id, scan_res)
        self._deliver_reports(
            entity,
            dict(found),
            {p: str(t.get("id")) for p, t in found.items()},
            lookup_hash,
            filename,
            stix_objects,
            scan_id=scan_id,
            scan_res=scan_res,
            llm_task_ids=llm_task_ids,
        )
        return True

    # -- StixFile: lookup, then optionally detonate by hash

    def _detonate_held_sample(
        self, entity: dict[str, Any], hash_value: str, missing: list[str]
    ) -> tuple[dict[str, str], str]:
        """Start sandbox runs for the sample PolySwarm holds.

        Returns (provider to task id, outcome) where outcome is one of
        "started", "refused", "not_held", "submit_failed".
        """
        if not self._upload_community_allowed():
            self.helper.connector_logger.warning(
                f"[CONNECTOR] {self._enrich_ctx} Detonation refused: the community "
                "is the public 'default' community and "
                "POLYSWARM_ALLOW_PUBLIC_COMMUNITY is not true"
            )
            self._send_error_note(
                entity,
                "Detonation Refused: Public Community",
                "The sample was not detonated. POLYSWARM_COMMUNITY is set to the "
                "public 'default' community, where submissions become visible to "
                "the PolySwarm community, and POLYSWARM_ALLOW_PUBLIC_COMMUNITY is "
                "not true.",
                [
                    "Set POLYSWARM_COMMUNITY to your private PolySwarm community.",
                    "Or set POLYSWARM_ALLOW_PUBLIC_COMMUNITY=true to detonate publicly.",
                ],
            )
            return {}, "refused"

        instance = self.polyswarm_client.find_instance_by_hash(hash_value)
        if not instance or not instance.get("id"):
            return {}, "not_held"

        tasks: dict[str, str] = {}
        for provider in missing:
            vm_slug = self._get_vm_for_provider(provider)
            task_id = self.polyswarm_client.submit_sandbox_by_instance_async(
                str(instance["id"]),
                provider,
                vm_slug,
                self.config.polyswarm.sandbox_network_enabled,
            )
            if task_id:
                tasks[provider] = task_id
            else:
                self.helper.connector_logger.warning(
                    f"[CONNECTOR] Failed to start {provider} sandbox for the held sample"
                )
        return tasks, "started" if tasks else "submit_failed"

    def _enrich_stixfile(
        self,
        entity_id: str | None,
        entity: dict[str, Any],
        opencti_entity: dict[str, Any],
        stix_objects: list,
    ) -> dict | None:
        """Sandbox reports for a StixFile observable, found by hash.

        Reads the latest existing report for each configured provider. If
        none is usable and POLYSWARM_SANDBOX_DETONATE_BY_HASH is true, the
        sample PolySwarm already holds is detonated (credits are spent,
        nothing is uploaded). Otherwise a note says no report exists.

        Returns:
            None on success, or dict with {"status": "error"|"skipped", ...}.
        """
        short_id = (entity_id or "unknown")[:12]
        self._enrich_ctx = f"[entity={short_id}]"
        ps = self.config.polyswarm
        try:
            tlp_skip = self._tlp_skip(opencti_entity, stix_objects)
            if tlp_skip:
                return tlp_skip

            if ps.sandbox_enabled is not True:
                self._send_error_note(
                    entity,
                    "Sandbox Disabled",
                    "No report was looked up. A file hash is only looked up in the "
                    "sandbox, and POLYSWARM_SANDBOX_ENABLED is false.",
                    ["Set POLYSWARM_SANDBOX_ENABLED=true."],
                )
                return {
                    "status": "error",
                    "error": "Hash not looked up: POLYSWARM_SANDBOX_ENABLED is false",
                }

            hashes = self._entity_hashes(entity)
            hash_value = next(
                (hashes[a] for a, _n in _HASH_PREFERENCE if a in hashes), ""
            )
            if not hash_value:
                self._send_error_note(
                    entity,
                    "No Hash",
                    "The file observable has no MD5, SHA-1 or SHA-256 hash, so "
                    "nothing was looked up.",
                    ["Add a hash to the observable in OpenCTI."],
                )
                return {
                    "status": "error",
                    "error": "File observable has no hash, nothing sent to PolySwarm",
                }

            sha256 = hashes.get("SHA-256")
            if not sha256:
                # PolySwarm's sandbox lookup takes a SHA-256: resolve the other hash
                instance = self.polyswarm_client.find_instance_by_hash(hash_value)
                sha256 = (instance or {}).get("sha256")
                if not sha256:
                    self._send_info_note(
                        entity,
                        "No PolySwarm Sandbox Report",
                        "PolySwarm has no record of this hash in the community "
                        f"'{ps.community}', so there is no sandbox report to import.",
                        self._no_report_next_steps(),
                    )
                    return None
            self._enrich_ctx = f"[entity={short_id} hash={sha256[:16]}]"
            self.helper.connector_logger.info(
                f"[CONNECTOR] {self._enrich_ctx} Starting hash lookup"
            )

            providers = self._get_sandbox_providers()
            found, missing = self._lookup_reports(sha256, providers)
            tasks = {p: str(t.get("id")) for p, t in found.items()}
            results: dict[str, dict | None] = dict(found)
            llm_task_ids = self._fire_llm_for_existing(found)

            held_outcome = ""
            if missing and ps.sandbox_detonate_by_hash is True:
                started, held_outcome = self._detonate_held_sample(
                    entity, sha256, missing
                )
                if started:
                    results.update(
                        self._phase_poll_sandboxes(
                            entity,
                            started,
                            ps.poll_interval,
                            ps.sandbox_timeout,
                            llm_task_ids,
                        )
                    )
                    tasks.update(started)
                elif held_outcome == "submit_failed":
                    self._send_error_note(
                        entity,
                        "Sandbox Submission Failed",
                        "Failed to start the sandbox for the sample PolySwarm holds "
                        f"on provider(s): {', '.join(missing)}.",
                        [
                            "Verify your PolySwarm plan includes sandbox analysis.",
                            "Contact customersuccess@polyswarm.io to enable sandbox features "
                            "or increase quota.",
                        ],
                    )
                    if not results:
                        return {
                            "status": "error",
                            "error": "Sandbox start for the held sample failed",
                        }
                elif held_outcome == "refused" and not results:
                    return {
                        "status": "error",
                        "error": "Detonation in the public community refused "
                        "(POLYSWARM_ALLOW_PUBLIC_COMMUNITY is not true)",
                    }

            if not results:
                if held_outcome == "not_held":
                    detail = (
                        "PolySwarm has no sandbox report for this hash, and does not "
                        "hold the sample, so it could not be detonated. Nothing was "
                        "uploaded."
                    )
                    steps = [
                        "Upload the file to OpenCTI as an Artifact and enrich the "
                        "Artifact to scan and detonate it."
                    ]
                else:
                    detail = self._no_report_detail()
                    steps = self._no_report_next_steps()
                self._send_info_note(
                    entity, "No PolySwarm Sandbox Report", detail, steps
                )
                return None

            filename = entity.get("name") or sha256[:16]
            self._deliver_reports(
                entity,
                results,
                tasks,
                sha256,
                str(filename),
                stix_objects,
                llm_task_ids=llm_task_ids,
            )
            return None
        except PolySwarmAPIError:
            raise
        finally:
            self._enrich_ctx = ""

    def _no_report_detail(self) -> str:
        max_age = self.config.polyswarm.sandbox_lookup_max_age_days
        age = (
            f" (reports older than {max_age} days are ignored, "
            "POLYSWARM_SANDBOX_LOOKUP_MAX_AGE_DAYS)"
            if isinstance(max_age, int)
            and not isinstance(max_age, bool)
            and max_age > 0
            else ""
        )
        return (
            "PolySwarm has no usable sandbox report for this hash" + age + ". "
            "Only the hash was sent to PolySwarm, and nothing was detonated."
        )

    def _no_report_next_steps(self) -> list[str]:
        steps = []
        if self.config.polyswarm.sandbox_detonate_by_hash is not True:
            steps.append(
                "Set POLYSWARM_SANDBOX_DETONATE_BY_HASH=true to detonate a sample "
                "PolySwarm already holds for this hash (spends sandbox credits, "
                "nothing is uploaded from OpenCTI)."
            )
        steps.append(
            "Or upload the file to OpenCTI as an Artifact and enrich the "
            "Artifact to scan and detonate it."
        )
        return steps
