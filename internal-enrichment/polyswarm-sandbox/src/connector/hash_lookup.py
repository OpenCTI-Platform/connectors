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

from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any

from connector.polyswarm_client import PolySwarmAPIError, PolySwarmClient
from connector.scan_processor import ScanProcessor

_HASH_PREFERENCE = (("SHA-256", 64), ("SHA-1", 40), ("MD5", 32))


def _is_timeout_status(result: dict) -> bool:
    """True for any timeout variant a provider reports (TIMED OUT, TIMEDOUT, ...)."""
    status = str(result.get("status", "")).upper()
    return "TIMED OUT" in status or "TIMEDOUT" in status


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

    def _within_max_age(self, task: dict) -> bool:
        """True when the task is not older than the configured age limit."""
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

    def _report_usable(self, task: dict | None) -> bool:
        """A finished (successful) report that is not older than the age limit."""
        if not task or not PolySwarmClient.is_sandbox_success(
            str(task.get("status", ""))
        ):
            return False
        return self._within_max_age(task)

    def _running_window(self) -> timedelta:
        """How long an unfinished task counts as running: twice
        POLYSWARM_SANDBOX_TIMEOUT, and at least 10 minutes. An unfinished task
        older than that is treated as stuck."""
        timeout = self.config.polyswarm.sandbox_timeout
        if not isinstance(timeout, int) or isinstance(timeout, bool):
            timeout = 0
        return timedelta(seconds=max(2 * timeout, 600))

    def _unfinished_state(self, task: dict | None) -> str | None:
        """State of a task that has not finished.

        Returns None for no task or a finished one, "running" for a task
        created within ``_running_window``, "stuck" for an older one (or one
        older than the age limit), and "unknown" when its creation time is
        missing or unparseable (never detonated over blindly).
        """
        if not task or not task.get("id"):
            return None
        if PolySwarmClient.is_sandbox_terminal(str(task.get("status", ""))):
            return None
        try:
            created = datetime.fromisoformat(
                str(task.get("created") or "").replace("Z", "+00:00")
            )
        except ValueError:
            return "unknown"
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        if not self._within_max_age(task):
            return "stuck"
        if datetime.now(timezone.utc) - created > self._running_window():
            return "stuck"
        return "running"

    def _lookup_reports(
        self, sha256: str, providers: list[str]
    ) -> tuple[dict[str, dict], list[str], list[str], dict[str, str]]:
        """Latest task per provider, sorted by what it means.

        Returns (found, missing, failed, running):
        - found: provider to a usable report
        - missing: providers for which PolySwarm confirmed there is no
          usable report
        - failed: providers whose lookup failed, or whose unfinished task has
          no usable creation time, so it is not known whether a report (or
          a paid task in progress) exists (never treated as missing)
        - running: provider to the id of a task that is still in progress
          (see ``_unfinished_state``; a stuck task counts as missing)
        """
        found: dict[str, dict] = {}
        missing: list[str] = []
        failed: list[str] = []
        running: dict[str, str] = {}
        for provider in providers:
            task = self.polyswarm_client.get_latest_sandbox_task(sha256, provider)
            if task is None:
                failed.append(provider)
                continue
            if self._report_usable(task):
                found[provider] = task
                continue
            state = self._unfinished_state(task)
            if state == "running":
                running[provider] = str(task["id"])
            elif state == "unknown":
                failed.append(provider)
            else:
                missing.append(provider)
        return found, missing, failed, running

    def _send_info_note(
        self,
        entity: dict[str, Any],
        title: str,
        detail: str,
        next_steps: list[str] | None = None,
        stix_objects: list | None = None,
    ) -> None:
        """Attach a plain (non-error) note to the observable.

        The incoming ``stix_objects`` are sent in the same bundle, so a
        playbook gets its original bundle back on this path too.
        """
        try:
            note = self.stix_builder.create_info_note(
                entity=entity, title=title, detail=detail, next_steps=next_steps
            )
            author = self.stix_builder._create_author()
            objects: list = []
            seen: set = set()
            for obj in [author, note, *(stix_objects or [])]:
                obj_id = obj.get("id") if isinstance(obj, Mapping) else None
                if obj_id is not None and obj_id in seen:
                    continue
                if obj_id is not None:
                    seen.add(obj_id)
                objects.append(obj)
            bundle = self.helper.stix2_create_bundle(objects)
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
            llm_id = self._request_report(
                self.polyswarm_client.create_llm_report,
                sandbox_task_id=task.get("id"),
                provider=provider,
            )
            if llm_id:
                llm_task_ids[provider] = llm_id
        if scan_id and scan_res and not scan_res.get("failed"):
            llm_id = self._request_report(
                self.polyswarm_client.create_llm_report, instance_id=scan_id
            )
            if llm_id:
                llm_task_ids["scan"] = llm_id
        return llm_task_ids

    # -- Artifact: reuse an existing report instead of uploading again

    def _send_lookup_failed_note(self, entity: dict[str, Any], failed: list[str]):
        """Error note for providers whose report lookup failed."""
        self._send_error_note(
            entity,
            "Sandbox Lookup Failed",
            "The lookup of the existing sandbox report failed for "
            f"provider(s): {', '.join(failed)}. It is not known whether a "
            "report exists, so nothing was detonated for them.",
            [
                "Retry the enrichment in a few minutes.",
                "Check the connector logs for the PolySwarm API error.",
            ],
        )

    def _deliver_existing(
        self,
        entity: dict[str, Any],
        found: dict[str, dict],
        running: dict[str, str],
        lookup_hash: str,
        filename: str,
        stix_objects: list,
        scan_id: str | None = None,
        scan_res: dict | None = None,
    ) -> dict | None:
        """Deliver reports that exist, waiting for the tasks still running.

        Nothing is submitted. Returns None on success, or an error result
        when no report could be delivered.
        """
        ps = self.config.polyswarm
        results: dict[str, dict | None] = dict(found)
        tasks = {p: str(t.get("id")) for p, t in found.items()}
        llm_task_ids = self._fire_llm_for_existing(found, scan_id, scan_res)
        if running:
            self.helper.connector_logger.info(
                f"[CONNECTOR] {self._enrich_ctx} Sandbox task already running for "
                f"{list(running)}, waiting for it"
            )
            polled = self._phase_poll_sandboxes(
                entity, running, ps.poll_interval, ps.sandbox_timeout, llm_task_ids
            )
            results.update({p: r for p, r in polled.items() if r})
            tasks.update(running)
        if not results and not scan_res:
            return {
                "status": "error",
                "error": "No existing sandbox report could be delivered",
            }
        self._deliver_reports(
            entity,
            results,
            tasks,
            lookup_hash,
            filename,
            stix_objects,
            scan_id=scan_id,
            scan_res=scan_res,
            llm_task_ids=llm_task_ids,
        )
        return None

    def _try_reuse_existing_reports(
        self,
        entity: dict[str, Any],
        lookup_hash: str | None,
        filename: str,
        stix_objects: list,
    ) -> tuple[bool, dict | None, dict[str, str]]:
        """Use existing reports for an Artifact instead of uploading again.

        Returns (handled, result, existing):
        - handled True: the enrichment is finished, ``result`` is its
          result (None on success). Nothing was uploaded.
        - handled False: run the upload. ``existing`` maps provider to the
          task id of a report that exists or a task still running; those
          providers must not be detonated again, only polled.

        Never uploads or detonates when a lookup failed: it is not known
        whether a report (or a paid task in progress) exists. Never starts a
        second detonation for a task still running. When every provider has
        a report or a running task but no finished scan of the hash exists,
        the upload only scans the file.
        """
        ps = self.config.polyswarm
        if (
            ps.sandbox_reuse_report is not True
            or ps.sandbox_enabled is not True
            or not lookup_hash
        ):
            return False, None, {}
        try:
            providers = self._get_sandbox_providers()
            found, missing, failed, running = self._lookup_reports(
                lookup_hash, providers
            )
        except PolySwarmAPIError as e:
            if e.is_quota_or_rate_limited:
                # A second request (the upload) would hit the same quota or
                # rate limit. End the enrichment so the quota note is
                # attached instead.
                raise
            self.helper.connector_logger.warning(
                f"[CONNECTOR] {self._enrich_ctx} Report lookup failed, uploading "
                f"instead: {e.category}"
            )
            return False, None, {}

        if failed:
            self._send_lookup_failed_note(entity, failed)
            if not found and not running:
                return (
                    True,
                    {
                        "status": "error",
                        "error": "Sandbox report lookup failed for "
                        f"{', '.join(failed)}, nothing was uploaded",
                    },
                    {},
                )
            scan_id, scan_res = self.polyswarm_client.get_scan_by_hash(lookup_hash)
            if not scan_res or scan_res.get("failed"):
                scan_id, scan_res = None, None
            return (
                True,
                self._deliver_existing(
                    entity,
                    found,
                    running,
                    lookup_hash,
                    filename,
                    stix_objects,
                    scan_id,
                    scan_res,
                ),
                {},
            )

        existing = {p: str(t.get("id")) for p, t in found.items()}
        existing.update(running)
        if missing:
            self.helper.connector_logger.info(
                f"[CONNECTOR] {self._enrich_ctx} No usable report for {missing}, "
                "uploading"
            )
            return False, None, existing

        scan_id, scan_res = self.polyswarm_client.get_scan_by_hash(lookup_hash)
        if not scan_res or scan_res.get("failed"):
            self.helper.connector_logger.info(
                f"[CONNECTOR] {self._enrich_ctx} No finished scan for the hash, "
                "uploading to scan only (existing sandbox tasks are reused)"
            )
            return False, None, existing
        self.helper.connector_logger.info(
            f"[CONNECTOR] {self._enrich_ctx} Existing report and scan found for "
            f"{list(existing)}, not uploading again"
        )
        return (
            True,
            self._deliver_existing(
                entity,
                found,
                running,
                lookup_hash,
                filename,
                stix_objects,
                scan_id,
                scan_res,
            ),
            {},
        )

    # -- StixFile: lookup, then optionally detonate by hash

    def _detonate_held_sample(
        self,
        entity: dict[str, Any],
        hash_value: str,
        missing: list[str],
        kept: list[str] | None = None,
    ) -> tuple[dict[str, str], str]:
        """Start sandbox runs for the sample PolySwarm holds.

        ``kept`` names providers with a report found or a task running: an
        API error on every submit is then noted per provider instead of
        raised, so those are still delivered.

        Returns (provider to task id, outcome) where outcome is one of
        "started", "refused", "not_held", "submit_failed", "api_error" (no
        task started, every failure was an API error and is already noted).
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
        errors: dict[str, PolySwarmAPIError] = {}
        for provider in missing:
            vm_slug = self._get_vm_for_provider(provider)
            try:
                task_id = self.polyswarm_client.submit_sandbox_by_instance_async(
                    str(instance["id"]),
                    provider,
                    vm_slug,
                    self.config.polyswarm.sandbox_network_enabled,
                )
            except PolySwarmAPIError as e:
                # Keep going: a task another provider already started is
                # billed and must still be polled and delivered.
                self.helper.connector_logger.warning(
                    f"[CONNECTOR] Failed to start {provider} sandbox for the held "
                    f"sample: {e.category}"
                )
                errors[provider] = e
                continue
            if task_id:
                tasks[provider] = task_id
            else:
                self.helper.connector_logger.warning(
                    f"[CONNECTOR] Failed to start {provider} sandbox for the held sample"
                )
        self._settle_submit_errors(entity, tasks, errors, kept)
        if tasks:
            return tasks, "started"
        if errors and len(errors) == len(missing):
            return tasks, "api_error"
        return tasks, "submit_failed"

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
            tlp_skip = self._tlp_skip(opencti_entity, stix_objects, entity)
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
                        stix_objects=stix_objects,
                    )
                    return None
            self._enrich_ctx = f"[entity={short_id} hash={sha256[:16]}]"
            self.helper.connector_logger.info(
                f"[CONNECTOR] {self._enrich_ctx} Starting hash lookup"
            )

            providers = self._get_sandbox_providers()
            found, missing, failed, running = self._lookup_reports(sha256, providers)
            tasks = {p: str(t.get("id")) for p, t in found.items()}
            results: dict[str, dict | None] = dict(found)
            llm_task_ids = self._fire_llm_for_existing(found)

            if failed:
                # Unknown is not "no report": never detonate on a failed lookup,
                # it could start a second paid analysis of the same sample.
                self._send_lookup_failed_note(entity, failed)

            held_outcome = ""
            no_analysis = False
            if ps.sandbox_detonate_by_hash is not True:
                # A task still in progress has no report yet: with detonation
                # off it is reported like any other missing report.
                missing = missing + list(running)
                running = {}
            if (missing or running) and ps.sandbox_detonate_by_hash is True:
                started: dict[str, str] = {}
                if missing:
                    started, held_outcome = self._detonate_held_sample(
                        entity, sha256, missing, kept=[*found, *running]
                    )
                if held_outcome == "submit_failed":
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
                if running:
                    # Poll the detonation already in progress instead of
                    # starting (and paying for) another one.
                    self.helper.connector_logger.info(
                        f"[CONNECTOR] {self._enrich_ctx} Sandbox task already "
                        f"running for {list(running)}, waiting for it"
                    )
                    started = {**started, **running}
                if started:
                    polled = self._phase_poll_sandboxes(
                        entity,
                        started,
                        ps.poll_interval,
                        ps.sandbox_timeout,
                        llm_task_ids,
                    )
                    # A provider still pending at the local timeout already
                    # got a timeout note while polling; it has no report to
                    # attach, so it is left out of the results.
                    results.update({p: r for p, r in polled.items() if r})
                    tasks.update(started)
                    no_analysis = not any(
                        r and not _is_timeout_status(r) for r in results.values()
                    )
                    if no_analysis and not results:
                        return {
                            "status": "error",
                            "error": "No sandbox analysis completed before the "
                            "timeout",
                        }
                elif held_outcome in ("submit_failed", "api_error") and not results:
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
                if failed:
                    return {
                        "status": "error",
                        "error": "Sandbox report lookup failed for "
                        f"{', '.join(failed)}, nothing was detonated",
                    }
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
                    entity,
                    "No PolySwarm Sandbox Report",
                    detail,
                    steps,
                    stix_objects=stix_objects,
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
            if no_analysis:
                # Every provider reported a timeout: the notes above explain
                # it, and the enrichment is not acknowledged as a success.
                return {
                    "status": "error",
                    "error": "No sandbox analysis completed before the timeout",
                }
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
