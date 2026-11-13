"""PolySwarm Connector — main orchestration class.

Production implementation with real scan and sandbox submission.
Supports multiple sandbox providers (cape, triage, both).
Artifacts are scanned and detonated; Url observables are detonated.
"""

import hashlib
import json
import threading
import time
import traceback
import uuid
from typing import Any

from connector.artifact_handler import ArtifactHandler
from connector.hash_lookup import HashLookupMixin
from connector.polyswarm_client import PolySwarmAPIError, PolySwarmClient
from connector.report_depth import select_pcap_artifact
from connector.sandbox_processor import SandboxProcessor
from connector.scan_processor import ScanProcessor
from connector.stix_builder import StixBuilder
from connector.url_utils import (
    is_non_public_url,
    loggable_url,
    url_for_submission,
    url_has_query_or_fragment,
    url_has_userinfo,
)
from pycti import MarkingDefinition, OpenCTIConnectorHelper

# Names that all mean PolySwarm's public community: an account's community list
# shows it as "public", the API's default is "default", and task records say
# "mainnet1".
PUBLIC_COMMUNITY_NAMES = ("", "default", "public", "mainnet1")

# Fixed STIX ids of the TLP markings, so a ref is resolved even when the
# bundle does not carry its marking-definition object. TLP:WHITE and
# TLP:CLEAR share one id. A bundle cannot redefine these ids.
WELL_KNOWN_TLP_IDS = {
    MarkingDefinition.generate_id("TLP", tlp): tlp
    for tlp in ("TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED")
}


def tlp_of_marking(marking: dict) -> str | None:
    """TLP name of a STIX marking-definition, or None when it is not a TLP.

    Read in order: OpenCTI's x_opencti_definition (when its type is TLP),
    then a name starting with "TLP:", then the definition when
    definition_type is TLP (any case): the STIX 2.1 form {"tlp": "red"}
    (or key "TLP"), or the OpenCTI API string form "TLP:RED".
    """
    if str(marking.get("x_opencti_definition_type") or "").upper() == "TLP":
        if marking.get("x_opencti_definition"):
            return str(marking["x_opencti_definition"]).upper()
    name = str(marking.get("name") or "")
    if name.upper().startswith("TLP:"):
        return name.upper()
    if str(marking.get("definition_type") or "").lower() == "tlp":
        definition = marking.get("definition")
        if isinstance(definition, dict):
            definition = definition.get("tlp") or definition.get("TLP")
        if isinstance(definition, str) and definition.strip():
            tlp = definition.strip().upper()
            return tlp if tlp.startswith("TLP:") else f"TLP:{tlp}"
    return None


class PolySwarmConnector(HashLookupMixin):
    """OpenCTI internal enrichment connector for PolySwarm file scanning and sandbox analysis."""

    def __init__(self, config, helper: OpenCTIConnectorHelper) -> None:
        """Wire up configuration, API client, artifact handler, and STIX builder.

        Args:
            config: ``ConnectorSettings`` instance (Pydantic, from env/YAML).
            helper: OpenCTI SDK helper for messaging, logging, and bundle submission.
        """
        self.helper = helper
        self.config = config
        # Thread-local storage for per-enrichment log context (entity ID, hash prefix)
        self._local = threading.local()

        ps = config.polyswarm
        self.max_tlp = f"TLP:{config.connector.max_tlp.upper()}"
        self.replace_with_lower_score = ps.replace_with_lower_score

        self.polyswarm_client = PolySwarmClient(
            api_key=ps.api_key.get_secret_value(),
            api_url=ps.api_url,
            community=ps.community,
            timeout=ps.timeout,
            helper=helper,
            quota_warn_below=ps.quota_warn_below,
        )
        # Log the account plan and quota at startup (read-only, never raises)
        self.polyswarm_client.quota.refresh()
        self.artifact_handler = ArtifactHandler(
            helper=helper,
            max_file_size=ps.max_file_size,
            download_enabled=ps.download_artifacts,
        )
        self.stix_builder = StixBuilder(
            helper=helper,
            polykg_api_url=ps.polykg_api_url,
            polyswarm_api_key=ps.api_key.get_secret_value(),
        )

    def run(self) -> None:
        """Start the connector — delegates to start() for backward compatibility."""
        self.start()

    @property
    def _enrich_ctx(self) -> str:
        """PROD-16 + NEW-04: Thread-safe enrichment context for log correlation."""
        return getattr(self._local, "enrich_ctx", "")

    @_enrich_ctx.setter
    def _enrich_ctx(self, value: str) -> None:
        self._local.enrich_ctx = value

    def _report_quota_error(self) -> PolySwarmAPIError | None:
        """Quota or rate error a report request hit in this enrichment, if any."""
        err = getattr(self._local, "report_quota_error", None)
        return err if isinstance(err, PolySwarmAPIError) else None

    def _request_report(self, call: Any, *args: Any, **kwargs: Any) -> Any:
        """Run a report request (LLM report, PDF report).

        A quota or rate error does not end the enrichment (the analysis is
        already done and is still delivered): it is kept for the quota note
        that ``_phase_reports`` attaches, and no further report requests are
        sent in this enrichment. Returns None in that case.
        """
        if self._report_quota_error() is not None:
            return None
        try:
            return call(*args, **kwargs)
        except PolySwarmAPIError as e:
            if not e.is_quota_or_rate_limited:
                raise
            self.helper.connector_logger.warning(
                f"[CONNECTOR] {self._enrich_ctx} Report request stopped: {e.category}"
            )
            self._local.report_quota_error = e
            return None

    def _send_report_quota_note(self, entity: dict[str, Any]) -> None:
        """Attach the quota note for a report request, once per enrichment."""
        err = self._report_quota_error()
        if err is None or getattr(self._local, "report_quota_noted", None) is err:
            return
        # Keep the error (no further report requests), remember it was noted
        self._local.report_quota_noted = err
        self._send_error_note(
            entity,
            err.category,
            "Some PDF or AI-generated reports were not created. The scan and "
            f"sandbox results are still included.\n\n{err.detail}",
            err.recommendations,
        )

    def _get_vm_for_provider(self, provider: str) -> str:
        """Get the correct VM slug for a given sandbox provider.

        Priority: legacy sandbox_vm override > API default (prefers Windows) > hardcoded fallback.
        """
        ps = self.config.polyswarm

        # Legacy single-VM override — user explicitly wants one VM for everything
        if ps.sandbox_vm:
            return ps.sandbox_vm

        # Ask the API — prefers Windows VMs since most malware targets Windows
        api_default = self.polyswarm_client.get_default_vm_for_provider(
            provider.lower().strip()
        )
        if api_default:
            return api_default

        # Hardcoded fallback (should never hit if API is reachable)
        return "win-10-build-19041"

    def _get_sandbox_providers(self) -> list[str]:
        """Resolve the configured provider string into a list of provider slugs.

        Validates against the API's available providers. 'both' expands to
        all available providers. Unknown slugs are logged and skipped.
        """
        provider_config = self.config.polyswarm.sandbox_provider.lower().strip()
        available_slugs = self.polyswarm_client.get_provider_slugs()

        if provider_config == "both":
            return available_slugs if available_slugs else ["cape", "triage"]

        if provider_config in available_slugs:
            return [provider_config]

        # Unknown provider — warn and fall back to first available
        if available_slugs:
            fallback = available_slugs[0]
            self.helper.connector_logger.warning(
                f"[CONNECTOR] Unknown sandbox provider '{provider_config}', "
                f"available: {available_slugs}. Defaulting to '{fallback}'"
            )
            return [fallback]

        self.helper.connector_logger.warning(
            f"[CONNECTOR] Unknown sandbox provider '{provider_config}' and "
            "no providers available from API. Defaulting to 'cape'"
        )
        return ["cape"]

    def start(self) -> None:
        """Start listening for enrichment events from OpenCTI."""
        self.helper.listen(self._process_message)

    # ── Playbook & Spec Compliance ──────────────────────────────────────

    def _entity_in_scope(self, data: dict[str, Any]) -> bool:
        """Check if entity type is in connector scope.

        Uses the authoritative ``enrichment_entity.entity_type`` rather than
        parsing the STIX ID prefix. A StixFile observable has id
        ``file--<uuid>`` but entity_type ``StixFile``, so deriving the type
        from the ID prefix never matches a ``StixFile`` scope entry.
        """
        scopes = self.helper.connect_scope.lower().replace(" ", "").split(",")
        opencti_entity = data.get("enrichment_entity") or {}
        entity_type = opencti_entity.get("entity_type", "").lower()

        if entity_type in scopes:
            return True

        self.helper.connector_logger.info(
            f"[CONNECTOR] Entity type '{entity_type}' not in scope {scopes}"
        )
        return False

    def _send_original_bundle(self, stix_objects: list) -> None:
        """Send original stix_objects bundle back for playbook compatibility.

        Spec: Always return a bundle, even on error or out-of-scope.
        """
        if not stix_objects:
            return
        try:
            bundle = self.helper.stix2_create_bundle(stix_objects)
            self.helper.send_stix2_bundle(
                bundle, update=True, cleanup_inconsistent_bundle=True
            )
        except (ValueError, TypeError, RuntimeError) as e:
            self.helper.connector_logger.warning(
                f"[CONNECTOR] Failed to return original bundle: {e}"
            )

    def _process_message(self, data: dict[str, Any]) -> str:
        """Process enrichment message.

        Follows OpenCTI enrichment spec:
        1. Extract enrichment_entity, stix_entity, stix_objects
        2. Validate entity scope
        3. Perform enrichment
        4. On error/out-of-scope: return original bundle for playbook compat
        """
        # At most one account read an hour; never raises
        self.polyswarm_client.quota.refresh()
        opencti_entity = data.get("enrichment_entity")
        stix_entity = data.get("stix_entity")
        stix_objects = data["stix_objects"] if "stix_objects" in data else []
        entity_id = data.get("entity_id")

        if not opencti_entity:
            self._send_original_bundle(stix_objects)
            return json.dumps({"status": "error", "error": "Entity not found"})

        self.helper.connector_logger.info(
            f"[CONNECTOR] Processing entity type: {opencti_entity.get('entity_type')}"
        )

        # Scope check — return original bundle if not in scope
        if not self._entity_in_scope(data):
            if not data.get("event_type"):
                self._send_original_bundle(stix_objects)
                return "Entity not in scope, returned original bundle"
            raise ValueError(
                f"{opencti_entity.get('entity_type')} is not a supported entity type"
            )

        # Use STIX entity if available, otherwise normalize OpenCTI entity
        entity = (
            stix_entity
            if stix_entity
            else self._normalize_opencti_entity(opencti_entity)
        )

        try:
            result = self._enrich_file(entity_id, entity, opencti_entity, stix_objects)
            if result and result.get("status") in ("error", "skipped"):
                error_msg = result.get("error") or result.get(
                    "message", "Unknown error"
                )
                self.helper.connector_logger.warning(f"[CONNECTOR] {error_msg}")
                self._send_original_bundle(stix_objects)
                return json.dumps(result)
            return json.dumps({"status": "success", "message": "Enrichment completed"})
        except PolySwarmAPIError as api_err:
            self.helper.connector_logger.error(
                f"[CONNECTOR] PolySwarm API error: {api_err}"
            )
            self._send_error_note(
                entity, api_err.category, api_err.detail, api_err.recommendations
            )
            self._send_original_bundle(stix_objects)
            return json.dumps({"status": "error", "error": str(api_err)})
        except (ValueError, TypeError, RuntimeError, KeyError, AttributeError) as e:
            error_msg = f"Enrichment failed: {str(e)}"
            self.helper.connector_logger.error(f"[CONNECTOR] {error_msg}")
            self._send_error_note(
                entity,
                "Unexpected Enrichment Error",
                error_msg,
                [
                    "Retry the enrichment — this may be a transient issue.",
                    "Check the connector logs for full traceback details.",
                    "Contact customersuccess@polyswarm.io if the issue persists.",
                ],
            )
            self._send_original_bundle(stix_objects)
            return json.dumps({"status": "error", "error": error_msg})

    def _normalize_opencti_entity(
        self, opencti_entity: dict[str, Any]
    ) -> dict[str, Any]:
        """Normalize an OpenCTI entity dict into a STIX-like dict.

        OpenCTI's internal entity format differs from STIX 2.1 in field names,
        hash layout, and type strings.  This mapping lets downstream code
        (StixBuilder, processors) work with a single consistent shape regardless
        of whether the message carried a ``stix_entity`` or only an
        ``enrichment_entity``.
        """
        normalized: dict[str, Any] = {}

        # OpenCTI uses title-case type names; map to STIX 2.1 SDO type strings.
        entity_type = opencti_entity.get("entity_type", "").lower()
        type_mapping = {
            "stixfile": "file",
            "stix-file": "file",
            "artifact": "artifact",
            "file": "file",
            "indicator": "indicator",
            "url": "url",
        }
        normalized["type"] = type_mapping.get(entity_type, "file")

        normalized["id"] = (
            opencti_entity.get("standard_id")
            or opencti_entity.get("stix_id")
            or opencti_entity.get("id")
            or f"file--{uuid.uuid5(uuid.NAMESPACE_URL, f'polyswarm:unknown:{opencti_entity.get("id", "unknown")}')}"
        )

        normalized["name"] = opencti_entity.get("name") or opencti_entity.get(
            "observable_value", ""
        )
        if normalized["type"] == "url":
            normalized["value"] = opencti_entity.get("value") or opencti_entity.get(
                "observable_value", ""
            )

        # Extract hashes
        hashes = {}
        if opencti_entity.get("hashes"):
            if isinstance(opencti_entity["hashes"], dict):
                hashes = opencti_entity["hashes"].copy()
            elif isinstance(opencti_entity["hashes"], list):
                for h in opencti_entity["hashes"]:
                    if isinstance(h, dict) and h.get("algorithm") and h.get("hash"):
                        hashes[h["algorithm"]] = h["hash"]

        for algo, field in [("SHA-256", "sha256"), ("SHA-1", "sha1"), ("MD5", "md5")]:
            if opencti_entity.get(field):
                hashes[algo] = opencti_entity[field]

        # Last-resort: infer hash algorithm from observable_value length.
        # This handles cases where the entity is a bare hash with no hashes dict.
        obs_val = opencti_entity.get("observable_value", "")
        if obs_val and not hashes:
            if len(obs_val) == 64 and all(
                c in "0123456789abcdefABCDEF" for c in obs_val
            ):
                hashes["SHA-256"] = obs_val
            elif len(obs_val) == 40 and all(
                c in "0123456789abcdefABCDEF" for c in obs_val
            ):
                hashes["SHA-1"] = obs_val
            elif len(obs_val) == 32 and all(
                c in "0123456789abcdefABCDEF" for c in obs_val
            ):
                hashes["MD5"] = obs_val

        if hashes:
            normalized["hashes"] = hashes

        # Copy other useful fields
        for field in [
            "importFiles",
            "objectMarking",
            "createdBy",
            "x_opencti_score",
            "external_references",
            "labels",
            "description",
            "decryption_key",
            "x_opencti_encryption_password",
        ]:
            if opencti_entity.get(field):
                normalized[field] = opencti_entity[field]

        return normalized

    def _get_lookup_hash(self, entity: dict[str, Any]) -> str | None:
        """Extract SHA-256 hash for lookup."""
        hashes = entity.get("hashes", {})
        if isinstance(hashes, dict):
            return hashes.get("SHA-256")
        if isinstance(hashes, list):
            for h in hashes:
                if h.get("algorithm") == "SHA-256":
                    return h.get("hash")
        return None

    def _tlp_skip(
        self,
        opencti_entity: dict[str, Any],
        stix_objects: list,
        entity: dict[str, Any] | None = None,
    ) -> dict | None:
        """Return a "skipped" result when the entity's TLP exceeds max_tlp (#38).

        check_max_tlp takes one TLP name ("TLP:GREEN"), not a list of marking
        ids, so each TLP marking on the entity is checked (the #7955 fix).
        ``entity`` is the STIX entity being enriched; its own
        object_marking_refs are checked too.
        """
        max_tlp = self.max_tlp
        if max_tlp:
            # The limit is always evaluated, whether or not the message carries
            # a STIX bundle. Markings come from the OpenCTI entity and, when
            # present, from the bundle's TLP marking definitions the entity
            # references. An entity with no resolvable marking is allowed, as
            # on the file path.
            tlp_levels = [
                m["definition"]
                for m in opencti_entity.get("objectMarking") or []
                if isinstance(m, dict)
                and m.get("definition_type") == "TLP"
                and m.get("definition")
            ]
            by_id = dict(WELL_KNOWN_TLP_IDS)
            for o in stix_objects or []:
                if isinstance(o, dict) and o.get("type") == "marking-definition":
                    tlp = tlp_of_marking(o)
                    if tlp:
                        by_id.setdefault(o.get("id"), tlp)
            entity = entity if isinstance(entity, dict) else {}
            entity_ids = {
                i
                for i in (
                    opencti_entity.get("standard_id"),
                    opencti_entity.get("id"),
                    entity.get("id"),
                )
                if i
            }
            refs = list(entity.get("object_marking_refs") or [])
            for o in stix_objects or []:
                if isinstance(o, dict) and o.get("id") in entity_ids:
                    refs += o.get("object_marking_refs") or []
            tlp_levels += [by_id[r] for r in refs if r in by_id]
            if any(not self.helper.check_max_tlp(tlp, max_tlp) for tlp in tlp_levels):
                self.helper.connector_logger.info(
                    f"[CONNECTOR] {self._enrich_ctx} Skipping: TLP exceeds max_tlp={max_tlp}"
                )
                return {
                    "status": "skipped",
                    "message": f"TLP exceeds configured max_tlp ({max_tlp})",
                }
        return None

    def _refuse_public_upload(self, entity: dict[str, Any]) -> dict:
        """Note and error result for an upload refused by the public community guard."""
        self.helper.connector_logger.warning(
            f"[CONNECTOR] {self._enrich_ctx} Upload refused: the community is "
            "the public 'default' community and POLYSWARM_ALLOW_PUBLIC_COMMUNITY "
            "is not true"
        )
        self._send_error_note(
            entity,
            "Upload Refused: Public Community",
            "The file was not uploaded. POLYSWARM_COMMUNITY is set to the public "
            "'default' community, where uploaded files become visible to the "
            "PolySwarm community, and POLYSWARM_ALLOW_PUBLIC_COMMUNITY is not true.",
            [
                "Set POLYSWARM_COMMUNITY to your private PolySwarm community.",
                "Or set POLYSWARM_ALLOW_PUBLIC_COMMUNITY=true to submit files publicly.",
            ],
        )
        return {
            "status": "error",
            "error": "Upload to the public community refused "
            "(POLYSWARM_ALLOW_PUBLIC_COMMUNITY is not true)",
        }

    def _upload_community_allowed(self) -> bool:
        """True unless uploads would go to the public community without opt-in."""
        community = (self.config.polyswarm.community or "").strip().lower()
        if community not in PUBLIC_COMMUNITY_NAMES:
            return True
        return self.config.polyswarm.allow_public_community is True

    def _send_error_note(
        self,
        entity: dict[str, Any],
        error_category: str,
        error_detail: str,
        recommendations: list[str] | None = None,
    ) -> None:
        """Create an error note on the artifact and send it to OpenCTI.

        This ensures errors are visible in the OpenCTI UI as Notes attached to the artifact,
        not just buried in connector logs.
        """
        try:
            error_note = self.stix_builder.create_error_note(
                entity=entity,
                error_category=error_category,
                error_detail=error_detail,
                recommendations=recommendations,
            )
            # Build a minimal bundle with just the author identity + error note
            author = self.stix_builder._create_author()
            bundle = self.helper.stix2_create_bundle([author, error_note])
            self.helper.send_stix2_bundle(
                bundle, update=True, cleanup_inconsistent_bundle=True
            )
            self.helper.connector_logger.info(
                f"[CONNECTOR] Error note created: {error_category}"
            )
        except (
            ValueError,
            TypeError,
            RuntimeError,
            KeyError,
            AttributeError,
        ) as note_err:
            self.helper.connector_logger.warning(
                f"[CONNECTOR] Failed to create error note: {type(note_err).__name__}: {note_err}"
            )

    def _submit_sandboxes(
        self,
        file_data: bytes,
        filename: str,
        password: str | None = None,
        skip: set[str] | None = None,
        only: list[str] | None = None,
    ) -> tuple[dict[str, str], dict[str, PolySwarmAPIError]]:
        """Submit file to the configured sandbox providers.

        ``only``, when given, is the exact list of providers to submit to
        (the ones a report lookup confirmed have no report), so a provider
        that appears in a later provider listing is never detonated without
        having been looked up. Otherwise every configured provider not in
        ``skip`` is used.

        Returns (provider to task ID for successful submissions, provider to
        API error). Failures are not raised: the scan is already submitted,
        so the caller decides whether to continue with scan-only results.
        After a quota or rate error the remaining providers are not tried.
        """
        sandbox_tasks: dict[str, str] = {}
        errors: dict[str, PolySwarmAPIError] = {}
        if only is not None:
            providers = [p for p in only if p not in (skip or ())]
        else:
            providers = [
                p for p in self._get_sandbox_providers() if p not in (skip or ())
            ]

        self.helper.connector_logger.info(
            f"[CONNECTOR] Submitting to sandbox provider(s): {providers}"
        )

        for provider in providers:
            vm_slug = self._get_vm_for_provider(provider)
            self.helper.connector_logger.info(
                f"[CONNECTOR] Submitting to {provider} with VM: {vm_slug}"
            )

            try:
                task_id = self.polyswarm_client.submit_sandbox_async(
                    file_data=file_data,
                    filename=filename,
                    provider=provider,
                    vm_slug=vm_slug,
                    network=self.config.polyswarm.sandbox_network_enabled,
                    password=password,
                )
            except PolySwarmAPIError as e:
                self.helper.connector_logger.warning(
                    f"[CONNECTOR] Failed to submit to {provider} sandbox: {e.category}"
                )
                errors[provider] = e
                if e.is_quota_or_rate_limited:
                    break
                continue

            if task_id:
                sandbox_tasks[provider] = task_id
                self.helper.connector_logger.info(
                    f"[CONNECTOR] {provider.upper()} sandbox submitted, task_id: {task_id}"
                )
            else:
                self.helper.connector_logger.warning(
                    f"[CONNECTOR] Failed to submit to {provider} sandbox"
                )

        return sandbox_tasks, errors

    # Status classification is delegated to PolySwarmClient's static helpers
    # (is_sandbox_success, is_sandbox_failure) which use substring matching to
    # catch all known variants ("FAILED", "TIMED OUT", "TIMEDOUT", etc.).

    def _poll_sandbox_results(
        self,
        sandbox_tasks: dict[str, str],
        poll_interval: int,
        poll_timeout: int,
        llm_task_ids: dict[str, str] | None = None,
    ) -> dict[str, dict | None]:
        """
        Poll for sandbox results from all submitted tasks.
        Returns dict mapping provider name to result dict.
        Detects failures early and stops polling immediately.

        If llm_task_ids dict is provided and LLM reports are enabled, fires LLM report
        creation as soon as each provider succeeds (non-blocking).
        """
        sandbox_results = dict.fromkeys(sandbox_tasks)
        poll_start = time.monotonic()
        fire_llm = llm_task_ids is not None and self.config.polyswarm.llm_report_enabled

        while any(result is None for result in sandbox_results.values()):
            elapsed = time.monotonic() - poll_start
            if elapsed >= poll_timeout:
                self.helper.connector_logger.warning(
                    f"[CONNECTOR] Sandbox polling timeout reached ({poll_timeout}s)"
                )
                break

            time.sleep(poll_interval)

            for provider, task_id in sandbox_tasks.items():
                if sandbox_results[provider] is None:
                    result = self.polyswarm_client.get_sandbox_results(task_id)
                    if result:
                        sandbox_results[provider] = result
                        status = str(result.get("status", "")).upper()

                        # Check if this is a failure state
                        if PolySwarmClient.is_sandbox_failure(status):
                            self.helper.connector_logger.warning(
                                f"[CONNECTOR] {provider.upper()} sandbox FAILED with status: {status}"
                            )
                        elif PolySwarmClient.is_sandbox_success(status):
                            self.helper.connector_logger.info(
                                f"[CONNECTOR] {provider.upper()} sandbox completed successfully"
                            )
                            # Fire LLM report creation immediately on success
                            if (
                                fire_llm
                                and llm_task_ids is not None
                                and provider not in llm_task_ids
                            ):
                                llm_id = self._request_report(
                                    self.polyswarm_client.create_llm_report,
                                    sandbox_task_id=task_id,
                                    provider=provider,
                                )
                                if llm_id:
                                    llm_task_ids[provider] = llm_id
                                    self.helper.connector_logger.info(
                                        f"[CONNECTOR] {provider.upper()} LLM report fired (task: {llm_id})"
                                    )
                        else:
                            self.helper.connector_logger.info(
                                f"[CONNECTOR] {provider.upper()} sandbox completed with status: {status}"
                            )

            # Log polling status with more detail
            status_parts = []
            for p in sandbox_tasks:
                res = sandbox_results[p]
                if res:
                    status = str(res.get("status", "Unknown")).upper()
                    if PolySwarmClient.is_sandbox_failure(status):
                        status_parts.append(f"{p.upper()}: FAILED ({status})")
                    else:
                        status_parts.append(f"{p.upper()}: Ready")
                else:
                    status_parts.append(f"{p.upper()}: Pending")

            status_str = ", ".join(status_parts)
            self.helper.connector_logger.info(
                f"[CONNECTOR] Sandbox polling... {int(elapsed)}s. {status_str}"
            )

        return sandbox_results

    def _merge_sandbox_results(
        self, sandbox_results: dict[str, dict | None]
    ) -> tuple[dict | None, tuple[str, dict] | None]:
        """
        Merge sandbox results from multiple providers.
        Returns (merged_raw_result, best_result_for_pdf).

        Strategy:
        - Only merge SUCCESSFUL sandbox results (skip failed ones)
        - Combine TTPs, domains, signatures from all providers
        - Use highest score
        - Prefer family detection from provider with higher score
        """
        # Only include successful sandbox results for merging
        valid_results = {}
        for k, v in sandbox_results.items():
            if v is not None:
                status = str(v.get("status", "")).upper()
                if PolySwarmClient.is_sandbox_success(status):
                    valid_results[k] = v
                else:
                    self.helper.connector_logger.debug(
                        f"[CONNECTOR] Skipping {k} from merge (status: {status})"
                    )

        if not valid_results:
            return None, None

        if len(valid_results) == 1:
            provider, result = next(iter(valid_results.items()))
            return result, (provider, result)

        # Multiple results - merge them
        self.helper.connector_logger.info(
            f"[CONNECTOR] Merging sandbox results from {list(valid_results.keys())}"
        )

        # Start with the first result as base
        providers = list(valid_results.keys())
        merged = valid_results[providers[0]].copy()

        # Track which provider had the best score for PDF generation
        best_provider = providers[0]
        best_score = self._extract_sandbox_score(valid_results[providers[0]])

        for provider in providers[1:]:
            other = valid_results[provider]
            other_score = self._extract_sandbox_score(other)

            # Use higher score
            if other_score > best_score:
                best_score = other_score
                best_provider = provider
                # Also prefer family from higher-scoring result
                if other.get("family"):
                    merged["family"] = other["family"]

            # Merge report data
            if "report" in other and "report" in merged:
                merged["report"] = self._merge_report_data(
                    merged.get("report", {}), other.get("report", {})
                )
            elif "report" in other:
                merged["report"] = other["report"]

        # Mark as merged
        merged["_merged_from"] = providers
        merged["_best_provider"] = best_provider

        return merged, (best_provider, valid_results[best_provider])

    def _extract_sandbox_score(self, sandbox_result: dict) -> int:
        """Extract numeric score from a sandbox result.

        Cape and Triage nest the score at different depths in their JSON;
        this method walks the three known locations in priority order.
        """
        if not sandbox_result:
            return 0

        # Priority: top-level > report.score > report.info.score (Cape legacy)
        score = sandbox_result.get("score", 0)
        if not score:
            report = sandbox_result.get("report")
            if report and isinstance(report, dict):
                score = report.get("score", 0)
                if not score:
                    info = report.get("info")
                    if info and isinstance(info, dict):
                        score = info.get("score", 0)

        try:
            return int(float(score)) if score else 0
        except (TypeError, ValueError):
            return 0

    def _merge_report_data(self, base_report: dict, other_report: dict) -> dict:
        """Merge two sandbox report dicts, deduplicating list fields.

        Dict items are deduplicated by their JSON serialisation so structurally
        identical entries from different providers collapse into one.
        """
        merged = base_report.copy()

        # Merge list fields (signatures, TTPs, network data)
        list_fields = ["signatures", "ttps", "mitre_attck"]
        for field in list_fields:
            base_list = base_report.get(field, [])
            other_list = other_report.get(field, [])
            if base_list or other_list:
                # Deduplicate by converting to set of JSON strings
                combined = list(base_list) + list(other_list)
                seen = set()
                unique = []
                for item in combined:
                    key = (
                        json.dumps(item, sort_keys=True)
                        if isinstance(item, dict)
                        else str(item)
                    )
                    if key not in seen:
                        seen.add(key)
                        unique.append(item)
                merged[field] = unique

        # Merge network data
        if "network" in base_report or "network" in other_report:
            base_network = base_report.get("network", {})
            other_network = other_report.get("network", {})
            merged["network"] = self._merge_network_data(base_network, other_network)

        # Merge dropped files
        if "dropped" in base_report or "dropped" in other_report:
            base_dropped = base_report.get("dropped", [])
            other_dropped = other_report.get("dropped", [])
            merged["dropped"] = base_dropped + other_dropped

        return merged

    def _merge_network_data(self, base_network: dict, other_network: dict) -> dict:
        """Merge network IOC data (DNS, TCP, UDP, hosts) from two sandbox reports."""
        merged = base_network.copy()

        # List fields to merge
        network_list_fields = ["dns", "http", "hosts", "tcp", "udp", "domains", "ips"]
        for field in network_list_fields:
            base_list = base_network.get(field, [])
            other_list = other_network.get(field, [])
            if base_list or other_list:
                combined = list(base_list) + list(other_list)
                # Deduplicate
                seen = set()
                unique = []
                for item in combined:
                    key = (
                        json.dumps(item, sort_keys=True)
                        if isinstance(item, dict)
                        else str(item)
                    )
                    if key not in seen:
                        seen.add(key)
                        unique.append(item)
                merged[field] = unique

        return merged

    def _process_sandbox_results(
        self, sandbox_results: dict[str, dict | None]
    ) -> tuple[dict[str, dict], dict[str, dict]]:
        """Split raw sandbox results into processed successes and failures.

        Per provider, no merge: dedup happens in stix_builder.
        """
        sandbox_processed: dict[str, dict] = {}
        sandbox_failures: dict[str, dict] = {}
        for provider, raw_result in sandbox_results.items():
            if raw_result:
                status = str(raw_result.get("status", "")).upper()
                if PolySwarmClient.is_sandbox_success(status):
                    processed = SandboxProcessor.process(raw_result)
                    if processed:
                        sandbox_processed[provider] = processed
                        self.helper.connector_logger.info(
                            f"[CONNECTOR] {provider.upper()} sandbox processed: "
                            f"score={processed.get('score')}, "
                            f"family={processed.get('family')}, "
                            f"ttps={len(processed.get('ttps', []))}, "
                            f"domains={len(processed.get('domains', []))}, "
                            f"ips={len(processed.get('ips', []))}"
                        )
                elif PolySwarmClient.is_sandbox_failure(status):
                    sandbox_failures[provider] = {
                        "status": status,
                        "raw_result": raw_result,
                        "error": raw_result.get("error")
                        or raw_result.get("message")
                        or f"Sandbox execution {status.lower()}",
                    }
                    self.helper.connector_logger.warning(
                        f"[CONNECTOR] {provider.upper()} sandbox failed: {status}"
                    )
                else:
                    self.helper.connector_logger.warning(
                        f"[CONNECTOR] {provider.upper()} sandbox has unknown status: {status}"
                    )
                    sandbox_failures[provider] = {
                        "status": status or "UNKNOWN",
                        "raw_result": raw_result,
                        "error": f"Sandbox returned unexpected status: {status}",
                    }
        return sandbox_processed, sandbox_failures

    # ── Phase methods (decomposed from _enrich_file) ─────────────────────────

    def _phase_download(
        self,
        entity: dict[str, Any],
        opencti_entity: dict[str, Any],
        lookup_hash: str | None,
    ) -> tuple[bytes | None, str, str | None, str | None]:
        """Download artifact and extract metadata.

        Returns:
            (file_data, filename, password, mime_type).
            Raises ValueError with an error dict on failure.
        """
        file_data, download_error = self.artifact_handler.download_artifact(
            opencti_entity
        )

        if download_error:
            self.helper.connector_logger.error(
                f"[CONNECTOR] {self._enrich_ctx} Download failed: {download_error}"
            )
            if "exceeds the maximum" in download_error:
                cat, recs = "File Size Limit Exceeded", [
                    "Increase POLYSWARM_MAX_FILE_SIZE in your connector configuration.",
                    "Contact customersuccess@polyswarm.io for enterprise file size limits.",
                ]
            elif "disabled" in download_error.lower():
                cat, recs = "Artifact Download Disabled", [
                    "Set POLYSWARM_DOWNLOAD_ARTIFACTS=true in your connector configuration.",
                    "Contact customersuccess@polyswarm.io if you need help enabling this feature.",
                ]
            elif "empty" in download_error.lower():
                cat, recs = "Empty File", [
                    "Re-upload the file to the artifact — it may have been corrupted.",
                    "Verify the original file is not zero bytes.",
                ]
            elif "No file attached" in download_error:
                cat, recs = "No File Attached", [
                    "Upload a file to this artifact before running PolySwarm enrichment.",
                    "Ensure the file was saved correctly in OpenCTI.",
                ]
            else:
                cat, recs = "File Download Failed", [
                    "Retry the enrichment — this may be a transient storage issue.",
                    "Verify the file still exists in OpenCTI.",
                    "Contact customersuccess@polyswarm.io if the issue persists.",
                ]
            self._send_error_note(entity, cat, download_error, recs)
            raise ValueError(download_error)

        if not file_data:
            err_msg = "Could not download artifact from OpenCTI. Ensure a file is attached to this artifact."
            self.helper.connector_logger.warning(f"[CONNECTOR] {err_msg}")
            self._send_error_note(
                entity,
                "No File Downloaded",
                err_msg,
                [
                    "Upload a file to this artifact before running enrichment.",
                    "Verify the file exists in OpenCTI storage.",
                    "Contact customersuccess@polyswarm.io if you need help.",
                ],
            )
            raise ValueError(err_msg)

        self.helper.connector_logger.info(
            f"[CONNECTOR] Downloaded artifact: {len(file_data)} bytes"
        )
        password = entity.get("decryption_key") or entity.get(
            "x_opencti_encryption_password"
        )
        import_files = opencti_entity.get("importFiles", [])
        filename = (
            (import_files[0].get("name") if import_files else None)
            or entity.get("name")
            or lookup_hash
            or "sample"
        )
        # PROD-18: Extract mime_type from entity metadata
        mime_type = (
            import_files[0].get("metaData", {}).get("mimetype")
            if import_files
            else None
        ) or opencti_entity.get("mime_type")
        self.helper.connector_logger.info(
            f"[CONNECTOR] Filename: {filename}, MIME: {mime_type or 'auto-detect'}"
        )
        return file_data, filename, password, mime_type

    def _phase_submit(
        self,
        entity: dict[str, Any],
        file_data: bytes,
        filename: str,
        mime_type: str | None,
        password: str | None,
        existing: dict[str, str] | None = None,
        detonate: list[str] | None = None,
    ) -> tuple[str, dict[str, str]]:
        """Submit file for scanning and optionally sandbox analysis.

        ``existing`` maps provider to the task id of a report that already
        exists or a task still running: those providers are not detonated
        again, their task is returned with the new ones to be polled.
        ``detonate``, when given, is the exact list of providers to detonate
        (looked up and confirmed to have no report); None means every
        configured provider not in ``existing``.

        Returns:
            (scan_id, sandbox_tasks) where sandbox_tasks maps provider→task_id.
            Raises ValueError if scan submission fails.
        """
        existing = existing or {}
        scan_id = self.polyswarm_client.submit_file_async(
            file_data, filename, mime_type, "default", password
        )
        if not scan_id:
            self.helper.connector_logger.error(
                f"[CONNECTOR] {self._enrich_ctx} Scan submission failed"
            )
            self._send_error_note(
                entity,
                "Scan Submission Failed",
                "PolySwarm was unable to accept the file for scanning. The API may be temporarily "
                "unavailable, or your account may have reached its scan quota.",
                [
                    "Retry the enrichment in a few minutes.",
                    "Check your PolySwarm API key is valid and active.",
                    "Verify your scan quota at https://polyswarm.network.",
                    "Contact customersuccess@polyswarm.io for quota increases or plan upgrades.",
                ],
            )
            raise ValueError(
                "Scan submission to PolySwarm API failed. Check API key and quota."
            )

        sandbox_tasks: dict[str, str] = {}
        if self.config.polyswarm.sandbox_enabled:
            sandbox_tasks, errors = self._submit_sandboxes(
                file_data, filename, password, skip=set(existing), only=detonate
            )
            if existing:
                self.helper.connector_logger.info(
                    f"[CONNECTOR] {self._enrich_ctx} Reusing existing sandbox "
                    f"task(s) for {list(existing)}"
                )
            sandbox_tasks = {**existing, **sandbox_tasks}
            if errors:
                # The scan is already submitted, so nothing is raised here: the
                # API error (quota ...) gets its own note and the enrichment
                # continues with the scan and any sandbox that started.
                if sandbox_tasks:
                    self._settle_submit_errors(entity, sandbox_tasks, errors)
                else:
                    err = next(iter(errors.values()))
                    self._send_error_note(
                        entity,
                        err.category,
                        "No sandbox was started. Scan results will still be "
                        f"processed.\n\n{err.detail}",
                        err.recommendations,
                    )
            elif not sandbox_tasks:
                providers = self._get_sandbox_providers()
                self._send_error_note(
                    entity,
                    "Sandbox Submission Failed",
                    f"Failed to submit file to sandbox provider(s): {', '.join(providers)}. "
                    f"Scan results will still be processed, but sandbox analysis is unavailable.",
                    [
                        "Verify your PolySwarm plan includes sandbox analysis.",
                        "Check that sandbox provider(s) ({}) are valid.".format(
                            ", ".join(providers)
                        ),
                        "Contact customersuccess@polyswarm.io to enable sandbox features or increase quota.",
                    ],
                )
        return scan_id, sandbox_tasks

    def _phase_poll_scan(
        self,
        entity: dict[str, Any],
        scan_id: str,
        poll_interval: int,
        poll_timeout: int,
    ) -> tuple[dict | None, dict[str, str]]:
        """Poll for scan results and fire LLM report on success.

        Returns:
            (scan_res, llm_task_ids) where llm_task_ids maps source→task_id.
        """
        # PROD-15: Use monotonic clock for accurate elapsed time
        poll_start = time.monotonic()
        scan_res = None
        llm_task_ids: dict[str, str] = {}

        while scan_id and not scan_res:
            elapsed = time.monotonic() - poll_start
            if elapsed >= poll_timeout:
                self.helper.connector_logger.warning(
                    f"[CONNECTOR] Scan polling timeout reached ({poll_timeout}s)"
                )
                break
            time.sleep(poll_interval)
            scan_res = self.polyswarm_client.get_scan_results(scan_id)
            elapsed = int(time.monotonic() - poll_start)
            self.helper.connector_logger.info(
                f"[CONNECTOR] Scan polling... {elapsed}s. "
                f"Scan: {'Ready' if scan_res else 'Pending'}"
            )

        if scan_id and not scan_res:
            self._send_error_note(
                entity,
                "Scan Polling Timeout",
                f"The scan did not complete within the configured timeout of {poll_timeout} seconds. "
                f"The file may be complex or the PolySwarm platform may be under heavy load.",
                [
                    f"Increase POLYSWARM_POLL_TIMEOUT (current: {poll_timeout}s).",
                    "Retry the enrichment later when the platform is less busy.",
                    "Contact customersuccess@polyswarm.io if scans consistently time out.",
                ],
            )

        if scan_res and scan_res.get("failed"):
            self._send_error_note(
                entity,
                "Scan Failed",
                "The PolySwarm scan completed but was marked as failed. This can happen when "
                "the file is corrupt, uses an unsupported format, or triggers an infrastructure error.",
                [
                    "Try re-uploading the file and running enrichment again.",
                    "Verify the file is not corrupt or password-protected without providing the password.",
                    "Contact customersuccess@polyswarm.io if the issue persists.",
                ],
            )

        if (
            scan_res
            and not scan_res.get("failed")
            and self.config.polyswarm.llm_report_enabled
        ):
            llm_id = self._request_report(
                self.polyswarm_client.create_llm_report, instance_id=scan_id
            )
            if llm_id:
                llm_task_ids["scan"] = llm_id
                self.helper.connector_logger.info(
                    f"[CONNECTOR] Scan LLM report fired (task: {llm_id})"
                )

        return scan_res, llm_task_ids

    def _phase_poll_sandboxes(
        self,
        entity: dict[str, Any],
        sandbox_tasks: dict[str, str],
        poll_interval: int,
        sandbox_timeout: int,
        llm_task_ids: dict[str, str],
    ) -> dict[str, dict | None]:
        """Poll for sandbox results from all providers.

        Returns:
            sandbox_results mapping provider→result dict.
        """
        self.helper.connector_logger.info(
            f"[CONNECTOR] Polling sandbox results (timeout: {sandbox_timeout}s)"
        )
        sandbox_results = self._poll_sandbox_results(
            sandbox_tasks, poll_interval, sandbox_timeout, llm_task_ids=llm_task_ids
        )
        for provider, _task_id in sandbox_tasks.items():
            if sandbox_results.get(provider) is None:
                self._send_error_note(
                    entity,
                    f"{provider.upper()} Sandbox Timeout",
                    f"The {provider.upper()} sandbox analysis did not complete within "
                    f"{sandbox_timeout} seconds. The file may require extended analysis time.",
                    [
                        f"Increase POLYSWARM_SANDBOX_TIMEOUT (current: {sandbox_timeout}s).",
                        "Try a different sandbox provider (cape or triage).",
                        "Contact customersuccess@polyswarm.io for help with sandbox analysis.",
                    ],
                )
        return sandbox_results

    def _attach_pcaps(
        self,
        entity: dict[str, Any],
        sandbox_tasks: dict[str, str],
        sandbox_results: dict[str, dict | None],
        lookup_hash: str | None,
    ) -> None:
        """Download each successful provider's pcap and attach it to the observable."""
        max_bytes = self.config.polyswarm.sandbox_pcap_max_size
        for provider, task_id in sandbox_tasks.items():
            result = sandbox_results.get(provider)
            if not result or not PolySwarmClient.is_sandbox_success(
                str(result.get("status", "")).upper()
            ):
                continue
            art = select_pcap_artifact(result)
            if not art:
                continue
            try:
                got = self.polyswarm_client.download_sandbox_artifact_bytes(
                    task_id, str(art["instance_id"]), max_bytes
                )
                if not got:
                    continue
                _, data = got
                short = lookup_hash[:16] if lookup_hash else "unknown"
                pcap_filename = f"Sandbox_{provider}_{short}.pcap"
                self.helper.connector_logger.info(
                    f"[CONNECTOR] Attaching pcap: {pcap_filename}"
                )
                self.helper.api.stix_cyber_observable.add_file(
                    id=entity["id"],
                    file_name=pcap_filename,
                    data=data,
                    mime_type="application/vnd.tcpdump.pcap",
                    no_trigger_import=True,
                )
            except (OSError, KeyError, RuntimeError, TypeError) as e:
                self.helper.connector_logger.warning(
                    f"[CONNECTOR] Failed to attach {provider} pcap: {type(e).__name__}"
                )

    def _phase_reports(
        self,
        entity: dict[str, Any],
        scan_id: str | None,
        scan_res: dict | None,
        scan_mapped: dict | None,
        sandbox_tasks: dict[str, str],
        sandbox_results: dict[str, dict | None],
        llm_task_ids: dict[str, str],
        filename: str,
        lookup_hash: str | None,
    ) -> dict[str, str]:
        """Attach JSON/PDF reports and collect LLM reports.

        Returns:
            llm_reports mapping source→report_text.
        """
        # ── JSON attachments
        if self.config.polyswarm.json_report_enabled:
            if scan_res:
                json_filename = (
                    f"Scan_result_{lookup_hash[:16] if lookup_hash else 'unknown'}.json"
                )
                self.helper.connector_logger.info(
                    f"[CONNECTOR] Attaching JSON: {json_filename}"
                )
                try:
                    self.helper.api.stix_cyber_observable.add_file(
                        id=entity["id"],
                        file_name=json_filename,
                        data=json.dumps(scan_res, indent=2, default=str).encode(
                            "utf-8"
                        ),
                        no_trigger_import=True,
                    )
                except (OSError, KeyError, RuntimeError, TypeError) as e:
                    self.helper.connector_logger.warning(
                        f"[CONNECTOR] Failed to attach scan JSON: {type(e).__name__}: {e}"
                    )

            for provider, result in sandbox_results.items():
                if result:
                    json_filename = f"Sandbox_{provider}_{lookup_hash[:16] if lookup_hash else 'unknown'}.json"
                    self.helper.connector_logger.info(
                        f"[CONNECTOR] Attaching JSON: {json_filename}"
                    )
                    try:
                        self.helper.api.stix_cyber_observable.add_file(
                            id=entity["id"],
                            file_name=json_filename,
                            data=json.dumps(result, indent=2, default=str).encode(
                                "utf-8"
                            ),
                            no_trigger_import=True,
                        )
                    except (OSError, KeyError, RuntimeError, TypeError) as e:
                        self.helper.connector_logger.warning(
                            f"[CONNECTOR] Failed to attach {provider} sandbox JSON: {type(e).__name__}: {e}"
                        )
                    # PROD-24: Only run debug helper when debug logging is active
                    if (
                        getattr(self.helper, "connect_log_level", "info").lower()
                        == "debug"
                    ):
                        self._debug_sandbox_structure(result)

        # pcap (off by default: one extra download per detonation)
        if self.config.polyswarm.sandbox_attach_pcap:
            self._attach_pcaps(entity, sandbox_tasks, sandbox_results, lookup_hash)

        # ── PDF reports
        if self.config.polyswarm.pdf_report_enabled:
            safe_filename = filename[:50] if len(filename) > 50 else filename
            if scan_mapped and scan_id:
                pdf = self._request_report(
                    self.polyswarm_client.generate_pdf, scan_id, "scan"
                )
                if pdf:
                    pdf_filename = f"PolySwarm_Scan_{safe_filename}.pdf"
                    self.helper.connector_logger.info(
                        f"[CONNECTOR] Attaching PDF: {pdf_filename}"
                    )
                    try:
                        self.helper.api.stix_cyber_observable.add_file(
                            id=entity["id"],
                            file_name=pdf_filename,
                            data=pdf,
                            no_trigger_import=True,
                        )
                    except (OSError, KeyError, RuntimeError, TypeError) as e:
                        self.helper.connector_logger.warning(
                            f"[CONNECTOR] Failed to attach scan PDF: {type(e).__name__}: {e}"
                        )

            for provider, task_id in sandbox_tasks.items():
                sb_res = sandbox_results.get(provider)
                if sb_res:
                    status = str(sb_res.get("status", "")).upper()
                    if PolySwarmClient.is_sandbox_success(status):
                        pdf = self._request_report(
                            self.polyswarm_client.generate_pdf, task_id, "sandbox"
                        )
                        if pdf:
                            pdf_filename = (
                                f"PolySwarm_Sandbox_{provider}_{safe_filename}.pdf"
                            )
                            self.helper.connector_logger.info(
                                f"[CONNECTOR] Attaching PDF: {pdf_filename}"
                            )
                            try:
                                self.helper.api.stix_cyber_observable.add_file(
                                    id=entity["id"],
                                    file_name=pdf_filename,
                                    data=pdf,
                                    no_trigger_import=True,
                                )
                            except (OSError, KeyError, RuntimeError, TypeError) as e:
                                self.helper.connector_logger.warning(
                                    f"[CONNECTOR] Failed to attach {provider} sandbox PDF: {type(e).__name__}: {e}"
                                )

        # ── LLM report collection
        llm_reports: dict[str, str] = {}
        if self.config.polyswarm.llm_report_enabled and llm_task_ids:
            llm_timeout = self.config.polyswarm.llm_report_timeout
            self.helper.connector_logger.info(
                f"[CONNECTOR] Collecting {len(llm_task_ids)} LLM report(s): {list(llm_task_ids.keys())}"
            )
            for source, llm_id in llm_task_ids.items():
                report_text = self.polyswarm_client.collect_llm_report(
                    llm_id, timeout=llm_timeout
                )
                if report_text:
                    llm_reports[source] = report_text
                    self.helper.connector_logger.info(
                        f"[CONNECTOR] {source.upper()} LLM report collected ({len(report_text)} chars)"
                    )
                else:
                    self.helper.connector_logger.warning(
                        f"[CONNECTOR] {source.upper()} LLM report collection failed"
                    )
                    self._send_error_note(
                        entity,
                        f"{source.upper()} LLM Report Unavailable",
                        f"The {source.upper()} AI-generated threat analysis report could not be retrieved. "
                        f"This is non-fatal — scan and sandbox results are still included.",
                        [
                            "Your PolySwarm plan may not include LLM reports, contact customersuccess@polyswarm.io to enable.",
                            "Set POLYSWARM_LLM_REPORT_ENABLED=false to disable LLM reports if not needed.",
                            f"Increase POLYSWARM_LLM_REPORT_TIMEOUT (current: {llm_timeout}s)"
                            " if reports are timing out.",
                        ],
                    )
        self._send_report_quota_note(entity)
        return llm_reports

    def _phase_stix(
        self,
        entity: dict[str, Any],
        scan_mapped: dict | None,
        sandbox_mapped: dict | None,
        sandbox_processed: dict[str, dict],
        sandbox_failures: dict[str, dict],
        llm_reports: dict[str, str],
        stix_objects: list,
    ) -> None:
        """Build and send the STIX bundle."""
        if not (scan_mapped or sandbox_mapped or sandbox_processed or sandbox_failures):
            self.helper.connector_logger.warning(
                "[CONNECTOR] No scan or sandbox data to process"
            )
            self._send_error_note(
                entity,
                "No Analysis Data Available",
                "Neither the scan nor the sandbox produced results to process. "
                "This typically means all submissions failed or timed out.",
                [
                    "Check the connector logs for detailed error information.",
                    "Verify your PolySwarm API key and quota at https://polyswarm.network.",
                    "Retry the enrichment in a few minutes.",
                    "Contact customersuccess@polyswarm.io for assistance.",
                ],
            )
            return

        self.helper.connector_logger.info("[CONNECTOR] Building STIX bundle...")
        new_stix_objects = self.stix_builder.build_bundle(
            entity=entity,
            scan_data=scan_mapped,
            sandbox_data=sandbox_mapped,
            sandbox_results=sandbox_processed,
            sandbox_failures=sandbox_failures,
            llm_reports=llm_reports,
            config=self.config,
        )

        if not new_stix_objects:
            self.helper.connector_logger.warning("[CONNECTOR] No STIX objects created")
            self._send_error_note(
                entity,
                "No Results Generated",
                "The scan and/or sandbox completed but no STIX intelligence objects could be "
                "generated from the results. The file may not have triggered any detections.",
                [
                    "This can be normal for benign files.",
                    "Try submitting to a different sandbox provider for deeper analysis.",
                    "Contact customersuccess@polyswarm.io if you believe this is an error.",
                ],
            )
            return

        # Log object types
        type_counts: dict[str, int] = {}
        for obj in new_stix_objects:
            t = obj.get("type", "unknown")
            type_counts[t] = type_counts.get(t, 0) + 1
        self.helper.connector_logger.info(
            f"[CONNECTOR] STIX objects created: {type_counts}"
        )

        # Merge with existing objects — strip binary payloads so the bundle doesn't
        # re-upload the file to OpenCTI (it's already stored).
        final_objects: list[dict[str, Any]] = []
        if stix_objects:
            for obj in stix_objects:
                clean_obj = dict(obj)
                clean_obj.pop("payload_bin", None)
                clean_obj.pop("x_opencti_files", None)
                final_objects.append(clean_obj)

        # Update existing observable
        observable_updated = False
        for i, obj in enumerate(final_objects):
            if obj.get("id") == entity["id"]:
                for new_obj in new_stix_objects:
                    if new_obj.get("id") == entity["id"]:
                        final_objects[i] = self._merge_stix_objects(obj, new_obj)
                        observable_updated = True
                        break
                break

        # Add new objects
        existing_ids = {obj.get("id") for obj in final_objects}
        for new_obj in new_stix_objects:
            if new_obj.get("id") not in existing_ids:
                final_objects.append(new_obj)

        if not observable_updated:
            for new_obj in new_stix_objects:
                if new_obj.get("id") == entity["id"]:
                    final_objects.append(new_obj)
                    break

        # #40: Playbook compat — original observable MUST be in bundle
        obs_ids = {obj.get("id") for obj in final_objects}
        if entity.get("id") and entity["id"] not in obs_ids:
            clean_entity = dict(entity)
            clean_entity.pop("payload_bin", None)
            clean_entity.pop("x_opencti_files", None)
            final_objects.insert(0, clean_entity)

        # Sort by STIX dependency order: identities first, relationships last.
        # This prevents OpenCTI from rejecting refs to objects it hasn't seen yet.
        _type_order = {
            "identity": 0,
            "location": 1,
            "marking-definition": 1,
            "malware": 2,
            "intrusion-set": 2,
            "threat-actor": 2,
            "tool": 2,
            "vulnerability": 2,
            "campaign": 2,
            "attack-pattern": 3,
            "domain-name": 4,
            "ipv4-addr": 4,
            "ipv6-addr": 4,
            "artifact": 5,
            "file": 5,
            "indicator": 5,
            "note": 6,
            "report": 6,
            "relationship": 7,
            "sighting": 7,
        }
        final_objects.sort(key=lambda o: _type_order.get(o.get("type", ""), 5))
        bundle = self.helper.stix2_create_bundle(final_objects)
        bundles_sent = self.helper.send_stix2_bundle(
            bundle, update=True, cleanup_inconsistent_bundle=True
        )
        self.helper.connector_logger.info(
            f"[CONNECTOR] {self._enrich_ctx} Sent {len(bundles_sent)} bundle(s)"
        )

    # ── Orchestrator ───────────────────────────────────────────────────────

    def _enrich_file(
        self,
        entity_id: str | None,
        entity: dict[str, Any],
        opencti_entity: dict[str, Any],
        stix_objects: list,
    ) -> dict | None:
        """Enrich file with PolySwarm scan and sandbox results.

        Orchestrates the phase methods. Every error path creates a visible Note
        on the artifact in OpenCTI so the user can see what went wrong.

        Returns:
            None on success, or dict with {"status": "error", "error": "..."} on failure.
        """
        # A report quota error is tracked per enrichment
        self._local.report_quota_error = None

        # Url observables have no file: they are detonated by _enrich_url
        if str(opencti_entity.get("entity_type", "")).lower() == "url":
            return self._enrich_url(entity_id, entity, opencti_entity, stix_objects)

        # StixFile observables carry a hash and no file: look up the existing
        # sandbox report (and detonate by hash only when enabled)
        if str(opencti_entity.get("entity_type", "")).lower() == "stixfile":
            return self._enrich_stixfile(
                entity_id, entity, opencti_entity, stix_objects
            )

        file_data = None
        short_id = (entity_id or "unknown")[:12]
        self._enrich_ctx = f"[entity={short_id}]"
        try:
            lookup_hash = self._get_lookup_hash(entity)
            if lookup_hash:
                self._enrich_ctx = f"[entity={short_id} hash={lookup_hash[:16]}]"
                self.helper.connector_logger.info(
                    f"[CONNECTOR] {self._enrich_ctx} Starting enrichment"
                )

            # ── TLP CHECK (#38)
            tlp_skip = self._tlp_skip(opencti_entity, stix_objects, entity)
            if tlp_skip:
                return tlp_skip

            # -- REUSE: an existing report for every provider means no re-upload
            import_files = opencti_entity.get("importFiles") or []
            reuse_name = (
                (import_files[0].get("name") if import_files else None)
                or entity.get("name")
                or lookup_hash
                or "sample"
            )
            handled, reuse_result, existing_tasks, detonate = (
                self._try_reuse_existing_reports(
                    entity, lookup_hash, reuse_name, stix_objects
                )
            )
            if handled:
                return reuse_result

            # ── PUBLIC COMMUNITY GUARD: refuse to upload publicly unless allowed
            if not self._upload_community_allowed():
                return self._refuse_public_upload(entity)

            # ── DOWNLOAD
            try:
                file_data, filename, password, mime_type = self._phase_download(
                    entity, opencti_entity, lookup_hash
                )
            except ValueError as e:
                return {"status": "error", "error": str(e)}

            # ── SUBMIT
            if file_data is None:
                return {
                    "status": "error",
                    "error": "No file data available for submission",
                }
            try:
                scan_id, sandbox_tasks = self._phase_submit(
                    entity,
                    file_data,
                    filename,
                    mime_type,
                    password,
                    existing=existing_tasks,
                    detonate=detonate,
                )
            except ValueError as e:
                return {"status": "error", "error": str(e)}

            # ── POLL SCAN
            poll_interval = self.config.polyswarm.poll_interval
            poll_timeout = self.config.polyswarm.poll_timeout
            scan_res, llm_task_ids = self._phase_poll_scan(
                entity, scan_id, poll_interval, poll_timeout
            )

            # ── POLL SANDBOXES
            sandbox_results: dict[str, dict | None] = {}
            if sandbox_tasks:
                sandbox_timeout = self.config.polyswarm.sandbox_timeout
                sandbox_results = self._phase_poll_sandboxes(
                    entity, sandbox_tasks, poll_interval, sandbox_timeout, llm_task_ids
                )

            # ── PROCESS (per-provider, no merge — dedup happens in stix_builder)
            scan_mapped = None
            if scan_res and not scan_res.get("failed"):
                scan_mapped = ScanProcessor.process(scan_res, scan_id=scan_id)
                if scan_mapped:
                    self.helper.connector_logger.info(
                        f"[CONNECTOR] Scan processed: score={scan_mapped.get('score')}, "
                        f"family={scan_mapped.get('family')}"
                    )

            sandbox_processed, sandbox_failures = self._process_sandbox_results(
                sandbox_results
            )

            # ── REPORTS (JSON, PDF, LLM)
            llm_reports = self._phase_reports(
                entity,
                scan_id,
                scan_res,
                scan_mapped,
                sandbox_tasks,
                sandbox_results,
                llm_task_ids,
                filename,
                lookup_hash,
            )

            # ── STIX BUNDLE
            self._phase_stix(
                entity,
                scan_mapped,
                None,  # sandbox_data — no longer merged; per-provider results used directly
                sandbox_processed,
                sandbox_failures,
                llm_reports,
                stix_objects,
            )

            return None

        except PolySwarmAPIError:
            raise
        except Exception as e:
            self.helper.connector_logger.error(
                f"[CONNECTOR] {self._enrich_ctx} Enrichment failure: {str(e)}"
            )
            self.helper.connector_logger.error(
                f"[CONNECTOR] {self._enrich_ctx} Traceback: {traceback.format_exc()}"
            )
            raise
        finally:
            # PROD-02: Guarantee file_data is released regardless of success/failure
            file_data = None
            # PROD-16: Clear enrichment context
            self._enrich_ctx = ""

    # -- URL detonation

    def _refuse_url(
        self,
        entity: dict[str, Any],
        category: str,
        detail: str,
        recommendations: list[str],
        error: str,
    ) -> dict:
        """Attach a refusal note to the Url observable; nothing is sent to PolySwarm."""
        self.helper.connector_logger.warning(f"[CONNECTOR] {self._enrich_ctx} {error}")
        self._send_error_note(entity, category, detail, recommendations)
        return {"status": "error", "error": error}

    def _settle_submit_errors(
        self,
        entity: dict[str, Any],
        started: dict[str, str],
        errors: dict[str, PolySwarmAPIError],
        kept: list[str] | None = None,
    ) -> None:
        """Handle API errors from a per-provider submit loop.

        ``kept`` names providers that already have something to deliver (a
        report found or a task still running). When nothing started and
        nothing is kept, the first error is raised so the caller's API error
        note (quota, authentication ...) is attached. Otherwise the tasks
        and reports are kept: each failed provider gets its own note and the
        enrichment goes on with what it has.
        """
        if not errors:
            return
        going_on = list(dict.fromkeys([*started, *(kept or [])]))
        if not going_on:
            raise next(iter(errors.values()))
        for provider, err in errors.items():
            self._send_error_note(
                entity,
                err.category,
                f"The {provider.upper()} sandbox was not started. The analysis on "
                f"{', '.join(p.upper() for p in going_on)} continues.\n\n{err.detail}",
                err.recommendations,
            )

    def _submit_url_sandboxes(self, url: str, entity: dict[str, Any]) -> dict[str, str]:
        """Submit a URL to each configured sandbox provider.

        Returns a dict mapping provider name to task ID for successful
        submissions. Providers with no VM that accepts URLs are skipped. An
        API error on one provider does not drop a task another provider
        already started (see ``_settle_submit_errors``).
        """
        sandbox_tasks: dict[str, str] = {}
        errors: dict[str, PolySwarmAPIError] = {}
        for provider in self._get_sandbox_providers():
            vm_slug = self.polyswarm_client.get_url_vm_for_provider(
                provider, preferred=self.config.polyswarm.sandbox_vm
            )
            if not vm_slug:
                self.helper.connector_logger.warning(
                    f"[CONNECTOR] {provider} lists no VM that accepts URLs, skipped"
                )
                continue
            try:
                task_id = self.polyswarm_client.submit_sandbox_url_async(
                    url, provider=provider, vm_slug=vm_slug
                )
            except PolySwarmAPIError as e:
                self.helper.connector_logger.warning(
                    f"[CONNECTOR] URL submit to {provider} sandbox failed: {e.category}"
                )
                errors[provider] = e
                continue
            if task_id:
                sandbox_tasks[provider] = task_id
            else:
                self.helper.connector_logger.warning(
                    f"[CONNECTOR] Failed to submit URL to {provider} sandbox"
                )
        self._settle_submit_errors(entity, sandbox_tasks, errors)
        return sandbox_tasks

    def _enrich_url(
        self,
        entity_id: str | None,
        entity: dict[str, Any],
        opencti_entity: dict[str, Any],
        stix_objects: list,
    ) -> dict | None:
        """Detonate a Url observable in the PolySwarm sandbox.

        Refusals (credentials in the URL, private or internal host, public
        community without opt-in, sandbox disabled) attach a note to the
        observable and make no API call. The query string and fragment are
        removed before submission unless POLYSWARM_SANDBOX_URL_SEND_QUERY is
        true. Logs only show the URL's scheme and host.

        Returns:
            None on success, or dict with {"status": "error", "error": "..."} on failure.
        """
        short_id = (entity_id or "unknown")[:12]
        value = str(
            entity.get("value")
            or opencti_entity.get("observable_value")
            or opencti_entity.get("value")
            or ""
        ).strip()
        self._enrich_ctx = f"[entity={short_id} url={loggable_url(value)}]"
        try:
            self.helper.connector_logger.info(
                f"[CONNECTOR] {self._enrich_ctx} Starting URL enrichment"
            )

            # -- TLP CHECK (#38)
            tlp_skip = self._tlp_skip(opencti_entity, stix_objects, entity)
            if tlp_skip:
                return tlp_skip

            if not value:
                return self._refuse_url(
                    entity,
                    "No URL Value",
                    "The Url observable has no value, so nothing was submitted.",
                    ["Check the observable's value in OpenCTI."],
                    "Url observable has no value, nothing sent to PolySwarm",
                )

            # URLs with a username or password are never sent (credentials)
            if url_has_userinfo(value):
                return self._refuse_url(
                    entity,
                    "Submission Refused: URL Contains Credentials",
                    "The URL was not submitted. It contains a username or password, "
                    "and URLs with credentials are never sent to PolySwarm.",
                    [
                        "Remove the username and password from the URL if it "
                        "should be detonated.",
                    ],
                    "URL contains a username or password and is never sent to PolySwarm",
                )

            # Private and internal values never leave the platform
            if is_non_public_url(value):
                return self._refuse_url(
                    entity,
                    "Submission Refused: Private or Internal Host",
                    "The URL was not submitted. Its host is missing, or is a "
                    "private, loopback, link-local, shared (CGNAT), reserved or "
                    "internal address or name, and private or internal values are "
                    "never sent to PolySwarm.",
                    ["Only URLs on public hosts can be detonated in the sandbox."],
                    "Private or internal value is never sent to PolySwarm",
                )

            # -- PUBLIC COMMUNITY GUARD: same rule as file uploads
            if not self._upload_community_allowed():
                return self._refuse_url(
                    entity,
                    "Upload Refused: Public Community",
                    "The URL was not submitted. POLYSWARM_COMMUNITY is set to the "
                    "public 'default' community, where submissions become visible "
                    "to the PolySwarm community, and POLYSWARM_ALLOW_PUBLIC_COMMUNITY "
                    "is not true.",
                    [
                        "Set POLYSWARM_COMMUNITY to your private PolySwarm community.",
                        "Or set POLYSWARM_ALLOW_PUBLIC_COMMUNITY=true to submit publicly.",
                    ],
                    "Upload to the public community refused "
                    "(POLYSWARM_ALLOW_PUBLIC_COMMUNITY is not true)",
                )

            if not self.config.polyswarm.sandbox_enabled:
                return self._refuse_url(
                    entity,
                    "Sandbox Disabled",
                    "The URL was not submitted. URLs are only detonated in the "
                    "sandbox, and POLYSWARM_SANDBOX_ENABLED is false.",
                    ["Set POLYSWARM_SANDBOX_ENABLED=true to detonate URLs."],
                    "URL not submitted: POLYSWARM_SANDBOX_ENABLED is false",
                )

            # -- SUBMIT
            send_query = self.config.polyswarm.sandbox_url_send_query is True
            submit_url = url_for_submission(value, send_query)
            if not send_query and url_has_query_or_fragment(value):
                self.helper.connector_logger.info(
                    f"[CONNECTOR] {self._enrich_ctx} Query string and fragment "
                    "removed before submission"
                )
            # The sandbox task's sha256 is the SHA-256 of the submitted URL
            url_sha256 = hashlib.sha256(submit_url.encode("utf-8")).hexdigest()

            sandbox_tasks = self._submit_url_sandboxes(submit_url, entity)
            if not sandbox_tasks:
                providers = self._get_sandbox_providers()
                self._send_error_note(
                    entity,
                    "Sandbox Submission Failed",
                    "Failed to submit the URL to sandbox provider(s): "
                    f"{', '.join(providers)}.",
                    [
                        "Verify your PolySwarm plan includes sandbox analysis.",
                        "Check that sandbox provider(s) ({}) are valid.".format(
                            ", ".join(providers)
                        ),
                        "Contact customersuccess@polyswarm.io to enable sandbox features or increase quota.",
                    ],
                )
                return {
                    "status": "error",
                    "error": "URL sandbox submission to PolySwarm API failed",
                }

            # -- POLL SANDBOXES (same interval and timeout as files)
            llm_task_ids: dict[str, str] = {}
            sandbox_results = self._phase_poll_sandboxes(
                entity,
                sandbox_tasks,
                self.config.polyswarm.poll_interval,
                self.config.polyswarm.sandbox_timeout,
                llm_task_ids,
            )

            # -- PROCESS
            sandbox_processed, sandbox_failures = self._process_sandbox_results(
                sandbox_results
            )

            # -- REPORTS (JSON, PDF, LLM): named from the URL's SHA-256, never the URL
            llm_reports = self._phase_reports(
                entity,
                None,
                None,
                None,
                sandbox_tasks,
                sandbox_results,
                llm_task_ids,
                f"url_{url_sha256[:16]}",
                url_sha256,
            )

            # -- STIX BUNDLE
            self._phase_stix(
                entity,
                None,
                None,
                sandbox_processed,
                sandbox_failures,
                llm_reports,
                stix_objects,
            )
            return None

        except PolySwarmAPIError:
            raise
        except Exception as e:
            # The exception text is not logged here: it could carry the URL
            self.helper.connector_logger.error(
                f"[CONNECTOR] {self._enrich_ctx} URL enrichment failure: "
                f"{type(e).__name__}"
            )
            raise
        finally:
            self._enrich_ctx = ""

    def _debug_sandbox_structure(self, sandbox_res: dict) -> None:
        """Log the key hierarchy of a sandbox result for troubleshooting IOC extraction.

        Only called when connector log level is ``debug`` (see PROD-24).
        """
        self.helper.connector_logger.debug(
            "[CONNECTOR] === Sandbox Structure Debug ==="
        )
        self.helper.connector_logger.debug(
            f"[CONNECTOR] Top-level keys: {list(sandbox_res.keys())}"
        )

        if sandbox_res.get("domains"):
            self.helper.connector_logger.debug(
                f"[CONNECTOR] result['domains']: {len(sandbox_res['domains'])} items"
            )

        report = sandbox_res.get("report", {})
        if report:
            self.helper.connector_logger.debug(
                f"[CONNECTOR] report keys: {list(report.keys())}"
            )

            if report.get("domains"):
                self.helper.connector_logger.debug(
                    f"[CONNECTOR] report['domains']: {len(report['domains'])} items"
                )

            network = report.get("network", {})
            if network:
                self.helper.connector_logger.debug(
                    f"[CONNECTOR] report['network'] keys: {list(network.keys())}"
                )
                for key in ["dns", "http", "hosts", "tcp", "udp"]:
                    if network.get(key):
                        self.helper.connector_logger.debug(
                            f"[CONNECTOR] network['{key}']: {len(network[key])} items"
                        )

    def _merge_stix_objects(
        self, original: dict[str, Any], update: dict[str, Any]
    ) -> dict[str, Any]:
        """Merge enrichment updates into the original STIX observable.

        Additive for list fields (labels, external_references);
        overwrite for scalar fields (score, created_by_ref).
        Preserves the original's ID so OpenCTI treats it as an update, not a new entity.
        """
        merged = original.copy()

        if update.get("created_by_ref"):
            merged["created_by_ref"] = update["created_by_ref"]

        if update.get("x_opencti_score") is not None:
            merged["x_opencti_score"] = update["x_opencti_score"]

        if update.get("x_opencti_labels"):
            current = merged.get("x_opencti_labels", [])
            if isinstance(current, list):
                for label in update["x_opencti_labels"]:
                    if label not in current:
                        current.append(label)
                merged["x_opencti_labels"] = current
            else:
                merged["x_opencti_labels"] = update["x_opencti_labels"]

        if update.get("external_references"):
            current = merged.get("external_references", [])
            if isinstance(current, list):
                existing = {ref.get("source_name") for ref in current}
                for ref in update["external_references"]:
                    if ref.get("source_name") not in existing:
                        current.append(ref)
                merged["external_references"] = current
            else:
                merged["external_references"] = update["external_references"]

        if update.get("x_opencti_description"):
            current = merged.get("x_opencti_description", "")
            new_desc = update["x_opencti_description"]
            if new_desc and new_desc not in current:
                merged["x_opencti_description"] = (
                    f"{current}\n\n{new_desc}" if current else new_desc
                )

        if update.get("hashes") and not merged.get("hashes"):
            merged["hashes"] = update["hashes"]

        if update.get("name") and not merged.get("name"):
            merged["name"] = update["name"]

        return merged
