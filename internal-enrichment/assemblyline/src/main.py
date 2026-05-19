"""OpenCTI AssemblyLine internal-enrichment connector.

Submits StixFile / Artifact observables to an AssemblyLine 4
deployment, polls until analysis completes (within the configured
timeout), and pushes the results back into OpenCTI:

* a Malware-Analysis SDO (submission id, profile, verdict, score);
* STIX Indicator + Observable pairs for every malicious IOC
  (domains, IPs, URLs);
* Malware SDOs for every malware family attributed to the file;
* Attack-Pattern SDOs for every MITRE ATT&CK technique observed
  at runtime, linked to the generated indicators with `related-to`;
* a Note summarising the verdict and counts;
* an External-Reference attached to the enriched observable.
"""

from __future__ import annotations

import base64
import io
import json
import os
import sys
import time
import traceback
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests
import stix2
import yaml
from assemblyline_client import get_client
from pycti import OpenCTIConnectorHelper, get_config_variable

_BOOL_TRUE = {"true", "1", "yes", "on"}
_BOOL_FALSE = {"false", "0", "no", "off"}

_DEFAULT_HTTP_TIMEOUT = 60  # seconds, used for non-streaming AssemblyLine calls
_POLL_SLEEP_SECONDS = 10


def _coerce_bool(value: Any, default: bool) -> bool:
    """Best-effort conversion of a config value to ``bool``.

    Treats common truthy / falsy strings ("true", "false", "1", "0", ...)
    as the corresponding boolean. Anything else falls back to ``default``.
    This is required because environment variables always arrive as
    strings, and passing the raw string to ``requests`` (e.g. for
    ``verify``) would be misinterpreted as a CA bundle path.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in _BOOL_TRUE:
            return True
        if lowered in _BOOL_FALSE:
            return False
    return default


class AssemblyLineConnector:
    """OpenCTI internal-enrichment connector for AssemblyLine 4."""

    def __init__(self) -> None:
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        self.opencti_url = get_config_variable(
            "OPENCTI_URL", ["opencti", "url"], config
        )
        self.opencti_token = get_config_variable(
            "OPENCTI_TOKEN", ["opencti", "token"], config
        )

        self.assemblyline_url = get_config_variable(
            "ASSEMBLYLINE_URL", ["assemblyline", "url"], config
        )
        self.assemblyline_user = get_config_variable(
            "ASSEMBLYLINE_USER", ["assemblyline", "user"], config
        )
        self.assemblyline_apikey = get_config_variable(
            "ASSEMBLYLINE_APIKEY", ["assemblyline", "apikey"], config
        )
        self.assemblyline_verify_ssl = _coerce_bool(
            get_config_variable(
                "ASSEMBLYLINE_VERIFY_SSL",
                ["assemblyline", "verify_ssl"],
                config,
                False,
                True,
            ),
            default=True,
        )
        self.assemblyline_submission_profile = get_config_variable(
            "ASSEMBLYLINE_SUBMISSION_PROFILE",
            ["assemblyline", "submission_profile"],
            config,
            False,
            "static_with_dynamic",
        )
        self.assemblyline_classification = get_config_variable(
            "ASSEMBLYLINE_CLASSIFICATION",
            ["assemblyline", "classification"],
            config,
            False,
            "TLP:C",
        )
        self.assemblyline_timeout = int(
            get_config_variable(
                "ASSEMBLYLINE_TIMEOUT",
                ["assemblyline", "timeout"],
                config,
                False,
                600,
            )
        )
        self.assemblyline_force_resubmit = _coerce_bool(
            get_config_variable(
                "ASSEMBLYLINE_FORCE_RESUBMIT",
                ["assemblyline", "force_resubmit"],
                config,
                False,
                False,
            ),
            default=False,
        )
        self.assemblyline_max_file_size_mb = float(
            get_config_variable(
                "ASSEMBLYLINE_MAX_FILE_SIZE_MB",
                ["assemblyline", "max_file_size_mb"],
                config,
                False,
                1,
            )
        )
        self.assemblyline_include_suspicious = _coerce_bool(
            get_config_variable(
                "ASSEMBLYLINE_INCLUDE_SUSPICIOUS",
                ["assemblyline", "include_suspicious"],
                config,
                False,
                False,
            ),
            default=False,
        )
        self.assemblyline_create_attack_patterns = _coerce_bool(
            get_config_variable(
                "ASSEMBLYLINE_CREATE_ATTACK_PATTERNS",
                ["assemblyline", "create_attack_patterns"],
                config,
                False,
                True,
            ),
            default=True,
        )
        self.assemblyline_create_malware_analysis = _coerce_bool(
            get_config_variable(
                "ASSEMBLYLINE_CREATE_MALWARE_ANALYSIS",
                ["assemblyline", "create_malware_analysis"],
                config,
                False,
                True,
            ),
            default=True,
        )
        self.assemblyline_create_observables = _coerce_bool(
            get_config_variable(
                "ASSEMBLYLINE_CREATE_OBSERVABLES",
                ["assemblyline", "create_observables"],
                config,
                False,
                True,
            ),
            default=True,
        )
        self.assemblyline_sequential_mode = _coerce_bool(
            get_config_variable(
                "ASSEMBLYLINE_SEQUENTIAL_MODE",
                ["assemblyline", "sequential_mode"],
                config,
                False,
                True,
            ),
            default=True,
        )
        self.assemblyline_poll_interval = int(
            get_config_variable(
                "ASSEMBLYLINE_POLL_INTERVAL",
                ["assemblyline", "poll_interval"],
                config,
                False,
                30,
            )
        )
        self.assemblyline_max_tlp = get_config_variable(
            "ASSEMBLYLINE_MAX_TLP",
            ["assemblyline", "max_tlp"],
            config,
            False,
            "TLP:AMBER",
        )

        self.helper.log_info(
            f"AssemblyLine submission profile: {self.assemblyline_submission_profile}"
        )
        self.helper.log_info(f"AssemblyLine timeout: {self.assemblyline_timeout}s")
        self.helper.log_info(
            f"AssemblyLine force resubmit: {self.assemblyline_force_resubmit}"
        )
        self.helper.log_info(
            f"AssemblyLine max file size: {self.assemblyline_max_file_size_mb} MB"
        )
        self.helper.log_info(
            f"AssemblyLine include suspicious: {self.assemblyline_include_suspicious}"
        )
        self.helper.log_info(
            f"AssemblyLine create attack patterns: {self.assemblyline_create_attack_patterns}"
        )
        self.helper.log_info(
            f"AssemblyLine create malware analysis: {self.assemblyline_create_malware_analysis}"
        )
        self.helper.log_info(
            f"AssemblyLine create observables: {self.assemblyline_create_observables}"
        )
        self.helper.log_info(
            f"AssemblyLine sequential mode: {self.assemblyline_sequential_mode}"
        )
        self.helper.log_info(
            f"AssemblyLine poll interval: {self.assemblyline_poll_interval}s"
        )
        self.helper.log_info(f"AssemblyLine max TLP: {self.assemblyline_max_tlp}")

        self.al_client = get_client(
            self.assemblyline_url,
            apikey=(self.assemblyline_user, self.assemblyline_apikey),
            verify=self.assemblyline_verify_ssl,
        )

        self.assemblyline_author: Optional[str] = None
        self.assemblyline_identity_standard_id: Optional[str] = None
        self._get_assemblyline_identity()

    # ------------------------------------------------------------------ #
    # Identity / TLP gate                                                #
    # ------------------------------------------------------------------ #

    def _get_assemblyline_identity(self) -> None:
        """Lookup or create the AssemblyLine organization identity."""
        try:
            identities = self.helper.api.identity.list(
                filters={
                    "mode": "and",
                    "filters": [{"key": "name", "values": ["AssemblyLine"]}],
                    "filterGroups": [],
                }
            )
            if identities:
                self.helper.log_info("Found existing AssemblyLine identity")
                self.assemblyline_author = identities[0]["id"]
                self.assemblyline_identity_standard_id = identities[0].get(
                    "standard_id"
                )
                return

            identity = self.helper.api.identity.create(
                type="Organization",
                name="AssemblyLine",
                description="AssemblyLine Malware Analysis System",
            )
            self.helper.log_info("Created new AssemblyLine identity")
            self.assemblyline_author = identity["id"]
            self.assemblyline_identity_standard_id = identity.get("standard_id")
        except Exception as exc:
            self.helper.log_warning(
                f"Could not create/find AssemblyLine identity: {exc}"
            )
            self.assemblyline_author = None
            self.assemblyline_identity_standard_id = None

    def _check_tlp(self, observable: Dict[str, Any]) -> None:
        """Raise ``ValueError`` when the observable's TLP exceeds the max."""
        tlp = "TLP:CLEAR"
        for marking in observable.get("objectMarking", []) or []:
            if marking.get("definition_type") == "TLP":
                tlp = marking.get("definition", tlp)
        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.assemblyline_max_tlp):
            raise ValueError(
                f"Do not send any data, TLP of the observable ({tlp}) is greater than "
                f"max TLP ({self.assemblyline_max_tlp})"
            )

    # ------------------------------------------------------------------ #
    # File retrieval                                                     #
    # ------------------------------------------------------------------ #

    def _download_import_file(self, file_id: str) -> bytes:
        """Download a file from OpenCTI's storage via the REST API."""
        try:
            file_url = f"{self.opencti_url}/storage/get/{file_id}"
            self.helper.log_info(f"Downloading file from: {file_url}")

            headers = {
                "Authorization": f"Bearer {self.opencti_token}",
                "Accept": "application/octet-stream",
            }
            response = requests.get(file_url, headers=headers, timeout=120)
            if response.status_code != 200:
                raise Exception(f"Failed to download file: HTTP {response.status_code}")
            self.helper.log_info(
                f"Successfully downloaded {len(response.content)} bytes"
            )
            self._current_file_size = len(response.content)
            return response.content
        except Exception as exc:
            raise Exception(f"Error downloading import file: {exc}") from exc

    def _select_sha256(self, hashes: List[Dict[str, Any]]) -> Optional[str]:
        """Return the SHA-256 hash from an OpenCTI hashes list, if any."""
        for hash_entry in hashes or []:
            if hash_entry.get("algorithm") == "SHA-256":
                return hash_entry.get("hash")
        return None

    def _select_any_hash(self, hashes: List[Dict[str, Any]]) -> Optional[str]:
        """Return the first available hash (preferring SHA-256)."""
        sha256 = self._select_sha256(hashes)
        if sha256:
            return sha256
        if hashes:
            return hashes[0].get("hash")
        return None

    def _fetch_attached_file(self, file_id: str) -> bytes:
        """Fetch a file attached to an observable via the storage API.

        Wraps :func:`pycti.OpenCTIApiClient.fetch_opencti_file` with the
        canonical ``/storage/get/{id}`` URL pattern used across the
        other sandbox connectors in this monorepo.
        """
        file_uri = f"{self.opencti_url}/storage/get/{file_id}"
        return self.helper.api.fetch_opencti_file(file_uri, binary=True)

    def _get_file_content(
        self, observable: Dict[str, Any]
    ) -> Tuple[Optional[bytes], Optional[str], Optional[str]]:
        """Retrieve file content for an observable.

        Returns a ``(file_content, file_name, file_hash)`` tuple. When
        ``file_content`` is ``None`` but ``file_hash`` is set, the caller
        should look up existing AssemblyLine results for that hash.
        """
        entity_type = observable.get("entity_type")

        if entity_type == "Artifact":
            return self._get_artifact_content(observable)
        if entity_type == "StixFile":
            return self._get_stixfile_content(observable)
        raise Exception(f"Unsupported entity type: {entity_type}")

    def _get_artifact_content(
        self, observable: Dict[str, Any]
    ) -> Tuple[Optional[bytes], Optional[str], Optional[str]]:
        """Resolve content for an ``Artifact`` observable (with retries)."""
        max_retries = 3
        retry_delays = [5, 10, 15]

        file_content: Optional[bytes] = None
        file_name: Optional[str] = None
        file_hash: Optional[str] = None

        for attempt in range(max_retries):
            self.helper.log_info(
                f"Retrieving file content (attempt {attempt + 1}/{max_retries})"
            )

            if observable.get("payload_bin"):
                file_content = base64.b64decode(observable["payload_bin"])
                file_name = (
                    observable.get("x_opencti_additional_names")
                    or [f"artifact_{str(observable.get('id', 'unknown'))[:8]}"]
                )[0]
                hashes = observable.get("hashes", [])
                file_hash = self._select_any_hash(hashes) or "unknown"
                self.helper.log_info("File content found in payload_bin")
                return file_content, file_name, file_hash

            import_files = observable.get("importFiles") or []
            if import_files:
                import_file = import_files[0]
                file_id = import_file["id"]
                file_name = import_file.get("name", "artifact")
                self.helper.log_info(f"Fetching file from importFiles: {file_id}")
                try:
                    file_content = self._download_import_file(file_id)
                    file_hash = (
                        self._select_any_hash(observable.get("hashes", [])) or "unknown"
                    )
                    self.helper.log_info("File content found in importFiles")
                    return file_content, file_name, file_hash
                except Exception as exc:
                    self.helper.log_warning(
                        f"Failed to download from importFiles: {exc}"
                    )

            x_files = observable.get("x_opencti_files") or []
            if x_files:
                file_id = x_files[0]["id"]
                file_name = x_files[0].get("name", "artifact")
                try:
                    file_content = self._fetch_attached_file(file_id)
                    file_hash = (
                        self._select_any_hash(observable.get("hashes", [])) or "unknown"
                    )
                    self.helper.log_info("File content found in x_opencti_files")
                    return file_content, file_name, file_hash
                except Exception as exc:
                    self.helper.log_warning(
                        f"Failed to fetch from x_opencti_files: {exc}"
                    )

            if attempt < max_retries - 1:
                delay = retry_delays[attempt]
                self.helper.log_info(
                    f"File content not available yet, waiting {delay}s before retry "
                    "(upload may still be in progress)..."
                )
                time.sleep(delay)
                try:
                    observable_id = observable.get("id")
                    if observable_id:
                        refreshed = self.helper.api.stix_cyber_observable.read(
                            id=observable_id
                        )
                        if refreshed:
                            observable = refreshed
                            self.helper.log_info(
                                "Successfully refreshed observable data"
                            )
                except Exception as exc:
                    self.helper.log_warning(f"Error refreshing observable: {exc}")

        # No file content recovered - try hash lookup
        file_hash = self._select_any_hash(observable.get("hashes", []))
        if file_hash:
            self.helper.log_info(
                f"No file content available, checking AssemblyLine for hash: {file_hash}"
            )
            if self._check_existing_analysis(file_hash):
                self.helper.log_info("Existing AssemblyLine analysis found for hash")
                return None, None, file_hash
        raise Exception(
            "Artifact has no file content for analysis. File may still be uploading "
            "or artifact contains only hashes."
        )

    def _get_stixfile_content(
        self, observable: Dict[str, Any]
    ) -> Tuple[Optional[bytes], Optional[str], Optional[str]]:
        """Resolve content for a ``StixFile`` observable.

        Mirrors what other sandbox connectors do: try ``importFiles``
        first (the canonical upload path for StixFiles), then
        ``x_opencti_files`` as a fallback, and finally fall back to a
        hash lookup if neither carries content.
        """
        hashes = observable.get("hashes", [])
        file_hash = self._select_any_hash(hashes) or observable.get("name") or "unknown"
        file_name = observable.get("name", file_hash)
        file_content: Optional[bytes] = None

        import_files = observable.get("importFiles") or []
        if import_files:
            import_file = import_files[0]
            file_id = import_file["id"]
            file_name = import_file.get("name", file_name)
            try:
                file_content = self._download_import_file(file_id)
                self.helper.log_info("File content found in importFiles")
            except Exception as exc:
                self.helper.log_warning(f"Failed to download from importFiles: {exc}")

        if not file_content:
            x_files = observable.get("x_opencti_files") or []
            if x_files:
                file_id = x_files[0]["id"]
                file_name = x_files[0].get("name", file_name)
                try:
                    file_content = self._fetch_attached_file(file_id)
                    self.helper.log_info("File content found in x_opencti_files")
                except Exception as exc:
                    self.helper.log_warning(
                        f"Failed to fetch from x_opencti_files: {exc}"
                    )

        if file_content:
            return file_content, file_name, file_hash

        sha256 = self._select_sha256(hashes)
        if sha256:
            self.helper.log_info(
                f"StixFile has no content, checking AssemblyLine for hash: {sha256}"
            )
            if self._check_existing_analysis(sha256):
                self.helper.log_info("Existing AssemblyLine analysis found for hash")
                return None, None, sha256

        raise Exception(
            f"StixFile has no accessible file content. Only hash available: {file_hash}"
        )

    # ------------------------------------------------------------------ #
    # AssemblyLine interactions                                          #
    # ------------------------------------------------------------------ #

    def _check_existing_analysis(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Look up an existing AssemblyLine submission for a SHA-256 hash."""
        try:
            self.helper.log_info(f"Checking existing analysis for SHA-256: {file_hash}")
            try:
                _ = self.al_client.file.info(file_hash)
                self.helper.log_info("File found in AssemblyLine database")
            except Exception as exc:
                self.helper.log_info(f"File not found in database: {exc}")

            self.helper.log_info("Searching submissions for this hash...")
            query = f"files.sha256:{file_hash}"
            search_result = self.al_client.search.submission(
                query, rows=1, sort="times.submitted desc"
            )

            if search_result.get("total", 0) <= 0:
                self.helper.log_info(
                    "No existing analysis found, new submission required"
                )
                return None

            items = search_result.get("items", [])
            if not items:
                return None
            sid = items[0].get("sid")
            self.helper.log_info(f"Found existing submission: {sid}")

            try:
                full_result = self.al_client.submission.full(sid)
            except Exception as exc:
                self.helper.log_warning(f"Error checking submission {sid}: {exc}")
                return None
            if not full_result:
                self.helper.log_info("Could not retrieve submission details")
                return None
            state = full_result.get("state", "unknown")
            self.helper.log_info(f"Existing submission state: {state}")
            if state != "completed":
                self.helper.log_info(
                    f"Existing submission not completed (state: {state})"
                )
                return None

            max_score = full_result.get("max_score", 0)
            self.helper.log_info(f"Reusing completed submission (score: {max_score})")
            summary_result = self.al_client.submission.summary(sid)
            if summary_result:
                summary_result["sid"] = sid
                summary_result["state"] = state
                if max_score:
                    summary_result["max_score"] = max_score
                if "file_info" in full_result:
                    summary_result["file_info"] = full_result["file_info"]
                if "times" in full_result:
                    summary_result["times"] = full_result["times"]
                return summary_result
            full_result["sid"] = sid
            return full_result
        except Exception as exc:
            self.helper.log_warning(f"Error checking existing analysis: {exc}")
            return None

    def _wait_for_al_ready(self, deadline: float) -> None:
        """Block until AssemblyLine has no in-flight submissions.

        Honours the configured analysis timeout (``deadline`` is a
        monotonic-clock cut-off in seconds) so the connector can never
        block forever even when AssemblyLine stays busy.
        """
        if not self.assemblyline_sequential_mode:
            return

        while True:
            try:
                result = self.al_client.search.submission("state:submitted", rows=0)
                active_count = result.get("total", 0)
                if active_count == 0:
                    self.helper.log_info(
                        "[Sequential] AssemblyLine is idle, proceeding with submission"
                    )
                    return
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise Exception(
                        "[Sequential] Timed out waiting for AssemblyLine to become "
                        f"idle ({active_count} active submissions remained)"
                    )
                self.helper.log_info(
                    f"[Sequential] AssemblyLine has {active_count} active analysis(es), "
                    f"waiting {self.assemblyline_poll_interval}s "
                    f"({int(remaining)}s remaining before timeout)..."
                )
            except Exception as exc:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise
                self.helper.log_warning(
                    f"[Sequential] Error checking AL status: {exc}, retrying in "
                    f"{self.assemblyline_poll_interval}s..."
                )
            time.sleep(self.assemblyline_poll_interval)

    def _process_file(self, observable: Dict[str, Any]) -> Dict[str, Any]:
        """Submit (or reuse) an AssemblyLine analysis for an observable."""
        deadline = time.monotonic() + self.assemblyline_timeout

        self.helper.log_info(
            "Processing observable: "
            f"{observable.get('observable_value', observable.get('name', 'unknown'))}"
        )

        file_content, file_name, file_hash = self._get_file_content(observable)

        if file_content is None and file_hash:
            self.helper.log_info(
                f"Using existing AssemblyLine results for hash: {file_hash}"
            )
            existing_results = self._check_existing_analysis(file_hash)
            if existing_results:
                return existing_results
            raise Exception(
                f"No file content and no existing analysis found for hash: {file_hash}"
            )

        file_size_mb = len(file_content) / (1024 * 1024)
        if file_size_mb > self.assemblyline_max_file_size_mb:
            raise Exception(
                f"File size ({file_size_mb:.2f} MB) exceeds maximum limit "
                f"({self.assemblyline_max_file_size_mb} MB)"
            )

        self.helper.log_info(
            f"Processing file: {file_name} ({file_size_mb:.2f} MB, SHA-256: {file_hash})"
        )

        if not self.assemblyline_force_resubmit and file_hash:
            existing_results = self._check_existing_analysis(file_hash)
            if existing_results:
                self.helper.log_info("Using existing AssemblyLine results")
                return existing_results
        elif self.assemblyline_force_resubmit:
            self.helper.log_info("Force resubmit enabled")

        self.helper.log_info(
            f"Submitting file to AssemblyLine: {file_name} ({len(file_content)} bytes)"
        )
        self.helper.log_info(
            f"Submission profile: {self.assemblyline_submission_profile}"
        )

        self._wait_for_al_ready(deadline)

        json_data = {
            "name": file_name,
            "submission_profile": self.assemblyline_submission_profile,
            "metadata": {"submitter": "opencti-connector", "source": "OpenCTI"},
            "params": {
                "classification": self.assemblyline_classification,
                "description": f'Submitted from OpenCTI - {observable["id"]}',
                "deep_scan": False,
                "priority": 1000,
                "ignore_cache": False,
                "services": {"selected": [], "resubmit": [], "excluded": []},
            },
        }
        files = {
            "json": (None, json.dumps(json_data), "application/json"),
            "bin": (
                file_name,
                io.BytesIO(file_content),
                "application/octet-stream",
            ),
        }
        submit_url = f"{self.assemblyline_url}/api/v4/submit/"
        headers = {
            "X-User": self.assemblyline_user,
            "X-Apikey": self.assemblyline_apikey,
        }

        remaining = max(1, int(deadline - time.monotonic()))
        request_timeout = min(_DEFAULT_HTTP_TIMEOUT, remaining)
        self.helper.log_info(f"Submitting to {submit_url}")
        try:
            response = requests.post(
                submit_url,
                files=files,
                headers=headers,
                verify=self.assemblyline_verify_ssl,
                timeout=request_timeout,
            )
        except requests.RequestException as exc:
            raise Exception(f"Submission failed: {exc}") from exc

        if response.status_code != 200:
            raise Exception(f"HTTP {response.status_code}: {response.text}")
        result = response.json()
        submission = result.get("api_response", result)
        submission_id = submission.get("sid")
        if not submission_id:
            raise Exception("AssemblyLine did not return a submission id")
        self.helper.log_info(f"Submission successful: SID={submission_id}")

        while time.monotonic() < deadline:
            try:
                result = self.al_client.submission.full(submission_id)
                if result:
                    state = result.get("state", "unknown")
                    self.helper.log_info(f"Submission state: {state}")
                    if state == "completed":
                        self.helper.log_info("Analysis completed successfully")
                        summary_result = self.al_client.submission.summary(
                            submission_id
                        )
                        if summary_result:
                            summary_result["sid"] = submission_id
                            summary_result["state"] = state
                            if "max_score" in result:
                                summary_result["max_score"] = result["max_score"]
                            if "file_info" in result:
                                summary_result["file_info"] = result["file_info"]
                            if "times" in result:
                                summary_result["times"] = result["times"]
                            return summary_result
                        result["sid"] = submission_id
                        return result
                    if state == "failed":
                        raise Exception(
                            f"AssemblyLine analysis failed for submission {submission_id}"
                        )
                    if state in ("error", "cancelled"):
                        raise Exception(
                            f"AssemblyLine analysis {state} for submission {submission_id}"
                        )
                    self.helper.log_info(f"Analysis still running, state: {state}")
            except Exception as exc:
                if "does not exist" in str(exc).lower():
                    raise Exception(
                        f"Submission {submission_id} not found in AssemblyLine"
                    ) from exc
                self.helper.log_warning(f"Error checking submission status: {exc}")
            time.sleep(_POLL_SLEEP_SECONDS)

        raise Exception(
            f"Timeout waiting for AssemblyLine results after {self.assemblyline_timeout} seconds"
        )

    # ------------------------------------------------------------------ #
    # IOC / ATT&CK extraction                                            #
    # ------------------------------------------------------------------ #

    def _extract_malicious_iocs(
        self, tags: Optional[Dict[str, Any]]
    ) -> Dict[str, List[str]]:
        """Extract malicious (and optionally suspicious) IOCs from tags."""
        malicious_iocs: Dict[str, List[str]] = {
            "domains": [],
            "ips": [],
            "urls": [],
            "families": [],
        }
        if not tags:
            return malicious_iocs

        classification_types = ["malicious"]
        if self.assemblyline_include_suspicious:
            classification_types.append("suspicious")
        self.helper.log_info(
            f"Extracting IOCs from tags (including: {', '.join(classification_types)})..."
        )

        for main_category, category_data in tags.items():
            if not isinstance(category_data, dict):
                continue
            for tag_type, tag_list in category_data.items():
                if not isinstance(tag_list, list):
                    continue
                for tag_entry in tag_list:
                    if not isinstance(tag_entry, list) or len(tag_entry) < 2:
                        continue
                    value = tag_entry[0]
                    classification = tag_entry[1]
                    if classification == "malicious":
                        pass
                    elif (
                        classification == "suspicious"
                        and self.assemblyline_include_suspicious
                    ):
                        pass
                    else:
                        continue

                    lowered = tag_type.lower()
                    if "domain" in lowered:
                        if value not in malicious_iocs["domains"]:
                            malicious_iocs["domains"].append(value)
                    elif "ip" in lowered:
                        if value not in malicious_iocs["ips"]:
                            malicious_iocs["ips"].append(value)
                    elif "uri" in lowered or "url" in lowered:
                        if value not in malicious_iocs["urls"]:
                            malicious_iocs["urls"].append(value)

            if main_category == "attribution":
                for family_entry in category_data.get("attribution.family", []) or []:
                    if (
                        isinstance(family_entry, list)
                        and family_entry
                        and family_entry[0] not in malicious_iocs["families"]
                    ):
                        malicious_iocs["families"].append(family_entry[0])

        self.helper.log_info(
            f"Extracted IOCs ({', '.join(classification_types)}) - "
            f"Domains: {len(malicious_iocs['domains'])}, "
            f"IPs: {len(malicious_iocs['ips'])}, "
            f"URLs: {len(malicious_iocs['urls'])}, "
            f"Families: {len(malicious_iocs['families'])}"
        )
        return malicious_iocs

    def _extract_attack_patterns(
        self, results: Optional[Dict[str, Any]]
    ) -> List[Dict[str, str]]:
        """Extract MITRE ATT&CK techniques from ``attack_matrix``.

        Returned ``kill_chain_phase`` values keep the hyphenated MITRE
        phase names (e.g. ``defense-evasion``) so OpenCTI can match
        them against the official MITRE ATT&CK kill-chain entries.
        """
        attack_patterns: List[Dict[str, str]] = []
        if not results:
            return attack_patterns
        attack_matrix = results.get("attack_matrix", {}) or {}
        if not attack_matrix:
            self.helper.log_info("No attack_matrix found in AssemblyLine results")
            return attack_patterns

        for tactic, techniques in attack_matrix.items():
            if not isinstance(techniques, list):
                continue
            for technique_entry in techniques:
                if not isinstance(technique_entry, list) or len(technique_entry) < 3:
                    continue
                technique_id = technique_entry[0]
                technique_name = technique_entry[1]
                confidence = technique_entry[2]
                attack_patterns.append(
                    {
                        "technique_id": technique_id,
                        "technique_name": technique_name,
                        "tactic": tactic,
                        "confidence": confidence,
                        "kill_chain_phase": tactic,
                    }
                )

        self.helper.log_info(
            f"Extracted {len(attack_patterns)} ATT&CK techniques across "
            f"{len(attack_matrix)} tactics"
        )
        return attack_patterns

    def _create_attack_patterns(
        self, attack_patterns: List[Dict[str, str]]
    ) -> List[str]:
        """Create / lookup ATT&CK Attack-Pattern SDOs in OpenCTI."""
        created_patterns: List[str] = []
        if not attack_patterns:
            return created_patterns

        for pattern in attack_patterns:
            try:
                attack_pattern_data = {
                    "name": f"{pattern['technique_id']} - {pattern['technique_name']}",
                    "description": (
                        f"MITRE ATT&CK technique {pattern['technique_id']} "
                        f"({pattern['technique_name']}) observed in malware analysis. "
                        f"Tactic: {pattern['tactic']}."
                    ),
                    "x_mitre_id": pattern["technique_id"],
                    "kill_chain_phases": [
                        {
                            "kill_chain_name": "mitre-attack",
                            "phase_name": pattern["kill_chain_phase"],
                        }
                    ],
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": pattern["technique_id"],
                            "url": (
                                "https://attack.mitre.org/techniques/"
                                f"{pattern['technique_id'].replace('.', '/')}"
                            ),
                        }
                    ],
                    "labels": [
                        "assemblyline",
                        pattern["tactic"],
                        pattern["confidence"],
                    ],
                }
                if self.assemblyline_author:
                    attack_pattern_data["createdBy"] = self.assemblyline_author
                attack_pattern = self.helper.api.attack_pattern.create(
                    **attack_pattern_data
                )
                created_patterns.append(attack_pattern["id"])
            except Exception:
                try:
                    existing_patterns = self.helper.api.attack_pattern.list(
                        filters={
                            "mode": "and",
                            "filters": [
                                {
                                    "key": "x_mitre_id",
                                    "values": [pattern["technique_id"]],
                                }
                            ],
                            "filterGroups": [],
                        }
                    )
                    if existing_patterns:
                        created_patterns.append(existing_patterns[0]["id"])
                    else:
                        self.helper.log_warning(
                            f"Could not create or find attack pattern {pattern['technique_id']}"
                        )
                except Exception as search_error:
                    self.helper.log_warning(
                        "Error searching for attack pattern "
                        f"{pattern['technique_id']}: {search_error}"
                    )

        return created_patterns

    # ------------------------------------------------------------------ #
    # STIX object construction                                           #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _score_to_result_name(score: int) -> str:
        """Convert an AssemblyLine score to the STIX malware-analysis result vocabulary."""
        if score >= 500:
            return "malicious"
        if score >= 100:
            return "suspicious"
        if score > 0:
            return "unknown"
        return "benign"

    @staticmethod
    def _is_ipv6(value: str) -> bool:
        """Heuristic IPv4 vs IPv6 split (AssemblyLine does not split them)."""
        return ":" in value

    @staticmethod
    def _escape_stix_string(value: str) -> str:
        """Escape a literal string for inclusion in a STIX pattern.

        STIX 2.1 strings are delimited by single quotes and use
        backslash as the escape character. Escape backslashes
        first so we don't double-escape the quote sequences.
        """
        return value.replace("\\", "\\\\").replace("'", "\\'")

    def _safe_observable_ref(self, observable: Dict[str, Any]) -> str:
        """Return a short, log-safe identifier for an observable.

        Used in error paths so we never write the entire observable
        payload (which may contain ``payload_bin`` file content or
        other sensitive fields) into connector logs.
        """
        return f"{observable.get('entity_type', '?')}:{observable.get('id', 'unknown')}"

    def _parse_al_timestamp(self, value: Any, fallback: datetime) -> datetime:
        """Parse an AssemblyLine timestamp string (best effort)."""
        if not isinstance(value, str):
            return fallback
        cleaned = value.replace("Z", "+00:00").split("+", 1)[0]
        try:
            return datetime.strptime(cleaned, "%Y-%m-%dT%H:%M:%S.%f")
        except ValueError:
            try:
                return datetime.strptime(cleaned, "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                return fallback

    def _create_malware_analysis(
        self,
        observable_id: str,
        observable: Dict[str, Any],
        results: Dict[str, Any],
        malicious_iocs: Dict[str, List[str]],
    ) -> Optional[str]:
        """Emit a Malware-Analysis SDO + analysis_sco_refs bundle."""
        try:
            max_score = results.get("max_score", 0)
            sid = results.get("sid", "unknown")
            times = results.get("times", {}) or {}

            result_value = self._score_to_result_name(max_score)
            has_malicious_iocs = any(malicious_iocs.values())
            if has_malicious_iocs and result_value not in ("malicious", "suspicious"):
                result_value = "malicious"

            now = datetime.now(tz=timezone.utc).replace(tzinfo=None)
            analysis_started = self._parse_al_timestamp(times.get("submitted"), now)
            analysis_ended = self._parse_al_timestamp(times.get("completed"), now)

            stix_entity_id = observable.get("standard_id")
            if not stix_entity_id:
                entity_type = observable.get("entity_type", "Artifact")
                suffix = (
                    observable_id.split("--")[-1]
                    if "--" in observable_id
                    else observable_id
                )
                stix_entity_id = (
                    f"artifact--{suffix}"
                    if entity_type == "Artifact"
                    else f"file--{suffix}"
                )

            external_reference = stix2.ExternalReference(
                source_name="AssemblyLine",
                url=f"{self.assemblyline_url}/submission/{sid}",
                description=f"AssemblyLine analysis report (Score: {max_score}/2000)",
            )
            result_name = f"Result {sid}"
            malware_analysis_id = "malware-analysis--" + str(
                uuid.uuid5(uuid.NAMESPACE_X500, f"{result_name}AssemblyLine")
            )

            stix_objects: List[Any] = []
            analysis_sco_refs: List[str] = []

            for domain in malicious_iocs.get("domains", []):
                try:
                    domain_stix = stix2.DomainName(
                        value=domain,
                        object_marking_refs=[stix2.TLP_WHITE],
                        custom_properties={
                            "created_by_ref": self.assemblyline_identity_standard_id,
                        },
                    )
                    stix_objects.append(domain_stix)
                    analysis_sco_refs.append(domain_stix.id)
                except Exception as exc:
                    self.helper.log_warning(
                        f"Could not create STIX domain {domain}: {exc}"
                    )

            for ip in malicious_iocs.get("ips", []):
                try:
                    if ip in ("127.0.0.1", "::1", "0.0.0.0"):
                        continue
                    if self._is_ipv6(ip):
                        ip_stix = stix2.IPv6Address(
                            value=ip,
                            object_marking_refs=[stix2.TLP_WHITE],
                            custom_properties={
                                "created_by_ref": self.assemblyline_identity_standard_id,
                            },
                        )
                    else:
                        ip_stix = stix2.IPv4Address(
                            value=ip,
                            object_marking_refs=[stix2.TLP_WHITE],
                            custom_properties={
                                "created_by_ref": self.assemblyline_identity_standard_id,
                            },
                        )
                    stix_objects.append(ip_stix)
                    analysis_sco_refs.append(ip_stix.id)
                except Exception as exc:
                    self.helper.log_warning(f"Could not create STIX IP {ip}: {exc}")

            for url in malicious_iocs.get("urls", []):
                try:
                    url_stix = stix2.URL(
                        value=url,
                        object_marking_refs=[stix2.TLP_WHITE],
                        custom_properties={
                            "created_by_ref": self.assemblyline_identity_standard_id,
                        },
                    )
                    stix_objects.append(url_stix)
                    analysis_sco_refs.append(url_stix.id)
                except Exception as exc:
                    self.helper.log_warning(f"Could not create STIX URL {url}: {exc}")

            malware_analysis = stix2.MalwareAnalysis(
                id=malware_analysis_id,
                product="AssemblyLine",
                result_name=result_name,
                result=result_value,
                analysis_started=analysis_started,
                analysis_ended=analysis_ended,
                submitted=analysis_started,
                sample_ref=stix_entity_id,
                created_by_ref=self.assemblyline_identity_standard_id,
                analysis_sco_refs=analysis_sco_refs or None,
                external_references=[external_reference],
            )
            stix_objects.append(malware_analysis)

            serialized_bundle = self.helper.stix2_create_bundle(stix_objects)
            self.helper.send_stix2_bundle(serialized_bundle)
            self.helper.log_info(
                f"Sent Malware Analysis bundle with {len(stix_objects)} objects to OpenCTI"
            )
            return malware_analysis.id
        except Exception as exc:
            self.helper.log_error(f"Error creating Malware Analysis: {exc}")
            self.helper.log_error(f"Traceback: {traceback.format_exc()}")
            return None

    def _attach_external_reference(
        self, observable_id: str, sid: Any, max_score: int
    ) -> None:
        """Attach an AssemblyLine External-Reference to the enriched observable."""
        try:
            external_reference = self.helper.api.external_reference.create(
                source_name="AssemblyLine",
                url=f"{self.assemblyline_url}/submission/{sid}",
                description=f"AssemblyLine analysis report (Score: {max_score}/2000)",
            )
            self.helper.api.stix_cyber_observable.add_external_reference(
                id=observable_id,
                external_reference_id=external_reference["id"],
            )
            self.helper.log_info(
                "Attached AssemblyLine external reference to the enriched observable"
            )
        except Exception as exc:
            self.helper.log_warning(
                f"Could not attach AssemblyLine external reference: {exc}"
            )

    def _create_indicator_observable(
        self,
        observable_id: str,
        ioc_value: str,
        stix_observable_type: str,
        opencti_observable_type: str,
        max_score: int,
        description: str,
    ) -> Optional[str]:
        """Create one Indicator (+ optional matching Observable) for an IOC."""
        try:
            escaped = self._escape_stix_string(ioc_value)
            indicator_data: Dict[str, Any] = {
                "name": ioc_value,
                "description": (f"{description} (AssemblyLine score: {max_score})"),
                "pattern": f"[{stix_observable_type}:value = '{escaped}']",
                "pattern_type": "stix",
                "x_opencti_main_observable_type": opencti_observable_type,
                "valid_from": self.helper.api.stix2.format_date(),
                "labels": ["malicious", "assemblyline"],
                "x_opencti_score": 80,
            }
            if self.assemblyline_author:
                indicator_data["createdBy"] = self.assemblyline_author
            indicator = self.helper.api.indicator.create(**indicator_data)
            self.helper.api.stix_core_relationship.create(
                fromId=observable_id,
                toId=indicator["id"],
                relationship_type="related-to",
                description=description,
            )
            if self.assemblyline_create_observables:
                try:
                    obs_data: Dict[str, Any] = {
                        "observableData": {
                            "type": stix_observable_type,
                            "value": ioc_value,
                        },
                        "x_opencti_score": 80,
                    }
                    if self.assemblyline_author:
                        obs_data["createdBy"] = self.assemblyline_author
                    new_observable = self.helper.api.stix_cyber_observable.create(
                        **obs_data
                    )
                    self.helper.api.stix_cyber_observable.add_label(
                        id=new_observable["id"], label="malicious"
                    )
                    self.helper.api.stix_core_relationship.create(
                        fromId=indicator["id"],
                        toId=new_observable["id"],
                        relationship_type="based-on",
                        description=(
                            "Indicator based on observed malicious IOC from "
                            "AssemblyLine analysis"
                        ),
                    )
                except Exception as obs_exc:
                    self.helper.log_warning(
                        f"Could not create observable for IOC {ioc_value}: {obs_exc}"
                    )
            return indicator["id"]
        except Exception as exc:
            self.helper.log_warning(
                f"Could not create indicator for IOC {ioc_value}: {exc}"
            )
            return None

    def _create_indicators(
        self,
        observable_id: str,
        max_score: int,
        malicious_iocs: Dict[str, List[str]],
    ) -> Tuple[Dict[str, int], List[str]]:
        """Create indicators (and optional observables) for every malicious IOC.

        Returns ``(counts, indicator_ids)`` where ``indicator_ids`` is
        the list of created Indicator standard ids, used downstream to
        link MITRE ATT&CK techniques to them with ``related-to``.
        """
        counts = {"indicators": 0, "observables": 0, "relationships": 0}
        indicator_ids: List[str] = []

        for domain in malicious_iocs["domains"][:20]:
            ind_id = self._create_indicator_observable(
                observable_id,
                domain,
                "domain-name",
                "Domain-Name",
                max_score,
                "Domain contacted during malware analysis",
            )
            if ind_id:
                indicator_ids.append(ind_id)
                counts["indicators"] += 1
                counts["relationships"] += 1
                if self.assemblyline_create_observables:
                    counts["observables"] += 1
                    counts["relationships"] += 1

        for ip in malicious_iocs["ips"][:20]:
            stix_type = "ipv6-addr" if self._is_ipv6(ip) else "ipv4-addr"
            octi_type = "IPv6-Addr" if self._is_ipv6(ip) else "IPv4-Addr"
            ind_id = self._create_indicator_observable(
                observable_id,
                ip,
                stix_type,
                octi_type,
                max_score,
                "IP address contacted during malware analysis",
            )
            if ind_id:
                indicator_ids.append(ind_id)
                counts["indicators"] += 1
                counts["relationships"] += 1
                if self.assemblyline_create_observables:
                    counts["observables"] += 1
                    counts["relationships"] += 1

        for url in malicious_iocs["urls"][:20]:
            ind_id = self._create_indicator_observable(
                observable_id,
                url,
                "url",
                "Url",
                max_score,
                "URL contacted during malware analysis",
            )
            if ind_id:
                indicator_ids.append(ind_id)
                counts["indicators"] += 1
                counts["relationships"] += 1
                if self.assemblyline_create_observables:
                    counts["observables"] += 1
                    counts["relationships"] += 1

        for family in malicious_iocs["families"][:10]:
            try:
                malware_data: Dict[str, Any] = {
                    "name": family,
                    "description": "Malware family identified by AssemblyLine analysis",
                    "is_family": True,
                }
                if self.assemblyline_author:
                    malware_data["createdBy"] = self.assemblyline_author
                malware = self.helper.api.malware.create(**malware_data)
                self.helper.api.stix_core_relationship.create(
                    fromId=observable_id,
                    toId=malware["id"],
                    relationship_type="related-to",
                    description=f"File attributed to {family} by AssemblyLine",
                )
            except Exception as exc:
                self.helper.log_warning(
                    f"Could not create malware family {family}: {exc}"
                )

        return counts, indicator_ids

    # ------------------------------------------------------------------ #
    # Top-level processing                                               #
    # ------------------------------------------------------------------ #

    def _process_message(self, data: Dict[str, Any]) -> str:
        observable = data["enrichment_entity"]
        self.helper.log_info(
            f"Received observable: {self._safe_observable_ref(observable)}"
        )

        if observable["entity_type"] not in ("Artifact", "StixFile"):
            msg = f"Observable type {observable['entity_type']} not supported"
            self.helper.log_info(msg)
            return msg

        try:
            self._check_tlp(observable)
        except ValueError as exc:
            self.helper.log_warning(str(exc))
            return str(exc)

        try:
            self.helper.log_info(f"Starting analysis for observable {observable['id']}")
            results = self._process_file(observable)
            tags = results.get("tags", {}) or {}
            max_score = int(results.get("max_score", 0) or 0)
            sid = results.get("sid", "N/A")

            malicious_iocs = self._extract_malicious_iocs(tags)
            has_malicious_iocs = any(malicious_iocs.values())
            is_malicious = max_score >= 500 or has_malicious_iocs

            if is_malicious:
                try:
                    self.helper.api.stix_cyber_observable.add_label(
                        id=observable["id"], label="malicious"
                    )
                except Exception as exc:
                    self.helper.log_warning(f"Could not add malicious label: {exc}")

            try:
                if max_score > 0:
                    opencti_score = min(100, int((max_score / 2000) * 100))
                elif has_malicious_iocs:
                    opencti_score = 80
                else:
                    opencti_score = 0
                self.helper.api.stix_cyber_observable.update_field(
                    id=observable["id"],
                    input={"key": "x_opencti_score", "value": str(opencti_score)},
                )
            except Exception as exc:
                self.helper.log_warning(f"Could not update score: {exc}")

            counts, indicator_ids = self._create_indicators(
                observable["id"], max_score, malicious_iocs
            )

            malware_analysis_id: Optional[str] = None
            if self.assemblyline_create_malware_analysis:
                malware_analysis_id = self._create_malware_analysis(
                    observable["id"], observable, results, malicious_iocs
                )

            attack_patterns_count = 0
            if self.assemblyline_create_attack_patterns:
                attack_patterns = self._extract_attack_patterns(results)
                if attack_patterns:
                    created_attack_patterns = self._create_attack_patterns(
                        attack_patterns
                    )
                    attack_patterns_count = len(created_attack_patterns)
                    for indicator_id in indicator_ids:
                        for pattern_id in created_attack_patterns:
                            try:
                                self.helper.api.stix_core_relationship.create(
                                    fromId=indicator_id,
                                    toId=pattern_id,
                                    relationship_type="related-to",
                                    description=(
                                        "Indicator related to ATT&CK technique "
                                        "observed during AssemblyLine analysis"
                                    ),
                                )
                            except Exception as exc:
                                self.helper.log_warning(
                                    "Could not relate indicator to attack pattern: "
                                    f"{exc}"
                                )

            self._attach_external_reference(observable["id"], sid, max_score)

            self._create_summary_note(
                observable,
                results,
                malicious_iocs,
                counts,
                malware_analysis_id,
                attack_patterns_count,
            )

            return (
                "File successfully analyzed by AssemblyLine and malicious indicators "
                "created"
            )
        except Exception as exc:
            error_msg = f"Error processing file: {exc}"
            self.helper.log_error(error_msg)
            self.helper.log_error(
                f"Observable reference: {self._safe_observable_ref(observable)}"
            )
            self.helper.log_error(f"Traceback: {traceback.format_exc()}")
            return error_msg

    def _create_summary_note(
        self,
        observable: Dict[str, Any],
        results: Dict[str, Any],
        malicious_iocs: Dict[str, List[str]],
        counts: Dict[str, int],
        malware_analysis_id: Optional[str],
        attack_patterns_count: int,
    ) -> None:
        max_score = int(results.get("max_score", 0) or 0)
        sid = results.get("sid", "N/A")
        file_info = results.get("file_info", {}) or {}
        if not file_info and "api_response" in results:
            file_info = results["api_response"].get("file_info", {}) or {}

        file_sha256 = file_info.get("sha256") or "N/A"
        file_type = file_info.get("type") or "N/A"
        file_size: Any = file_info.get("size") or "N/A"

        if file_sha256 == "N/A":
            for hash_entry in observable.get("hashes", []) or []:
                if (
                    isinstance(hash_entry, dict)
                    and hash_entry.get("algorithm") == "SHA-256"
                ):
                    file_sha256 = hash_entry.get("hash") or "N/A"
                    break

        if file_size == "N/A":
            if observable.get("payload_bin"):
                try:
                    file_size = len(base64.b64decode(observable["payload_bin"]))
                except Exception:
                    pass
            elif observable.get("size"):
                file_size = observable.get("size")
            elif observable.get("x_opencti_size"):
                file_size = observable.get("x_opencti_size")
            elif getattr(self, "_current_file_size", None):
                file_size = self._current_file_size

        if file_type == "N/A" and observable.get("mime_type"):
            file_type = observable.get("mime_type")

        if isinstance(file_size, (int, float)) and file_size != "N/A":
            if file_size >= 1024 * 1024:
                size_str = f"{file_size:,} bytes ({file_size / (1024 * 1024):.1f} MB)"
            elif file_size >= 1024:
                size_str = f"{file_size:,} bytes ({file_size / 1024:.1f} KB)"
            else:
                size_str = f"{file_size:,} bytes"
        else:
            size_str = "N/A bytes"

        verdict = (
            "MALICIOUS" if max_score >= 500 or any(malicious_iocs.values()) else "SAFE"
        )
        malware_analysis_note = (
            "\n**Malware Analysis Created:** Yes (visible in Malware Analysis section)"
            if malware_analysis_id
            else "\n**Malware Analysis Created:** No"
        )
        observables_note = (
            f"\n**Observables Created:** {counts.get('observables', 0)} "
            "(linked to indicators with 'based-on' relationships)"
            if self.assemblyline_create_observables
            else ""
        )

        note_content = f"""# AssemblyLine Analysis Results

**Verdict:** {verdict}
**Score:** {max_score}/2000
**Submission ID:** {sid}{malware_analysis_note}

## Malicious IOCs Created as Indicators
- **Malicious Domains:** {len(malicious_iocs['domains'])}
- **Malicious IP Addresses:** {len(malicious_iocs['ips'])}
- **Malicious URLs:** {len(malicious_iocs['urls'])}
- **Malware Families:** {len(malicious_iocs['families'])}{observables_note}

## MITRE ATT&CK Analysis
- **Attack Techniques Identified:** {attack_patterns_count}

## File Information
- **SHA256:** {file_sha256}
- **Type:** {file_type}
- **Size:** {size_str}

View full results in AssemblyLine: {self.assemblyline_url}/submission/{sid}
"""

        note_data: Dict[str, Any] = {
            "abstract": "AssemblyLine Analysis Results",
            "content": note_content,
            "object_refs": [observable["id"]],
        }
        if self.assemblyline_author:
            note_data["createdBy"] = self.assemblyline_author
        try:
            self.helper.api.note.create(**note_data)
        except Exception as exc:
            self.helper.log_warning(f"Could not create summary note: {exc}")

    def start(self) -> None:
        self.helper.log_info("Starting AssemblyLine connector...")
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    try:
        connector = AssemblyLineConnector()
        connector.start()
    except Exception as exc:
        print(exc)
        traceback.print_exc()
        time.sleep(10)
        sys.exit(0)
