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
import binascii
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
from pycti import MarkingDefinition, OpenCTIConnectorHelper, get_config_variable

# OpenCTI's canonical ID for the custom TLP:CLEAR marking definition. The
# platform uses a custom marking object (built with this id) rather than
# the legacy ``stix2.TLP_WHITE`` constant, and ``_check_tlp`` already
# treats an unmarked observable as ``TLP:CLEAR``. Using the same id here
# keeps the connector's "no source marking" fallback consistent with
# both the gate and the rest of the codebase.
_TLP_CLEAR_MARKING_ID = MarkingDefinition.generate_id("TLP", "TLP:CLEAR")

_BOOL_TRUE = {"true", "1", "yes", "on"}
_BOOL_FALSE = {"false", "0", "no", "off"}

_DEFAULT_HTTP_TIMEOUT = 60  # seconds, used for non-streaming AssemblyLine calls
_POLL_SLEEP_SECONDS = 10


class AssemblyLineTerminalError(Exception):
    """Raised when AssemblyLine reports a terminal submission state.

    ``failed`` / ``error`` / ``cancelled`` are end-of-life submission
    states — polling them again will never make them succeed. Using a
    dedicated exception type lets the polling loop's broad
    ``except Exception`` catch transient errors (network glitch /
    intermittent ``ApiException`` from ``assemblyline-client``) while
    propagating terminal failures immediately instead of letting the
    connector loop until the global timeout.
    """


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

    @staticmethod
    def _load_config_file(config_file_path: str) -> dict:
        """Load and parse ``config.yml`` using ``yaml.safe_load``.

        Extracted from ``__init__`` so unit tests can pin the
        connector's config-loading code path end-to-end (i.e. that the
        parser used to load ``config.yml`` is ``yaml.safe_load``, not
        ``yaml.load(..., Loader=FullLoader)`` or anything that would
        re-open the YAML-tag attack surface). The previous shape
        carried the parsing logic inline in ``__init__``, which made
        the existing ``TestConfigYamlSafeLoad`` test only able to
        assert the behaviour of ``yaml.safe_load`` itself rather than
        the connector's actual code path — a regression to
        ``FullLoader`` would have silently slipped through.

        ``FullLoader`` can instantiate arbitrary Python objects from
        YAML tags, which means a tampered ``config.yml`` could execute
        code at startup; ``safe_load`` restricts parsing to the YAML
        safe subset (plain mappings / lists / scalars). The
        ``with open(...)`` context manager guarantees the file handle
        is released even if YAML parsing raises. A missing config
        file resolves to an empty dict so the connector can run
        entirely off environment variables in containerised
        deployments.
        """
        if os.path.isfile(config_file_path):
            with open(config_file_path, encoding="utf-8") as fh:
                return yaml.safe_load(fh) or {}
        return {}

    def __init__(self) -> None:
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = self._load_config_file(config_file_path)
        self.helper = OpenCTIConnectorHelper(config)

        # Strip any trailing slash so the connector never builds a URL
        # with a double slash (e.g. ``http://opencti//storage/get/X``).
        # ``requests`` >= 2.34 no longer normalises double slashes, and
        # the repo's ``tests/test_url_construction.py`` guard enforces
        # this convention.
        self.opencti_url = (
            get_config_variable("OPENCTI_URL", ["opencti", "url"], config) or ""
        ).rstrip("/")
        self.opencti_token = get_config_variable(
            "OPENCTI_TOKEN", ["opencti", "token"], config
        )

        self.assemblyline_url = (
            get_config_variable("ASSEMBLYLINE_URL", ["assemblyline", "url"], config)
            or ""
        ).rstrip("/")
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
        # Clamp the configured value to a minimum of 1 second. The JSON
        # schema already advertises ``minimum: 1`` but a stale / hand-rolled
        # ``config.yml`` or ``ASSEMBLYLINE_POLL_INTERVAL=0`` env var would
        # turn the sequential-mode wait loop into a busy loop that burns
        # CPU and floods the connector logs with retry messages, so apply
        # the floor here in code too.
        self.assemblyline_poll_interval = max(
            1,
            int(
                get_config_variable(
                    "ASSEMBLYLINE_POLL_INTERVAL",
                    ["assemblyline", "poll_interval"],
                    config,
                    False,
                    30,
                )
            ),
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

    # Map OpenCTI / STIX TLP values to AssemblyLine's compact
    # classification strings (``TLP:C`` / ``TLP:G`` / ``TLP:A`` /
    # ``TLP:R``) — the default labels of the stock AssemblyLine
    # classification engine. ``+STRICT`` variants collapse to the
    # plain colour since stock AssemblyLine does not model strict /
    # non-strict distinctions; deployments that customise their
    # classification engine can still override the connector-wide
    # default via ``ASSEMBLYLINE_CLASSIFICATION``.
    _TLP_TO_AL_CLASSIFICATION: Dict[str, str] = {
        "TLP:CLEAR": "TLP:C",
        "TLP:WHITE": "TLP:C",
        "TLP:GREEN": "TLP:G",
        "TLP:AMBER": "TLP:A",
        "TLP:AMBER+STRICT": "TLP:A",
        "TLP:RED": "TLP:R",
    }

    @staticmethod
    def _source_tlp(observable: Dict[str, Any]) -> str:
        """Return the source observable's TLP marking (``TLP:CLEAR`` default)."""
        tlp = "TLP:CLEAR"
        for marking in observable.get("objectMarking", []) or []:
            if marking.get("definition_type") == "TLP":
                tlp = marking.get("definition", tlp)
        return tlp

    def _check_tlp(self, observable: Dict[str, Any]) -> None:
        """Raise ``ValueError`` when the observable's TLP exceeds the max."""
        tlp = self._source_tlp(observable)
        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.assemblyline_max_tlp):
            raise ValueError(
                f"Do not send any data, TLP of the observable ({tlp}) is greater than "
                f"max TLP ({self.assemblyline_max_tlp})"
            )

    def _resolve_submission_classification(self, observable: Dict[str, Any]) -> str:
        """Return the AssemblyLine classification string to submit with.

        Maps the source observable's TLP to AssemblyLine's compact
        form (``TLP:C`` / ``TLP:G`` / ``TLP:A`` / ``TLP:R``) when the
        observable actually carries a TLP marking. When there is no
        TLP marking on the source (or the marking value is not one
        of the known TLP labels), falls back to the
        operator-configured ``ASSEMBLYLINE_CLASSIFICATION`` so
        deployments with a customised AssemblyLine classification
        engine keep working unchanged.

        The previous behaviour always submitted with
        ``self.assemblyline_classification`` (default ``TLP:C``) —
        that silently downgraded the classification of every sample
        once it left OpenCTI, even when the source was ``TLP:AMBER``
        (which the max-TLP gate allows by default).
        """
        for marking in observable.get("objectMarking", []) or []:
            if marking.get("definition_type") != "TLP":
                continue
            tlp_definition = marking.get("definition")
            if tlp_definition in self._TLP_TO_AL_CLASSIFICATION:
                return self._TLP_TO_AL_CLASSIFICATION[tlp_definition]
        return self.assemblyline_classification

    @staticmethod
    def _source_marking_refs(observable: Dict[str, Any]) -> List[str]:
        """Return the ``object_marking_refs`` to apply to derived objects.

        Derived analysis SCOs (the domains / IPs / URLs the connector
        emits next to the Malware-Analysis SDO) inherit the source
        observable's markings so they cannot be downgraded — a file
        that passes the max-TLP gate with ``TLP:AMBER`` must produce
        ``TLP:AMBER`` analysis observables.

        When the source observable has no marking at all we fall back
        to OpenCTI's custom ``TLP:CLEAR`` marking (the platform's
        documented "public" marking, also the implicit default of
        ``_check_tlp``) rather than the deprecated ``stix2.TLP_WHITE``
        constant. Every derived object still ends up with *some*
        marking so the platform's access-control gates can apply.
        """
        refs: List[str] = []
        for marking in observable.get("objectMarking", []) or []:
            standard_id = marking.get("standard_id")
            if standard_id and standard_id not in refs:
                refs.append(standard_id)
        return refs or [_TLP_CLEAR_MARKING_ID]

    # ------------------------------------------------------------------ #
    # File retrieval                                                     #
    # ------------------------------------------------------------------ #

    def _download_import_file(self, file_id: str) -> bytes:
        """Download a file from OpenCTI's storage via ``pycti``'s helper.

        Going through ``helper.api.fetch_opencti_file`` (rather than a raw
        ``requests.get`` with a manually-set ``Authorization`` header)
        means the connector inherits the pycti HTTP session's
        configuration — timeouts, retries, custom CA bundles, the
        ``OpenCTIApiClient`` proxy / SSL settings — and stays consistent
        with :meth:`_fetch_attached_file`. The previous split between
        ``importFiles`` (raw HTTP) and ``x_opencti_files`` (helper) made
        the importFiles path silently miss any of those policies.
        """
        try:
            file_url = f"{self.opencti_url}/storage/get/{file_id}"
            self.helper.log_info(f"Downloading file from: {file_url}")
            content = self.helper.api.fetch_opencti_file(file_url, binary=True)
            if not isinstance(content, (bytes, bytearray)):
                raise Exception(
                    "fetch_opencti_file returned a non-binary payload "
                    f"({type(content).__name__})"
                )
            self.helper.log_info(f"Successfully downloaded {len(content)} bytes")
            self._current_file_size = len(content)
            return bytes(content)
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
        other sandbox connectors in this monorepo. Both this helper and
        :meth:`_download_import_file` cache the fetched payload size
        into ``self._current_file_size`` so :meth:`_create_summary_note`
        can fall back to it when neither the observable nor the
        AssemblyLine ``file_info`` carry a size.

        ``fetch_opencti_file(..., binary=True)`` is documented to
        return a bytes payload, but in degraded conditions (e.g. an
        HTML error page surfaced by the platform's reverse proxy)
        callers have seen ``str`` come back instead. The downstream
        consumers (``io.BytesIO(file_content)`` in :meth:`_process_file`
        and the ``submit`` call into the AssemblyLine SDK) then crash
        with an opaque ``TypeError`` that points at the wrong place.
        Validate the return type up-front and raise a clear exception
        — mirrors what :meth:`_download_import_file` does for the
        ``importFiles`` path so a failure mode in either fetch path
        surfaces with the same shape.
        """
        file_uri = f"{self.opencti_url}/storage/get/{file_id}"
        content = self.helper.api.fetch_opencti_file(file_uri, binary=True)
        if not isinstance(content, (bytes, bytearray)):
            raise Exception(
                "fetch_opencti_file returned a non-binary payload "
                f"({type(content).__name__})"
            )
        self._current_file_size = len(content)
        return bytes(content)

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
                # ``base64.b64decode`` raises ``binascii.Error`` (a
                # ``ValueError`` subclass) on malformed input.
                # Without an explicit guard, a single corrupted
                # observable would bypass the retry loop and surface
                # as a bare exception with no observable context —
                # making it hard to tell which observable caused the
                # failure or whether the upstream ``payload_bin``
                # field is itself the issue. Wrap with a contextual
                # ``ValueError`` and ``log_warning`` so the operator
                # can correlate the failure with the observable id
                # and the rest of the per-observable retry / fallback
                # path (``importFiles`` → ``x_opencti_files`` →
                # SHA-256 deferred lookup) still has a chance to
                # succeed instead of crashing on the first attempt.
                try:
                    file_content = base64.b64decode(
                        observable["payload_bin"], validate=False
                    )
                except (binascii.Error, ValueError) as exc:
                    observable_id = observable.get("id", "unknown")
                    self.helper.log_warning(
                        f"payload_bin for observable {observable_id} is not valid "
                        f"base64 ({type(exc).__name__}: {exc}); falling back to "
                        "importFiles / x_opencti_files"
                    )
                    file_content = None
                if file_content is not None:
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

        # No file content recovered — defer the AssemblyLine lookup to
        # :meth:`_process_file`. The previous shape called
        # ``_check_existing_analysis(sha256)`` here AND
        # ``_process_file`` then called it again on the
        # ``file_content is None`` branch — the same Lucene
        # ``files.sha256:<hash>`` query twice per cycle, doubling the
        # AssemblyLine API round-trip and the audit-log noise on every
        # hash-only Artifact reuse. Return ``(None, None, sha256)``
        # when a SHA-256 is available and let ``_process_file`` perform
        # the single lookup; raise here only when there is no SHA-256
        # to defer with.
        sha256 = self._select_sha256(observable.get("hashes", []))
        if sha256:
            self.helper.log_info(
                "No file content available, "
                f"deferring to AssemblyLine SHA-256 lookup in _process_file: {sha256}"
            )
            return None, None, sha256
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

        # Explicit ``is None`` checks (not truthiness) — a 0-byte file
        # payload (``b""``) is falsy in Python, so ``if not file_content``
        # would treat a successfully-downloaded empty file as "missing"
        # and either fall through to ``x_opencti_files`` for nothing
        # or skip the early return and trigger the SHA-256 fallback
        # path below as if no content had been fetched. The downstream
        # code already handles ``b""`` correctly (the file size is
        # tracked separately from content presence), so the right
        # signal here is "did the download succeed?" — i.e. did the
        # source return a ``bytes`` object at all, regardless of length.
        if file_content is None:
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

        if file_content is not None:
            return file_content, file_name, file_hash

        sha256 = self._select_sha256(hashes)
        if sha256:
            # Defer the AssemblyLine lookup to :meth:`_process_file`.
            # Same rationale as ``_get_artifact_content``: the previous
            # shape ran ``_check_existing_analysis(sha256)`` here AND
            # ``_process_file`` ran it again on the
            # ``file_content is None`` branch, paying for two
            # identical ``files.sha256:<hash>`` searches per cycle on
            # every hash-only StixFile reuse. Return ``(None, None,
            # sha256)`` and let ``_process_file`` perform the single
            # lookup.
            self.helper.log_info(
                "StixFile has no content, "
                f"deferring to AssemblyLine SHA-256 lookup in _process_file: {sha256}"
            )
            return None, None, sha256

        # ``file_hash`` falls back to ``observable.get("name")`` and then
        # to the literal ``"unknown"`` when the StixFile carries no
        # ``hashes`` at all (line 609). The previous "Only hash
        # available: …" wording therefore lied half the time — the
        # value rendered after the colon could be a plain filename or
        # the literal ``"unknown"`` string. Rephrase to make the
        # intent honest: this branch is reached when there is neither
        # a usable file payload nor a SHA-256 to look up, and we
        # surface whatever identifier we have so the operator can map
        # the failure back to the source observable.
        raise Exception(
            "StixFile has no accessible file content and no SHA-256 hash for "
            f"AssemblyLine lookup (identifier: {file_hash})"
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
            # Cap the sleep at the remaining deadline budget — the
            # ``while True`` guard only protects the *next* iteration,
            # so an unconditional ``sleep(poll_interval)`` could
            # overshoot ``ASSEMBLYLINE_TIMEOUT`` by up to one poll
            # interval on the boundary tick. Sleep at most as long as
            # the deadline allows, and break out immediately if no
            # budget remains so the caller's exception path
            # (already raised above when remaining <= 0) is the only
            # way out.
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Exception(
                    "[Sequential] Timed out waiting for AssemblyLine to become idle"
                )
            time.sleep(min(self.assemblyline_poll_interval, remaining))

    def _process_file(self, observable: Dict[str, Any]) -> Dict[str, Any]:
        """Submit (or reuse) an AssemblyLine analysis for an observable."""
        deadline = time.monotonic() + self.assemblyline_timeout

        self.helper.log_info(
            "Processing observable: "
            f"{observable.get('observable_value', observable.get('name', 'unknown'))}"
        )

        file_content, file_name, file_hash = self._get_file_content(observable)

        # ``_check_existing_analysis`` searches AssemblyLine submissions
        # by ``files.sha256:<hash>`` — passing an MD5 / SHA-1 there always
        # misses, generates noise in the AL audit log, and may even hit
        # an unrelated submission if the non-SHA-256 hash collides. Pick
        # the SHA-256 explicitly here and only attempt deduplication when
        # one is available; ``file_hash`` (first available hash, possibly
        # MD5 / SHA-1 / ``"unknown"``) is kept only for logging where it
        # is honestly labelled "hash" rather than "SHA-256".
        sha256_for_lookup = self._select_sha256(observable.get("hashes", []))

        if file_content is None:
            if sha256_for_lookup:
                self.helper.log_info(
                    f"Using existing AssemblyLine results for SHA-256: {sha256_for_lookup}"
                )
                existing_results = self._check_existing_analysis(sha256_for_lookup)
                if existing_results:
                    return existing_results
                raise Exception(
                    f"No file content and no existing analysis found for SHA-256: {sha256_for_lookup}"
                )
            raise Exception(
                f"No file content available and no SHA-256 hash to look up (hash: {file_hash})"
            )

        file_size_mb = len(file_content) / (1024 * 1024)
        if file_size_mb > self.assemblyline_max_file_size_mb:
            raise Exception(
                f"File size ({file_size_mb:.2f} MB) exceeds maximum limit "
                f"({self.assemblyline_max_file_size_mb} MB)"
            )

        self.helper.log_info(
            f"Processing file: {file_name} ({file_size_mb:.2f} MB, hash: {file_hash})"
        )

        if not self.assemblyline_force_resubmit and sha256_for_lookup:
            existing_results = self._check_existing_analysis(sha256_for_lookup)
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

        # Submission classification mirrors the source observable's TLP
        # so AssemblyLine never sees a marking lower than the file
        # actually carries in OpenCTI. Falls back to the configured
        # default when the source has no recognisable TLP marking.
        submission_classification = self._resolve_submission_classification(observable)
        self.helper.log_info(
            f"Submission classification: {submission_classification} "
            f"(source TLP: {self._source_tlp(observable)})"
        )
        # ``ignore_cache`` tells AssemblyLine itself to skip its own
        # result cache and re-run the full service chain. When the
        # operator sets ``ASSEMBLYLINE_FORCE_RESUBMIT=true``, the
        # connector's OpenCTI-side dedup lookup
        # (``_check_existing_analysis``) is already skipped above —
        # wire the same intent through to AssemblyLine so a forced
        # resubmit isn't silently served from AL's own cache one
        # layer deeper.
        json_data = {
            "name": file_name,
            "submission_profile": self.assemblyline_submission_profile,
            "metadata": {"submitter": "opencti-connector", "source": "OpenCTI"},
            "params": {
                "classification": submission_classification,
                "description": f'Submitted from OpenCTI - {observable["id"]}',
                "deep_scan": False,
                "priority": 1000,
                "ignore_cache": bool(self.assemblyline_force_resubmit),
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
                        raise AssemblyLineTerminalError(
                            f"AssemblyLine analysis failed for submission {submission_id}"
                        )
                    if state in ("error", "cancelled"):
                        raise AssemblyLineTerminalError(
                            f"AssemblyLine analysis {state} for submission {submission_id}"
                        )
                    self.helper.log_info(f"Analysis still running, state: {state}")
            except AssemblyLineTerminalError:
                # Terminal AssemblyLine states (failed / error / cancelled)
                # cannot recover by polling again — surface them to the
                # caller immediately instead of waiting until the global
                # timeout.
                raise
            except Exception as exc:
                if "does not exist" in str(exc).lower():
                    raise Exception(
                        f"Submission {submission_id} not found in AssemblyLine"
                    ) from exc
                self.helper.log_warning(f"Error checking submission status: {exc}")
            # Cap the sleep at the remaining time until ``deadline`` so the
            # polling loop never overshoots ``ASSEMBLYLINE_TIMEOUT`` by
            # nearly a full ``_POLL_SLEEP_SECONDS`` interval. ``while
            # time.monotonic() < deadline`` only guards the *next*
            # iteration; without this cap, the last sleep before the
            # ``deadline`` check could extend total wall-time well past
            # the configured timeout (which the README and config schema
            # both document as the maximum wait).
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(_POLL_SLEEP_SECONDS, remaining))

        raise Exception(
            f"Timeout waiting for AssemblyLine results after {self.assemblyline_timeout} seconds"
        )

    # ------------------------------------------------------------------ #
    # IOC / ATT&CK extraction                                            #
    # ------------------------------------------------------------------ #

    def _extract_iocs_by_classification(
        self,
        tags: Optional[Dict[str, Any]],
        classifications: Tuple[str, ...],
    ) -> Dict[str, List[str]]:
        """Return IOCs matching one of ``classifications`` (private).

        Used by :meth:`_extract_malicious_iocs` and
        :meth:`_extract_suspicious_iocs` so the two share the same
        de-duplication and category-routing logic. ``classifications``
        is a tuple of the AssemblyLine tag classifications to include
        (e.g. ``("malicious",)`` or ``("suspicious",)``).
        """
        bucket: Dict[str, List[str]] = {
            "domains": [],
            "ips": [],
            "urls": [],
            "families": [],
        }
        if not tags:
            return bucket

        classification_set = set(classifications)
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
                    if classification not in classification_set:
                        continue

                    lowered = tag_type.lower()
                    if "domain" in lowered:
                        if value not in bucket["domains"]:
                            bucket["domains"].append(value)
                    elif "ip" in lowered:
                        if value not in bucket["ips"]:
                            bucket["ips"].append(value)
                    elif "uri" in lowered or "url" in lowered:
                        if value not in bucket["urls"]:
                            bucket["urls"].append(value)

            if main_category == "attribution":
                for family_entry in category_data.get("attribution.family", []) or []:
                    if (
                        isinstance(family_entry, list)
                        and len(family_entry) >= 2
                        and family_entry[1] in classification_set
                        and family_entry[0] not in bucket["families"]
                    ):
                        bucket["families"].append(family_entry[0])

        return bucket

    def _extract_malicious_iocs(
        self, tags: Optional[Dict[str, Any]]
    ) -> Dict[str, List[str]]:
        """Return only the IOCs AssemblyLine tagged as ``malicious``.

        Suspicious-only IOCs are deliberately *not* mixed into this
        dict any more — they are returned separately by
        :meth:`_extract_suspicious_iocs` so the downstream "label the
        source observable malicious", "set ``x_opencti_score=80``" and
        "force ``malware-analysis.result=malicious``" paths only fire
        on truly-malicious IOCs. With ``ASSEMBLYLINE_INCLUDE_SUSPICIOUS``
        on, suspicious IOCs are still turned into indicators (see
        :meth:`_create_indicators`), just with a ``suspicious`` label
        and a lower score rather than being indistinguishable from
        malicious ones in OpenCTI.
        """
        malicious_iocs = self._extract_iocs_by_classification(tags, ("malicious",))
        self.helper.log_info(
            "Extracted malicious IOCs - "
            f"Domains: {len(malicious_iocs['domains'])}, "
            f"IPs: {len(malicious_iocs['ips'])}, "
            f"URLs: {len(malicious_iocs['urls'])}, "
            f"Families: {len(malicious_iocs['families'])}"
        )
        return malicious_iocs

    def _extract_suspicious_iocs(
        self, tags: Optional[Dict[str, Any]]
    ) -> Dict[str, List[str]]:
        """Return the IOCs AssemblyLine tagged as ``suspicious``.

        Returns an empty bucket when ``ASSEMBLYLINE_INCLUDE_SUSPICIOUS``
        is disabled so the caller can unconditionally iterate the
        result without an extra feature-flag branch.
        """
        if not self.assemblyline_include_suspicious:
            return {"domains": [], "ips": [], "urls": [], "families": []}
        suspicious_iocs = self._extract_iocs_by_classification(tags, ("suspicious",))
        self.helper.log_info(
            "Extracted suspicious IOCs - "
            f"Domains: {len(suspicious_iocs['domains'])}, "
            f"IPs: {len(suspicious_iocs['ips'])}, "
            f"URLs: {len(suspicious_iocs['urls'])}, "
            f"Families: {len(suspicious_iocs['families'])}"
        )
        return suspicious_iocs

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
        self,
        attack_patterns: List[Dict[str, str]],
        source_marking_refs: Optional[List[str]] = None,
    ) -> List[str]:
        """Create / lookup ATT&CK Attack-Pattern SDOs in OpenCTI.

        ``source_marking_refs`` is the list of marking ids derived
        from the enriched observable (via :meth:`_source_marking_refs`).
        It is applied to newly-created Attack-Pattern SDOs so a
        TLP:AMBER source does not produce unmarked / TLP:CLEAR
        Attack-Patterns visible to a broader audience than the
        observable that triggered the analysis. Existing Attack-
        Patterns picked up via the fallback list query are
        intentionally left untouched: they may already carry
        markings from previous enrichments and the connector
        should not silently downgrade or overwrite those.
        """
        created_patterns: List[str] = []
        if not attack_patterns:
            return created_patterns

        for pattern in attack_patterns:
            try:
                attack_pattern_data: Dict[str, Any] = {
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
                if source_marking_refs:
                    attack_pattern_data["objectMarking"] = source_marking_refs
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

    # IP literals that AssemblyLine routinely reports as observed during
    # sandbox detonation but that are never meaningful indicators in
    # OpenCTI: loopback (``127.0.0.1``, ``::1``) and the IPv4
    # unspecified / "any" address (``0.0.0.0``). The Malware-Analysis
    # bundle SCO path already skips these — extract the list as a
    # module-level constant so the indicator/observable creation path
    # below applies the same filter and a future contributor adding
    # another sandbox-internal address has a single site to update.
    _SKIP_IP_LITERALS = frozenset({"127.0.0.1", "::1", "0.0.0.0"})

    @classmethod
    def _is_skippable_ip(cls, value: str) -> bool:
        """Return ``True`` for IPs we never want to materialise as
        indicators / observables (loopback, unspecified).
        """
        return value in cls._SKIP_IP_LITERALS

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
        """Parse an AssemblyLine timestamp string (best effort).

        Uses :func:`datetime.fromisoformat` after normalising the ``Z``
        suffix so we correctly handle every ISO-8601 offset shape
        AssemblyLine produces, including negative offsets like
        ``-04:00`` (the earlier split-on-``+`` approach dropped the
        timezone entirely for ``+`` offsets and would mis-parse
        negative offsets). The result is normalised to a naive UTC
        datetime so the rest of the connector keeps using a single
        timezone-naive representation across STIX SDO ``created`` /
        ``modified`` fields (matching the pre-existing call sites).
        """
        if not isinstance(value, str):
            return fallback
        normalized = value.strip()
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError:
            return fallback
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed

    def _create_malware_analysis(
        self,
        observable_id: str,
        observable: Dict[str, Any],
        results: Dict[str, Any],
        malicious_iocs: Dict[str, List[str]],
    ) -> Optional[str]:
        """Emit a Malware-Analysis SDO + analysis_sco_refs bundle."""
        try:
            # ``max_score`` is fed straight into the numeric
            # comparisons in ``_score_to_result_name``. AssemblyLine
            # has been seen returning ``null`` (when no sub-service
            # produced a score, e.g. a benign upload that was
            # short-circuited) and the field is not strictly typed in
            # the ``v4_client`` response shape, so a future server-
            # side change could surface a string too. Normalising via
            # ``int(... or 0)`` mirrors ``_process_message`` and
            # ``_create_summary_note`` (the other two call sites that
            # read this field) so the Malware-Analysis emission can
            # never crash with ``TypeError`` and silently drop the
            # whole bundle on a benign-but-score-less submission.
            max_score = int(results.get("max_score", 0) or 0)
            sid = results.get("sid", "unknown")
            times = results.get("times", {}) or {}

            result_value = self._score_to_result_name(max_score)
            # ``malicious_iocs`` carries four buckets: ``domains`` /
            # ``ips`` / ``urls`` AND ``families`` (the malware-family
            # attributions). The variable name reflects the broader
            # "AssemblyLine emitted at least one malicious tag" signal
            # so a future refactor cannot accidentally treat a
            # family-only attribution as "no malicious evidence" and
            # downgrade the result to a non-malicious verdict — a
            # confirmed malware-family attribution from AssemblyLine
            # is a strong enough signal on its own to force the
            # ``malicious`` result.
            #
            # The upgrade fires whenever ``has_malicious_evidence`` is
            # true and the score-bucket result is not already
            # ``malicious`` — including the ``suspicious`` bucket. A
            # score in [100, 500) plus a ``malicious``-tagged IOC (or
            # family attribution) means the rest of the connector
            # already labels the source observable ``malicious``,
            # bumps ``x_opencti_score`` to 80, and emits a Note with
            # ``Verdict: MALICIOUS`` (see ``_process_file`` /
            # ``_create_summary_note``). Leaving the Malware-Analysis
            # SDO's ``result`` at ``suspicious`` in that case made the
            # SDO disagree with everything else the enrichment
            # produced — the OpenCTI UI then showed contradictory
            # signals on the same observable.
            has_malicious_evidence = any(malicious_iocs.values())
            if has_malicious_evidence and result_value != "malicious":
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
            # Derived analysis SCOs inherit the source observable's
            # markings so a TLP:AMBER file cannot produce TLP:WHITE
            # analysis objects in OpenCTI — see ``_source_marking_refs``.
            source_marking_refs = self._source_marking_refs(observable)

            # OpenCTI's observable/SCO authoring convention is the
            # ``x_opencti_created_by_ref`` custom property, not the
            # standard STIX ``created_by_ref`` (which is reserved for
            # SDOs/SROs). Setting the standard field on a SCO would
            # silently leave the platform's author column unset.
            # ``self.assemblyline_identity_standard_id`` is ``None`` when
            # the upfront identity lookup / creation failed (see
            # ``_get_assemblyline_identity``) — omit the key entirely in
            # that case so the SCOs serialise without a ``null`` author
            # (some stix2 validators reject the explicit-``null`` form
            # and OpenCTI ingest would otherwise drop the property).
            sco_author_properties: Dict[str, Any] = {}
            if self.assemblyline_identity_standard_id:
                sco_author_properties["x_opencti_created_by_ref"] = (
                    self.assemblyline_identity_standard_id
                )

            for domain in malicious_iocs.get("domains", []):
                try:
                    domain_stix = stix2.DomainName(
                        value=domain,
                        object_marking_refs=source_marking_refs,
                        custom_properties=sco_author_properties,
                    )
                    stix_objects.append(domain_stix)
                    analysis_sco_refs.append(domain_stix.id)
                except Exception as exc:
                    self.helper.log_warning(
                        f"Could not create STIX domain {domain}: {exc}"
                    )

            for ip in malicious_iocs.get("ips", []):
                try:
                    if self._is_skippable_ip(ip):
                        continue
                    if self._is_ipv6(ip):
                        ip_stix = stix2.IPv6Address(
                            value=ip,
                            object_marking_refs=source_marking_refs,
                            custom_properties=sco_author_properties,
                        )
                    else:
                        ip_stix = stix2.IPv4Address(
                            value=ip,
                            object_marking_refs=source_marking_refs,
                            custom_properties=sco_author_properties,
                        )
                    stix_objects.append(ip_stix)
                    analysis_sco_refs.append(ip_stix.id)
                except Exception as exc:
                    self.helper.log_warning(f"Could not create STIX IP {ip}: {exc}")

            for url in malicious_iocs.get("urls", []):
                try:
                    url_stix = stix2.URL(
                        value=url,
                        object_marking_refs=source_marking_refs,
                        custom_properties=sco_author_properties,
                    )
                    stix_objects.append(url_stix)
                    analysis_sco_refs.append(url_stix.id)
                except Exception as exc:
                    self.helper.log_warning(f"Could not create STIX URL {url}: {exc}")

            # ``self.assemblyline_identity_standard_id`` is ``None`` when
            # the upfront identity lookup / creation failed (see
            # ``_get_assemblyline_identity``). ``stix2.MalwareAnalysis``
            # validates ``created_by_ref`` as an ``identifier-type``
            # string and raises ``InvalidValueError`` on ``None``, which
            # would short-circuit the bundle and skip emitting the
            # Malware-Analysis altogether. Omit the field entirely when
            # the identity is unavailable so the rest of the enrichment
            # still lands in OpenCTI. ``id=`` is kept as an explicit
            # keyword (not unpacked through ``**``) so the repo's
            # ``no_generated_id_stix`` pylint plugin can statically see
            # the deterministic id and not fire its W9101 false positive.
            optional_malware_analysis_kwargs: Dict[str, Any] = {}
            if self.assemblyline_identity_standard_id:
                optional_malware_analysis_kwargs["created_by_ref"] = (
                    self.assemblyline_identity_standard_id
                )
            malware_analysis = stix2.MalwareAnalysis(
                id=malware_analysis_id,
                product="AssemblyLine",
                result_name=result_name,
                result=result_value,
                analysis_started=analysis_started,
                analysis_ended=analysis_ended,
                submitted=analysis_started,
                sample_ref=stix_entity_id,
                analysis_sco_refs=analysis_sco_refs or None,
                external_references=[external_reference],
                object_marking_refs=source_marking_refs,
                **optional_malware_analysis_kwargs,
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

    # AssemblyLine IOC classifications map to distinct OpenCTI scores and
    # labels: malicious IOCs are emitted as ``malicious`` indicators with
    # the standard high-confidence score (80), while suspicious IOCs are
    # emitted as ``suspicious`` indicators with a moderate score (50).
    # Keeping this mapping in one place means downstream consumers in
    # OpenCTI see honest classification labels matching what AssemblyLine
    # actually returned, instead of suspicious IOCs being indistinguishable
    # from malicious ones.
    _IOC_CLASSIFICATION_SCORES: Dict[str, int] = {
        "malicious": 80,
        "suspicious": 50,
    }

    def _create_indicator_observable(
        self,
        observable_id: str,
        ioc_value: str,
        stix_observable_type: str,
        opencti_observable_type: str,
        max_score: int,
        description: str,
        source_marking_refs: Optional[List[str]] = None,
        classification: str = "malicious",
    ) -> Tuple[Optional[str], bool]:
        """Create one Indicator (+ optional matching Observable) for an IOC.

        ``source_marking_refs`` is the list of marking ids that should
        be applied to the Indicator and (if enabled) the matching
        Observable. The caller derives it from the enriched
        observable's ``objectMarking`` so derived OpenCTI objects
        cannot be exposed more broadly than the source — a TLP:AMBER
        file produces TLP:AMBER indicators and observables.

        ``classification`` is the AssemblyLine IOC classification
        (``"malicious"`` or ``"suspicious"``). It drives the label
        applied to the Indicator / Observable and its
        ``x_opencti_score`` — suspicious-only IOCs no longer end up
        labelled ``malicious`` with the high-confidence score (was
        the previous behaviour when ``ASSEMBLYLINE_INCLUDE_SUSPICIOUS``
        was on).

        Returns a ``(indicator_id, observable_created)`` tuple. The
        ``observable_created`` flag is ``True`` when the matching
        Observable AND its ``based-on`` relationship were created
        successfully; the caller increments the observable / extra
        relationship counters off this flag only — without it the
        summary Note used to over-report observables every time the
        nested observable-creation block swallowed an exception.
        """
        observable_created = False
        try:
            indicator_score = self._IOC_CLASSIFICATION_SCORES.get(classification, 80)
            escaped = self._escape_stix_string(ioc_value)
            indicator_data: Dict[str, Any] = {
                "name": ioc_value,
                "description": (f"{description} (AssemblyLine score: {max_score})"),
                "pattern": f"[{stix_observable_type}:value = '{escaped}']",
                "pattern_type": "stix",
                "x_opencti_main_observable_type": opencti_observable_type,
                "valid_from": self.helper.api.stix2.format_date(),
                "labels": [classification, "assemblyline"],
                "x_opencti_score": indicator_score,
            }
            if self.assemblyline_author:
                indicator_data["createdBy"] = self.assemblyline_author
            if source_marking_refs:
                indicator_data["objectMarking"] = source_marking_refs
            indicator = self.helper.api.indicator.create(**indicator_data)
            # ``source_marking_refs`` is propagated onto the
            # ``related-to`` SRO so the source-observable → Indicator
            # edge stays inside the same access-control bucket as its
            # endpoints. Without this, a TLP:AMBER source observable
            # carrying a TLP:AMBER Indicator endpoint would be linked
            # by an unmarked SRO that OpenCTI exposes more broadly
            # than either endpoint — a marking-propagation gap that
            # the rest of the connector explicitly closes for every
            # other SDO/SCO/SRO it emits.
            related_to_data: Dict[str, Any] = {
                "fromId": observable_id,
                "toId": indicator["id"],
                "relationship_type": "related-to",
                "description": description,
            }
            if source_marking_refs:
                related_to_data["objectMarking"] = source_marking_refs
            self.helper.api.stix_core_relationship.create(**related_to_data)
            if self.assemblyline_create_observables:
                try:
                    obs_data: Dict[str, Any] = {
                        "observableData": {
                            "type": stix_observable_type,
                            "value": ioc_value,
                        },
                        "x_opencti_score": indicator_score,
                    }
                    if self.assemblyline_author:
                        obs_data["createdBy"] = self.assemblyline_author
                    if source_marking_refs:
                        obs_data["objectMarking"] = source_marking_refs
                    new_observable = self.helper.api.stix_cyber_observable.create(
                        **obs_data
                    )
                    self.helper.api.stix_cyber_observable.add_label(
                        id=new_observable["id"], label=classification
                    )
                    # Same rationale as the ``related-to`` edge above:
                    # the Indicator → Observable ``based-on`` SRO must
                    # carry the source markings so the whole derived
                    # sub-graph (Indicator + Observable + the two SROs
                    # that wire them up) lands in OpenCTI with one
                    # consistent marking shape.
                    based_on_data: Dict[str, Any] = {
                        "fromId": indicator["id"],
                        "toId": new_observable["id"],
                        "relationship_type": "based-on",
                        "description": (
                            f"Indicator based on observed {classification} IOC "
                            "from AssemblyLine analysis"
                        ),
                    }
                    if source_marking_refs:
                        based_on_data["objectMarking"] = source_marking_refs
                    self.helper.api.stix_core_relationship.create(**based_on_data)
                    observable_created = True
                except Exception as obs_exc:
                    self.helper.log_warning(
                        f"Could not create observable for IOC {ioc_value}: {obs_exc}"
                    )
            return indicator["id"], observable_created
        except Exception as exc:
            self.helper.log_warning(
                f"Could not create indicator for IOC {ioc_value}: {exc}"
            )
            return None, False

    def _create_indicators(
        self,
        observable: Dict[str, Any],
        max_score: int,
        malicious_iocs: Dict[str, List[str]],
        suspicious_iocs: Optional[Dict[str, List[str]]] = None,
    ) -> Tuple[Dict[str, int], List[str]]:
        """Create indicators (and optional observables) for every IOC.

        ``malicious_iocs`` and ``suspicious_iocs`` are processed in
        sequence so each indicator is created with a label and score
        matching its AssemblyLine classification — ``malicious`` IOCs
        get the ``malicious`` label and the high-confidence score
        (80); ``suspicious`` IOCs (only emitted when
        ``ASSEMBLYLINE_INCLUDE_SUSPICIOUS=true``) get the
        ``suspicious`` label and a moderate score (50).

        Returns ``(counts, indicator_ids)`` where ``indicator_ids`` is
        the list of *all* created Indicator standard ids (malicious +
        suspicious), used downstream to link MITRE ATT&CK techniques
        to them with ``related-to``.

        The full source observable is taken (rather than only its id)
        so each derived Indicator / Observable can inherit the source
        markings via ``_source_marking_refs``. Without this, a
        TLP:AMBER file would produce indicators/observables that
        OpenCTI exposes more broadly than the source SCO.
        """
        observable_id = observable["id"]
        source_marking_refs = self._source_marking_refs(observable)
        # ``malicious_indicators`` / ``suspicious_indicators`` track the
        # per-classification indicator counts so the summary Note and
        # the run's success-message can report ``N malicious indicators``
        # vs ``N suspicious indicators`` without conflating the two —
        # the previous shape lumped them under a single ``indicators``
        # key, which the success message then mixed with the
        # ``families`` extraction bucket (Malware SDOs, not indicators)
        # and over-reported the count.
        #
        # The per-category ``{classification}_{kind}`` counters
        # (``malicious_domains`` / ``malicious_ips`` / ``malicious_urls`` /
        # ``suspicious_domains`` / ``suspicious_ips`` / ``suspicious_urls``)
        # track how many indicators were *actually created* for each
        # bucket, distinct from the IOC-extraction bucket sizes (the
        # ``len(malicious_iocs['domains'])`` etc. used to flow straight
        # into the Note even though ``_process_bucket`` caps creation
        # at 20 per category, so the Note over-reported what ended up
        # in OpenCTI on large analyses).
        counts: Dict[str, int] = {
            "indicators": 0,
            "malicious_indicators": 0,
            "suspicious_indicators": 0,
            "malicious_domains": 0,
            "malicious_ips": 0,
            "malicious_urls": 0,
            "suspicious_domains": 0,
            "suspicious_ips": 0,
            "suspicious_urls": 0,
            "observables": 0,
            "relationships": 0,
            "malware_families": 0,
        }
        indicator_ids: List[str] = []

        def _process_bucket(bucket: Dict[str, List[str]], classification: str) -> None:
            for domain in bucket["domains"][:20]:
                ind_id, obs_created = self._create_indicator_observable(
                    observable_id,
                    domain,
                    "domain-name",
                    "Domain-Name",
                    max_score,
                    "Domain contacted during malware analysis",
                    source_marking_refs=source_marking_refs,
                    classification=classification,
                )
                if ind_id:
                    indicator_ids.append(ind_id)
                    counts["indicators"] += 1
                    counts[f"{classification}_indicators"] += 1
                    counts[f"{classification}_domains"] += 1
                    counts["relationships"] += 1
                    if obs_created:
                        counts["observables"] += 1
                        counts["relationships"] += 1

            for ip in bucket["ips"][:20]:
                # Mirror the SCO-bundle path's skip list so loopback /
                # unspecified addresses AssemblyLine reports as
                # "contacted during detonation" (often sandbox-internal
                # noise) are not materialised as OpenCTI indicators.
                # The pre-fix shape produced indicators for ``127.0.0.1``,
                # ``::1`` and ``0.0.0.0`` whenever they showed up in the
                # IOC bucket, polluting the indicator index.
                if self._is_skippable_ip(ip):
                    continue
                stix_type = "ipv6-addr" if self._is_ipv6(ip) else "ipv4-addr"
                octi_type = "IPv6-Addr" if self._is_ipv6(ip) else "IPv4-Addr"
                ind_id, obs_created = self._create_indicator_observable(
                    observable_id,
                    ip,
                    stix_type,
                    octi_type,
                    max_score,
                    "IP address contacted during malware analysis",
                    source_marking_refs=source_marking_refs,
                    classification=classification,
                )
                if ind_id:
                    indicator_ids.append(ind_id)
                    counts["indicators"] += 1
                    counts[f"{classification}_indicators"] += 1
                    counts[f"{classification}_ips"] += 1
                    counts["relationships"] += 1
                    if obs_created:
                        counts["observables"] += 1
                        counts["relationships"] += 1

            for url in bucket["urls"][:20]:
                ind_id, obs_created = self._create_indicator_observable(
                    observable_id,
                    url,
                    "url",
                    "Url",
                    max_score,
                    "URL contacted during malware analysis",
                    source_marking_refs=source_marking_refs,
                    classification=classification,
                )
                if ind_id:
                    indicator_ids.append(ind_id)
                    counts["indicators"] += 1
                    counts[f"{classification}_indicators"] += 1
                    counts[f"{classification}_urls"] += 1
                    counts["relationships"] += 1
                    if obs_created:
                        counts["observables"] += 1
                        counts["relationships"] += 1

        _process_bucket(malicious_iocs, "malicious")
        if suspicious_iocs is not None:
            _process_bucket(suspicious_iocs, "suspicious")

        # Malware families flagged by AssemblyLine are emitted as
        # ``Malware`` SDOs (NOT as STIX Indicators), so they are
        # counted into ``malware_families`` rather than
        # ``malicious_indicators`` — the summary Note and the run's
        # success-message report the two separately so an analyst can
        # tell at a glance how many indicators vs how many malware
        # SDOs the enrichment produced.
        for family in malicious_iocs["families"][:10]:
            try:
                # Malware family SDOs derived from a marked source must
                # inherit the same ``objectMarking`` as the enriched
                # observable so a TLP:AMBER file does not produce a
                # TLP:CLEAR (or unmarked) Malware SDO that OpenCTI
                # exposes more broadly than the source. The
                # ``related-to`` relationship is also marked so the
                # whole derived sub-graph stays in the same access-
                # control bucket as the source.
                malware_data: Dict[str, Any] = {
                    "name": family,
                    "description": "Malware family identified by AssemblyLine analysis",
                    "is_family": True,
                }
                if self.assemblyline_author:
                    malware_data["createdBy"] = self.assemblyline_author
                if source_marking_refs:
                    malware_data["objectMarking"] = source_marking_refs
                malware = self.helper.api.malware.create(**malware_data)
                relationship_data: Dict[str, Any] = {
                    "fromId": observable_id,
                    "toId": malware["id"],
                    "relationship_type": "related-to",
                    "description": f"File attributed to {family} by AssemblyLine",
                }
                if source_marking_refs:
                    relationship_data["objectMarking"] = source_marking_refs
                self.helper.api.stix_core_relationship.create(**relationship_data)
                counts["malware_families"] += 1
                counts["relationships"] += 1
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

        # Reset the file-size cache that ``_download_import_file`` /
        # ``_fetch_attached_file`` populate. The connector instance is
        # reused across enrichment messages, so a stale value from the
        # previous observable would otherwise leak into the current
        # summary note (``_create_summary_note`` falls back to
        # ``self._current_file_size`` when the observable + AL
        # ``file_info`` don't carry a size).
        self._current_file_size = None

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
            suspicious_iocs = self._extract_suspicious_iocs(tags)
            # ``has_malicious_evidence`` is intentionally scoped to the
            # truly-malicious bucket — the "label source observable as
            # malicious", "set ``x_opencti_score=80``" and
            # "force ``malware-analysis.result=malicious``" paths must
            # not fire on suspicious-only analyses (those get their
            # own ``suspicious`` indicators with a moderate score
            # below). The bucket carries domains / ips / urls AND
            # families (the malware-family attributions) — the name
            # uses the broader "evidence" wording rather than "iocs"
            # so a future contributor cannot mistake the flag for
            # "IOCs only" and accidentally drop the
            # family-attribution path on the floor.
            has_malicious_evidence = any(malicious_iocs.values())
            has_suspicious_iocs = any(suspicious_iocs.values())
            is_malicious = max_score >= 500 or has_malicious_evidence

            if is_malicious:
                try:
                    self.helper.api.stix_cyber_observable.add_label(
                        id=observable["id"], label="malicious"
                    )
                except Exception as exc:
                    self.helper.log_warning(f"Could not add malicious label: {exc}")
            elif has_suspicious_iocs:
                # Surface "suspicious-only" verdicts honestly in the
                # OpenCTI UI rather than leaving the source observable
                # unlabelled (and indistinguishable from a benign one).
                try:
                    self.helper.api.stix_cyber_observable.add_label(
                        id=observable["id"], label="suspicious"
                    )
                except Exception as exc:
                    self.helper.log_warning(f"Could not add suspicious label: {exc}")

            try:
                # Align ``x_opencti_score`` with the verdict bucket that
                # drives the rest of the enrichment (labels, indicators,
                # malware-analysis result) rather than mapping the raw
                # AssemblyLine score linearly. A "suspicious" AL score of
                # 120 used to land on ``x_opencti_score=6`` even though
                # the indicator emission path applies 50, and a 500-score
                # malicious sample used to land on 25 even though the
                # indicators are emitted with 80 — the OpenCTI UI badges
                # are tied to score buckets, so the mismatch was very
                # visible in practice. Bucket the observable's score by
                # the same rule the indicators use:
                #   * truly malicious (max_score >= 500 OR any malicious
                #     IOC tag) -> 80
                #   * suspicious (max_score >= 100 OR any suspicious IOC
                #     tag, after the malicious branch ruled it out) -> 50
                #   * everything else -> 0
                if is_malicious:
                    opencti_score = 80
                elif has_suspicious_iocs or max_score >= 100:
                    opencti_score = 50
                else:
                    opencti_score = 0
                self.helper.api.stix_cyber_observable.update_field(
                    id=observable["id"],
                    input={"key": "x_opencti_score", "value": str(opencti_score)},
                )
            except Exception as exc:
                self.helper.log_warning(f"Could not update score: {exc}")

            counts, indicator_ids = self._create_indicators(
                observable,
                max_score,
                malicious_iocs,
                suspicious_iocs=suspicious_iocs,
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
                    # Reuse the same marking refs the indicators /
                    # malware-analysis bundle / summary Note inherit
                    # so the whole derived sub-graph stays within the
                    # source observable's access-control bucket. A
                    # TLP:AMBER file thus produces TLP:AMBER Attack-
                    # Pattern SDOs and TLP:AMBER ``related-to``
                    # relationships, never silently downgraded.
                    attack_pattern_marking_refs = self._source_marking_refs(observable)
                    created_attack_patterns = self._create_attack_patterns(
                        attack_patterns,
                        source_marking_refs=attack_pattern_marking_refs,
                    )
                    attack_patterns_count = len(created_attack_patterns)
                    for indicator_id in indicator_ids:
                        for pattern_id in created_attack_patterns:
                            try:
                                relationship_data: Dict[str, Any] = {
                                    "fromId": indicator_id,
                                    "toId": pattern_id,
                                    "relationship_type": "related-to",
                                    "description": (
                                        "Indicator related to ATT&CK technique "
                                        "observed during AssemblyLine analysis"
                                    ),
                                }
                                if attack_pattern_marking_refs:
                                    relationship_data["objectMarking"] = (
                                        attack_pattern_marking_refs
                                    )
                                self.helper.api.stix_core_relationship.create(
                                    **relationship_data
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
                suspicious_iocs=suspicious_iocs,
            )

            # Return a success message that reflects what was actually
            # created — drive the numbers off ``counts`` (the indicator
            # creation path's own bookkeeping), not the raw IOC
            # extraction buckets. The previous shape summed
            # ``malicious_iocs.values()`` / ``suspicious_iocs.values()``
            # which included the ``families`` bucket — but families
            # are emitted as ``Malware`` SDOs, not ``Indicator`` SDOs,
            # so the message ended up over-reporting "indicators
            # created" by the number of malware families. Use the
            # per-classification indicator counters that
            # ``_create_indicators`` increments only on a successful
            # ``indicator.create``.
            malicious_indicators = counts.get("malicious_indicators", 0)
            suspicious_indicators = counts.get("suspicious_indicators", 0)
            malware_families = counts.get("malware_families", 0)
            family_suffix = (
                f" and {malware_families} malware families" if malware_families else ""
            )
            if malicious_indicators and suspicious_indicators:
                return (
                    "File successfully analyzed by AssemblyLine "
                    f"({malicious_indicators} malicious + "
                    f"{suspicious_indicators} suspicious indicators"
                    f"{family_suffix} created)"
                )
            if malicious_indicators:
                return (
                    "File successfully analyzed by AssemblyLine "
                    f"({malicious_indicators} malicious indicators"
                    f"{family_suffix} created)"
                )
            if suspicious_indicators:
                return (
                    "File successfully analyzed by AssemblyLine "
                    f"({suspicious_indicators} suspicious indicators"
                    f"{family_suffix} created)"
                )
            if malware_families:
                return (
                    "File successfully analyzed by AssemblyLine "
                    f"({malware_families} malware families created, "
                    "no IOC indicators)"
                )
            return "File successfully analyzed by AssemblyLine (no IOCs extracted)"
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
        suspicious_iocs: Optional[Dict[str, List[str]]] = None,
    ) -> None:
        max_score = int(results.get("max_score", 0) or 0)
        sid = results.get("sid", "N/A")
        file_info = results.get("file_info", {}) or {}
        if not file_info and "api_response" in results:
            file_info = results["api_response"].get("file_info", {}) or {}

        file_sha256 = file_info.get("sha256") or "N/A"
        file_type = file_info.get("type") or "N/A"
        # ``file_size`` distinguishes "absent" from "explicitly 0
        # bytes" via ``is not None``. A legitimate empty file (an
        # AssemblyLine submission of a zero-byte sample, a 0-length
        # archive entry surfaced by an upstream extractor, etc.)
        # would otherwise have its size rendered as ``N/A`` in the
        # summary Note by the previous ``or "N/A"`` truthiness check,
        # hiding the real datum from analysts reading the Note.
        raw_file_size = file_info.get("size")
        file_size: Any = raw_file_size if raw_file_size is not None else "N/A"

        if file_sha256 == "N/A":
            for hash_entry in observable.get("hashes", []) or []:
                if (
                    isinstance(hash_entry, dict)
                    and hash_entry.get("algorithm") == "SHA-256"
                ):
                    file_sha256 = hash_entry.get("hash") or "N/A"
                    break

        if file_size == "N/A":
            # Fallback resolution: prefer the SCO's own metadata
            # before reaching for the per-fetch cache. Each step is
            # gated on ``is not None`` (not truthiness) for the same
            # reason as the ``file_info.get("size")`` branch above —
            # a zero-byte payload is a valid datum and must not be
            # silently dropped into ``N/A``.
            if observable.get("payload_bin"):
                try:
                    file_size = len(base64.b64decode(observable["payload_bin"]))
                except Exception:
                    pass
            elif observable.get("size") is not None:
                file_size = observable.get("size")
            elif observable.get("x_opencti_size") is not None:
                file_size = observable.get("x_opencti_size")
            elif getattr(self, "_current_file_size", None) is not None:
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

        # Derive the verdict from the same buckets the rest of the
        # enrichment uses, so the note never reports ``SAFE`` for an
        # observable that the connector simultaneously labels
        # ``suspicious`` / emits suspicious indicators for. The previous
        # ``MALICIOUS`` / ``SAFE`` binary collapsed every non-malicious
        # bucket — including the suspicious one — into ``SAFE``.
        # See ``_process_file`` for the rationale behind the
        # ``has_malicious_evidence`` naming — the bucket carries
        # ``families`` alongside the IOC categories so a name like
        # ``has_malicious_iocs`` would understate what the flag
        # actually represents.
        has_malicious_evidence = any(malicious_iocs.values())
        has_suspicious_iocs = any((suspicious_iocs or {}).values())
        if max_score >= 500 or has_malicious_evidence:
            verdict = "MALICIOUS"
        elif max_score >= 100 or has_suspicious_iocs:
            verdict = "SUSPICIOUS"
        elif max_score > 0:
            verdict = "UNKNOWN"
        else:
            verdict = "SAFE"
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

        # When ``ASSEMBLYLINE_INCLUDE_SUSPICIOUS=true`` the rest of the
        # enrichment emits a separate batch of ``suspicious``-labelled
        # indicators (and may even flip the verdict to ``SUSPICIOUS``)
        # — surface that batch in the Note as well so the user-facing
        # summary cannot contradict what the connector actually sent.
        # The block is rendered only when there is at least one
        # suspicious IOC, so the malicious-only path keeps its
        # original short format. The block reports *only* the IOC
        # buckets that are actually emitted as ``Indicator`` SDOs
        # (domains / IPs / URLs) — the ``families`` bucket of the
        # suspicious tags is intentionally NOT rendered here because
        # the connector only creates ``Malware`` SDOs from the
        # *malicious* families bucket (``_create_indicators``), and
        # mentioning it under an "Indicators" header would imply
        # those were created as indicators.
        #
        # The per-category counts come from ``counts`` (populated by
        # ``_create_indicators``) rather than ``len(suspicious_iocs[...])``
        # so the Note reports what was *actually created in OpenCTI*,
        # not what was *extracted from AssemblyLine* —
        # ``_create_indicators`` caps creation at 20 indicators per
        # bucket, so on large analyses ``len(...)`` would over-state
        # the count and contradict the run's success-message.
        suspicious_block = ""
        if has_suspicious_iocs:
            suspicious_block = (
                "\n## Suspicious IOCs Created as Indicators\n"
                f"- **Suspicious Domains:** {counts.get('suspicious_domains', 0)}\n"
                f"- **Suspicious IP Addresses:** {counts.get('suspicious_ips', 0)}\n"
                f"- **Suspicious URLs:** {counts.get('suspicious_urls', 0)}\n"
            )

        # ``Malware Families`` is its own section because the family
        # entries are emitted as ``Malware`` SDOs, *not* STIX
        # ``Indicator`` SDOs — putting their count under the
        # "Created as Indicators" header is misleading and was the
        # subject of two separate review threads. The section is
        # rendered only when ``_create_indicators`` actually produced
        # at least one Malware SDO so the malicious-IOCs-only path
        # keeps its short format.
        malware_families_count = (counts or {}).get("malware_families", 0)
        malware_families_block = ""
        if malware_families_count:
            malware_families_block = (
                "\n## Malware Families\n"
                f"- **Malware Families Created:** {malware_families_count} "
                "(emitted as Malware SDOs, related to the source observable)\n"
            )

        # ``Malicious IOCs Created as Indicators`` reports the per-
        # category indicator counts from ``counts`` (populated by
        # ``_create_indicators``) rather than ``len(malicious_iocs[...])``
        # so the Note matches what was actually written to OpenCTI:
        # ``_create_indicators`` caps creation at 20 per category, so
        # on large analyses ``len(...)`` over-stated the counts and
        # contradicted the run's success-message ("Created N malicious
        # indicators") and the per-category numbers reported by the
        # ``Observables Created`` line.
        malicious_domains_created = counts.get("malicious_domains", 0)
        malicious_ips_created = counts.get("malicious_ips", 0)
        malicious_urls_created = counts.get("malicious_urls", 0)
        note_content = f"""# AssemblyLine Analysis Results

**Verdict:** {verdict}
**Score:** {max_score}/2000
**Submission ID:** {sid}{malware_analysis_note}

## Malicious IOCs Created as Indicators
- **Malicious Domains:** {malicious_domains_created}
- **Malicious IP Addresses:** {malicious_ips_created}
- **Malicious URLs:** {malicious_urls_created}{observables_note}
{suspicious_block}{malware_families_block}
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
            "objectMarking": self._source_marking_refs(observable),
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
