"""IPQS enrichment module."""

import datetime as _dt
from os import path
from pathlib import Path
from typing import Any, Dict, List, Optional

import pycti
import stix2
from pycti import MarkingDefinition as PyctiMarkingDefinition
from pycti import Note as PyctiNote
from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2 import Identity
from yaml import FullLoader, load

from .builder import IPQSBuilder
from .client import IPQSClient
from .constants import (
    EMAIL_ENRICH,
    IP_ENRICH,
    LEAK_PASSWORD,
    LEAK_USERNAME_OR_EMAIL,
    PHONE_ENRICH,
    SOURCE_NAME,
    URL_ENRICH,
    to_bool,
)


def _stix_quote(value: str) -> str:
    """Escape a value for inclusion in a single-quoted STIX pattern literal."""
    return (value or "").replace("\\", "\\\\").replace("'", "\\'")


_DEFAULT_FILE_SCORE = 50
_MALICIOUS_FILE_SCORE = 100
_DEFAULT_IPQS_BASE_URL = "https://ipqualityscore.com/api/json"


def _make_tlp_marking(definition: str) -> stix2.MarkingDefinition:
    """Return a stix2.MarkingDefinition for an OpenCTI-specific TLP value."""
    return stix2.MarkingDefinition(
        id=PyctiMarkingDefinition.generate_id("TLP", definition),
        definition_type="statement",
        definition={"statement": "custom"},
        allow_custom=True,
        x_opencti_definition_type="TLP",
        x_opencti_definition=definition,
    )


_TLP_MAP: Dict[str, stix2.MarkingDefinition] = {
    "TLP:CLEAR": _make_tlp_marking("TLP:CLEAR"),
    "TLP:WHITE": stix2.TLP_WHITE,
    "TLP:GREEN": stix2.TLP_GREEN,
    "TLP:AMBER": stix2.TLP_AMBER,
    "TLP:AMBER+STRICT": _make_tlp_marking("TLP:AMBER+STRICT"),
    "TLP:RED": stix2.TLP_RED,
}

_MARKING_ID_TO_TLP: Dict[str, str] = {
    marking.id: tlp_string for tlp_string, marking in _TLP_MAP.items()
}


def _normalize_tlp(value: Optional[str], fallback: str = "TLP:CLEAR") -> str:
    """Normalize a TLP marking string to OpenCTI's TLP:LEVEL format."""
    if not value or not isinstance(value, str):
        return fallback
    normalized = value.strip().upper()
    if not normalized:
        return fallback
    if not normalized.startswith("TLP:"):
        normalized = f"TLP:{normalized}"
    return normalized


def _resolve_tlp(env_var: str, value: Optional[str]) -> stix2.MarkingDefinition:
    """Return the stix2.MarkingDefinition for a configured TLP string.

    Unknown / mistyped TLP values raise ValueError at startup listing every
    supported alias verbatim instead of silently falling back to TLP:WHITE.
    """
    normalized = _normalize_tlp(value)
    try:
        return _TLP_MAP[normalized]
    except KeyError as exc:
        valid = ", ".join(sorted(_TLP_MAP))
        raise ValueError(
            f"Unsupported {env_var} value {value!r}. Expected one of {valid}."
        ) from exc


def _stable_note_timestamp(observable: Dict[str, Any]) -> _dt.datetime:
    """Return a stable timestamp anchored on the observable's creation time.

    The Note SDO emitted by ``IPQSConnector._send_failure_note`` is keyed
    on a deterministic id derived from ``(created, content)`` via
    ``pycti.Note.generate_id``. To keep the id stable across runs of the
    same observable, the matching ``created`` / ``modified`` fields on
    the Note must also be stable. Using ``datetime.now()`` here would
    break that invariant: the id would be the same on every cycle, but
    the SDO's ``created`` would shift each run, churning the SDO version
    in OpenCTI for the same logical Note. Anchoring to the observable's
    own ``created_at`` (or ``created``) field gives us a value that is
    fixed per observable and therefore consistent on every retry.
    Falls back to a fixed epoch anchor when the observable carries no
    parseable timestamp - any deterministic value works because the
    id only depends on whatever value we pick, as long as it is the
    same on every cycle.
    """
    raw = observable.get("created_at") or observable.get("created")
    if isinstance(raw, str) and raw:
        try:
            return _dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            pass
    return _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc)


class IPQSConnector:
    """IPQS connector.

    Drives three IPQS API families with a single API key:

    * the fraud-and-risk-scoring endpoints (``/ip``, ``/url``,
      ``/email``, ``/phone``) for ``IPv4-Addr``, ``Email-Addr``,
      ``Phone-Number``, ``Domain-Name`` and ``Url`` observables;
    * the Darkweb-Leak endpoints (``/leaked/email``,
      ``/leaked/username``, ``/leaked/password``) for ``User-Account``
      observables (PR #6399);
    * the malware-file-scanner endpoints (``/malware/scan``,
      ``/malware/lookup``, ``/postback``) for ``Artifact``
      observables - the integration originally proposed as a
      standalone connector in PR #5970 now lives here so a single
      connector serves every IPQS use case (issue #6199).
    """

    def __init__(self) -> None:
        """Instantiate the connector helper from config."""
        config_file_path = Path(__file__).parent / "config.yml"
        if path.isfile(config_file_path):
            with open(config_file_path, encoding="utf-8") as fh:
                config = load(fh, Loader=FullLoader) or {}
        else:
            config = {}
        self.helper = OpenCTIConnectorHelper(config)

        self.api_key = get_config_variable(
            "IPQS_PRIVATE_KEY", ["ipqs", "private_key"], config
        )
        self.base_url = get_config_variable(
            "IPQS_BASE_URL",
            ["ipqs", "base_url"],
            config,
            default=_DEFAULT_IPQS_BASE_URL,
        )

        # Used by the Artifact branch to download the file content from
        # OpenCTI's object storage (``/storage/get/<id>``).
        self.octi_api_url = get_config_variable(
            "OPENCTI_URL", ["opencti", "url"], config, required=True
        )

        self.author = Identity(
            id=pycti.Identity.generate_id(SOURCE_NAME, "organization"),
            name=SOURCE_NAME,
            identity_class="organization",
            description="IPQS",
            confidence=self.helper.connect_confidence_level,
        )
        self.bundle = [self.author]
        self.client = IPQSClient(self.helper, self.base_url, self.api_key)

        # IP specific settings
        self.ip_add_relationships = get_config_variable(
            "IPQS_IP_ADD_RELATIONSHIPS",
            ["ipqs", "ip_add_relationships"],
            config,
        )

        # Domain specific settings
        self.domain_add_relationships = get_config_variable(
            "IPQS_DOMAIN_ADD_RELATIONSHIPS",
            ["ipqs", "domain_add_relationships"],
            config,
        )

        # TLP handling.
        #
        # ``IPQS_DEFAULT_TLP`` (default ``TLP:CLEAR``) is the marking
        # applied to STIX objects emitted by the new Artifact /
        # failure-note branches when the source observable carries no
        # marking of its own. ``IPQS_MAX_TLP`` (default ``TLP:AMBER``)
        # gates EVERY enrichment branch (IP / Email / URL / Phone /
        # User-Account / Artifact) through ``_check_max_tlp``:
        # observables marked above this threshold are skipped with an
        # explicit message. Operators running the previous version with
        # TLP:RED observables must set ``IPQS_MAX_TLP=TLP:RED`` to keep
        # the existing behaviour. Both values are resolved through
        # ``_resolve_tlp`` which raises ValueError on a mistyped /
        # unknown TLP alias instead of silently falling back to
        # ``TLP:WHITE``.
        self.default_tlp_string = _normalize_tlp(
            get_config_variable(
                "IPQS_DEFAULT_TLP",
                ["ipqs", "default_tlp"],
                config,
                default="TLP:CLEAR",
            )
        )
        self.default_tlp_marking: stix2.MarkingDefinition = _resolve_tlp(
            "IPQS_DEFAULT_TLP", self.default_tlp_string
        )
        self.default_tlp_id: str = self.default_tlp_marking.id

        self.max_tlp = _normalize_tlp(
            get_config_variable(
                "IPQS_MAX_TLP",
                ["ipqs", "max_tlp"],
                config,
                default="TLP:AMBER",
            )
        )
        # Validate ``IPQS_MAX_TLP`` at startup so a typo fails fast
        # instead of letting the gate silently pass everything.
        _resolve_tlp("IPQS_MAX_TLP", self.max_tlp)

    # ------------------------------------------------------------------
    # Helpers shared with the Artifact / failure-note branches
    # ------------------------------------------------------------------
    @staticmethod
    def _is_detected(response: Dict[str, Any]) -> bool:
        """Return True if at least one malware engine reports a detection."""
        results = response.get("result", [])
        if not isinstance(results, list):
            return False
        for item in results:
            if isinstance(item, dict) and item.get("detected") is True:
                return True
        return False

    @staticmethod
    def _build_result_summary(response: Dict[str, Any]) -> str:
        """Return a formatted, multi-line summary of each engine result."""
        lines: List[str] = []
        for engine in response.get("result", []) or []:
            if not isinstance(engine, dict):
                continue
            name = engine.get("name", "Unknown Engine")
            detected = engine.get("detected", False)
            error = engine.get("error", False)
            lines.append(f"- {name}:    ")
            lines.append(f"    Detected - {detected} | ")
            lines.append(f"    Error    - {error}\n")
        return "\n".join(lines) if lines else "No engine results available."

    @staticmethod
    def _flatten_json(
        data: Dict[str, Any],
        parent_key: str = "",
        sep: str = "_",
    ) -> Dict[str, Any]:
        """Recursively flatten nested dictionaries / lists into one level."""
        items: Dict[str, Any] = {}
        for key, value in data.items():
            new_key = f"{parent_key}{sep}{key}" if parent_key else key
            if isinstance(value, dict):
                items.update(IPQSConnector._flatten_json(value, new_key, sep))
            elif isinstance(value, list):
                for idx, element in enumerate(value):
                    if isinstance(element, dict):
                        items.update(
                            IPQSConnector._flatten_json(
                                element, f"{new_key}{sep}{idx}", sep
                            )
                        )
                    else:
                        items[f"{new_key}{sep}{idx}"] = element
            else:
                items[new_key] = value
        return items

    def _default_marking_refs(self) -> List[str]:
        """Return the configured default marking reference as a list."""
        if not self.default_tlp_id:
            return []
        return [self.default_tlp_id]

    @staticmethod
    def _observable_marking_refs(observable: Dict[str, Any]) -> List[str]:
        """Extract marking-definition refs from an OpenCTI observable.

        Supports both the GraphQL ``objectMarking`` shape (list of dicts
        with a ``standard_id``) and a plain ``object_marking_refs`` list
        of ids. Returns ``[]`` when the observable carries no marking;
        callers must fall back to ``_default_marking_refs`` in that case.
        """
        refs: List[str] = []
        raw = observable.get("objectMarking")
        if raw is None:
            raw = observable.get("object_marking_refs")
        if isinstance(raw, list):
            for marking in raw:
                if isinstance(marking, dict) and marking.get("standard_id"):
                    refs.append(marking["standard_id"])
                elif isinstance(marking, str):
                    refs.append(marking)
        seen: set = set()
        result: List[str] = []
        for ref in refs:
            if ref not in seen:
                seen.add(ref)
                result.append(ref)
        return result

    def _note_marking_refs(self, observable: Dict[str, Any]) -> List[str]:
        """Return the marking refs to apply to a failure Note.

        Inherits the source observable's markings (so an AMBER /
        AMBER+STRICT artifact never produces a less-restrictive
        CLEAR / WHITE diagnostic note) and falls back to the connector
        default only when the observable has no marking of its own.
        """
        return self._observable_marking_refs(observable) or self._default_marking_refs()

    def _send_failure_note(
        self,
        response: Dict[str, Any],
        observable: Dict[str, Any],
    ) -> None:
        """Create and send a Note when an IPQS malware enrichment failed.

        The Note's deterministic id is derived from
        ``(created, content)`` via ``pycti.Note.generate_id``. ``created``
        is anchored to ``_stable_note_timestamp(observable)`` (the
        observable's own ``created_at`` when available, else a fixed
        epoch anchor) so the id stays stable across runs of the same
        observable AND so the matching ``created`` / ``modified`` fields
        on the Note SDO line up with the id - a previous shape passed
        ``created=None`` to ``generate_id`` and let stix2 auto-populate
        ``created`` at object construction time, which produced the same
        Note id with a different ``created`` timestamp on every run and
        churned the SDO version in OpenCTI.

        The Note inherits the source observable's TLP markings - a
        TLP:AMBER artifact whose enrichment fails produces a TLP:AMBER
        diagnostic Note, never a less-restrictive ``TLP:CLEAR`` /
        ``TLP:WHITE`` one that could leak the existence of the artifact
        to user groups not entitled to see it.
        """
        message = response.get("message", "")
        labels = ["enrichment-failed"]
        if "Invalid URL" in message:
            labels.append("ipqs-invalid-url")
        if "Could not download" in message:
            labels.append("ipqs-no-downloadable-file")

        content = f"IPQS enrichment failed for {observable['standard_id']}: {message}"
        note_created = _stable_note_timestamp(observable)
        note_id = PyctiNote.generate_id(created=note_created, content=content)
        marking_refs = self._note_marking_refs(observable)
        note = stix2.Note(
            id=note_id,
            abstract="IPQS enrichment failed",
            content=content,
            object_refs=[observable["standard_id"]],
            created=note_created,
            modified=note_created,
            created_by_ref=self.author,
            confidence=self.helper.connect_confidence_level,
            labels=labels,
            object_marking_refs=marking_refs,
        )
        # Include the configured default marking-definition object in
        # the bundle so OpenCTI-specific markings (TLP:CLEAR,
        # TLP:AMBER+STRICT) are registered with the platform by
        # name even when this is the connector's first emission for the
        # observable. The platform deduplicates by id on subsequent bundles.
        bundle_objects: List[Any] = [self.author, self.default_tlp_marking, note]
        self.helper.send_stix2_bundle(
            stix2.Bundle(*bundle_objects, allow_custom=True).serialize()
        )

    @staticmethod
    def _format_response(
        enrich_fields: Dict[str, str], response: Dict[str, Any]
    ) -> str:
        """Render the response as a Markdown bullet list."""
        return "\n".join(
            f"- **{field_label}:**    {response.get(field_name)} "
            for field_name, field_label in enrich_fields.items()
            if field_name in response
        )

    # ------------------------------------------------------------------
    # Observable handlers - fraud-and-risk-scoring branch
    # ------------------------------------------------------------------
    def _process_ip(self, observable):
        """Enriches the IP."""
        response = self.client.get_ipqs_info(IP_ENRICH, observable["observable_value"])
        if response is None:
            return "IPQS IP enrichment failed or returned no usable response."
        builder = IPQSBuilder(
            self.helper, self.author, observable, response.get("fraud_score")
        )
        if self.ip_add_relationships:
            builder.create_asn_belongs_to(response.get("ASN"))

        description = self._format_response(self.client.ip_enrich_fields, response)
        labels = builder.ip_address_risk_scoring()
        builder.create_indicator_based_on(
            labels,
            f"[ipv4-addr:value = '{_stix_quote(observable['observable_value'])}']",
            observable["observable_value"],
            description,
        )
        return builder.send_bundle()

    def _process_email(self, observable):
        """Enriches the Email."""
        response = self.client.get_ipqs_info(
            EMAIL_ENRICH, observable["observable_value"]
        )
        if response is None:
            return "IPQS Email enrichment failed or returned no usable response."
        builder = IPQSBuilder(
            self.helper, self.author, observable, response.get("fraud_score")
        )
        description = self._format_response(self.client.email_enrich_fields, response)
        labels = builder.email_address_risk_scoring(
            response.get("disposable"), response.get("valid")
        )
        builder.create_indicator_based_on(
            labels,
            f"[email-addr:value = '{_stix_quote(observable['observable_value'])}']",
            observable["observable_value"],
            description,
        )
        return builder.send_bundle()

    def _process_url(self, observable):
        """Enriches a URL or Domain observable."""
        response = self.client.get_ipqs_info(URL_ENRICH, observable["observable_value"])
        if response is None:
            return "IPQS URL/Domain enrichment failed or returned no usable response."
        builder = IPQSBuilder(
            self.helper, self.author, observable, response.get("risk_score")
        )
        if (
            self.domain_add_relationships
            and observable["entity_type"] == "Domain-Name"
            and response.get("ip_address")
            and response.get("ip_address") != "N/A"
        ):
            builder.create_ip_resolves_to(response.get("ip_address"))

        description = self._format_response(self.client.url_enrich_fields, response)
        labels = builder.url_risk_scoring(
            response.get("malware"), response.get("phishing")
        )
        builder.create_indicator_based_on(
            labels,
            (
                f"[{observable['entity_type'].lower()}:value = "
                f"'{_stix_quote(observable['observable_value'])}']"
            ),
            observable["observable_value"],
            description,
        )
        return builder.send_bundle()

    def _process_phone(self, observable):
        """Enriches Phone Numbers."""
        response = self.client.get_ipqs_info(
            PHONE_ENRICH, observable["observable_value"]
        )
        if response is None:
            return "IPQS Phone enrichment failed or returned no usable response."
        builder = IPQSBuilder(
            self.helper, self.author, observable, response.get("fraud_score")
        )
        description = self._format_response(self.client.phone_enrich_fields, response)
        labels = builder.phone_address_risk_scoring(
            response.get("valid"), response.get("active")
        )
        builder.create_indicator_based_on(
            labels,
            f"[phone-number:value = '{_stix_quote(observable['observable_value'])}']",
            observable["observable_value"],
            description,
        )
        return builder.send_bundle()

    # ------------------------------------------------------------------
    # Artifact / malware-file-scanner branch
    # ------------------------------------------------------------------
    def _process_artifact(self, observable: Dict[str, Any]) -> Optional[str]:
        """Download the artifact and submit it to IPQS for malware scanning."""
        import_files = observable.get("importFiles")
        if not isinstance(import_files, list) or not import_files:
            self.helper.log_error(
                "No importFiles found in observable; skipping enrichment."
            )
            return None

        file_info = import_files[0]
        file_name = file_info.get("name")
        file_id = file_info.get("id")
        if not file_id or not file_name:
            self.helper.log_error(
                "Artifact import file is missing 'id' or 'name'; skipping."
            )
            return None

        self.helper.log_info(f"[IPQS] processing file observable: {file_name}")
        file_uri = f"{self.octi_api_url}/storage/get/{file_id}"

        try:
            file_content = self.helper.api.fetch_opencti_file(file_uri, True)
            response = self.client.get_malware_scan_info(
                file={"file": (file_name, file_content)}
            )
        except Exception as error:  # pylint: disable=broad-exception-caught
            # Surface the failure to the operator through a STIX Note
            # attached to the observable (not just a log line) so the
            # diagnostic is visible from the OpenCTI UI without having
            # to inspect connector logs.
            self.helper.log_error(f"Failed to process file {file_name}: {error}")
            self._send_failure_note(
                {
                    "success": False,
                    "message": (
                        f"Failed to download or submit file {file_name!r} to "
                        f"IPQS: {error}"
                    ),
                },
                observable,
            )
            return None

        if response is None:
            self.helper.log_error(
                f"No response received from IPQS for file {file_name}; "
                "skipping enrichment."
            )
            self._send_failure_note(
                {
                    "success": False,
                    "message": "No response received from IPQS API.",
                },
                observable,
            )
            return None

        if not response.get("success"):
            self._send_failure_note(response, observable)
            return None

        # ``get_malware_scan_info`` may return the last response with
        # ``status == "pending"`` when the polling budget is exhausted before
        # IPQS produces a final verdict. Treating that as a clean / detected
        # verdict would label the observable from incomplete data and even
        # mark it ``Clean`` when a real scan is still running, so surface
        # this as an enrichment failure instead.
        scan_status = (response.get("status") or "").strip().lower()
        if scan_status == "pending":
            self.helper.log_warning(
                f"IPQS malware scan for file {file_name} is still pending "
                "after the polling budget; surfacing as enrichment failure."
            )
            self._send_failure_note(
                {
                    "success": False,
                    "message": (
                        "IPQS malware scan is still pending after the "
                        "polling budget; retry the enrichment later."
                    ),
                },
                observable,
            )
            return None

        engine_summary = self._build_result_summary(response)
        detected = self._is_detected(response)
        score = _MALICIOUS_FILE_SCORE if detected else _DEFAULT_FILE_SCORE
        flat_response = self._flatten_json(response)

        builder = IPQSBuilder(
            self.helper,
            self.author,
            observable,
            score,
            default_object_marking_refs=self._default_marking_refs(),
        )
        # Ship the configured default marking-definition object alongside
        # the bundle so non-built-in markings (TLP:CLEAR /
        # TLP:AMBER+STRICT) are registered with the platform by name
        # rather than being left as dangling references. OpenCTI
        # deduplicates by id on subsequent emissions.
        builder.bundle.append(self.default_tlp_marking)

        description_lines: List[str] = []
        for field, label in self.client.file_enrich_fields.items():
            if field in flat_response:
                description_lines.append(
                    f"- **{label}:**    {flat_response.get(field)}"
                )
        description = "\n".join(description_lines + [engine_summary])

        file_sha256 = flat_response.get("file_hash")
        if file_sha256:
            pattern = f"[file:hashes.'SHA-256' = '{file_sha256}']"
            labels = builder.malware_file_detection(detected)
            builder.create_indicator_based_on(
                labels,
                pattern,
                file_name,
                description,
                detection=detected,
            )
        else:
            self.helper.log_warning(
                "[IPQS] Could not derive a SHA-256 pattern from the IPQS "
                "response; no indicator will be created."
            )

        builder.add_reference(response, observable)
        return builder.send_bundle()

    def _check_max_tlp(self, observable: Dict[str, Any]) -> bool:
        """Return True when the observable's TLP is at or below max_tlp.

        Inspects BOTH marking shapes the connector accepts elsewhere:

        * the GraphQL ``objectMarking`` list (dicts with
          ``definition_type`` / ``definition`` - preferred), and
        * the alternate ``object_marking_refs`` flat list of
          marking-definition ids (resolved back to a canonical
          TLP string via ``_MARKING_ID_TO_TLP``).
        """
        tlp = self.default_tlp_string
        # Primary: GraphQL ``objectMarking`` (list of dicts).
        for marking_definition in observable.get("objectMarking", []) or []:
            if marking_definition.get("definition_type") == "TLP":
                tlp = _normalize_tlp(
                    marking_definition.get("definition"),
                    fallback=self.default_tlp_string,
                )
                break
        else:
            # Fallback: alternate ``object_marking_refs`` shape.
            for ref in observable.get("object_marking_refs", []) or []:
                if isinstance(ref, str):
                    resolved = _MARKING_ID_TO_TLP.get(ref)
                    if resolved is not None:
                        tlp = resolved
                        break
        return OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp)

    # ------------------------------------------------------------------
    # Darkweb-Leak branch (User-Account observables)
    # ------------------------------------------------------------------
    def _process_leak(self, observable):
        """Enriches a User-Account observable via the IPQS Darkweb-Leak API.

        OpenCTI ``User-Account`` observables carry either an
        ``account_login`` (username / email) or a ``credential``
        (password). The connector picks the right IPQS leaked endpoint
        depending on which value is populated; if both are present the
        credential takes precedence.
        """
        credential = observable.get("credential") or ""
        account_login = observable.get("account_login") or ""

        public_name: Optional[str] = None
        if credential:
            value = credential
            pattern = f"[user-account:credential = '{_stix_quote(value)}']"
            response = self.client.get_leaked_info(LEAK_PASSWORD, value)
            public_name = (
                f"Leaked credential for {observable.get('standard_id', 'user-account')}"
            )
        elif account_login:
            value = account_login
            pattern = f"[user-account:account_login = '{_stix_quote(value)}']"
            response = self.client.get_leaked_info(LEAK_USERNAME_OR_EMAIL, value)
        else:
            return (
                "User-Account observable is missing both ``account_login`` "
                "and ``credential``; nothing to enrich."
            )

        if not response:
            return "No leak data found or API error."

        exposed = to_bool(response.get("exposed"))
        plain_text_password = to_bool(response.get("plain_text_password"))

        score = 100 if exposed or plain_text_password else 0
        builder = IPQSBuilder(self.helper, self.author, observable, score)

        description = self._format_leak_description(
            response, exposed, plain_text_password
        )
        labels = builder.leak_risk_scoring(exposed, plain_text_password)
        builder.create_indicator_based_on(
            labels=labels,
            pattern=pattern,
            indicator_value=value,
            description=description,
            sensitive=True,
            public_name=public_name,
        )
        return builder.send_bundle()

    @staticmethod
    def _format_leak_description(
        response: Dict[str, Any],
        exposed: bool,
        plain_text_password: bool,
    ) -> str:
        """Render the Darkweb-Leak response as a Markdown bullet list."""
        sources_raw = response.get("source")
        if isinstance(sources_raw, list):
            sources: List[str] = [str(item) for item in sources_raw]
        elif sources_raw in (None, ""):
            sources = []
        else:
            sources = [str(sources_raw)]

        first_seen = response.get("first_seen")
        first_seen_parts: List[str] = []
        if isinstance(first_seen, dict):
            for key in ("human", "iso", "timestamp"):
                value = first_seen.get(key)
                if value is not None and value != "":
                    first_seen_parts.append(f"{key}={value}")

        fields: List[str] = []

        def add(label: str, val) -> None:
            if val not in (None, "", False):
                fields.append(f"- {label}: {val}")

        add("Success", response.get("success"))
        add("Exposed", exposed)
        add("Plain Text Password", plain_text_password)
        if sources:
            add("Source", ", ".join(sources))
        if first_seen_parts:
            add("First Seen", "; ".join(first_seen_parts))
        add("Message", response.get("message"))

        return "\n".join(fields) if fields else "- No leak details available"

    # ------------------------------------------------------------------
    # Dispatcher / listener
    # ------------------------------------------------------------------
    _SENSITIVE_OBSERVABLE_FIELDS = ("credential", "account_login")

    @classmethod
    def _redact_observable(cls, observable: Any) -> Any:
        """Return a log-safe copy of ``observable``."""
        if not isinstance(observable, dict):
            return observable
        redacted = dict(observable)
        for field in cls._SENSITIVE_OBSERVABLE_FIELDS:
            if field in redacted and redacted[field] not in (None, ""):
                redacted[field] = "***REDACTED***"
        return redacted

    def _process_message(self, data: Dict):
        observable = data["enrichment_entity"]
        if observable is None:
            raise ValueError(
                "Observable not found (or the connector does "
                "not have access to this observable, "
                "check the group of the connector user)",
            )
        # Never log ``credential`` / ``account_login`` - they are
        # plaintext secrets on Darkweb-Leak User-Account observables.
        self.helper.log_debug(
            "[IPQS] starting enrichment of observable: "
            f"{self._redact_observable(observable)}"
        )

        if not self._check_max_tlp(observable):
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than "
                "the configured IPQS_MAX_TLP."
            )

        match observable["entity_type"]:
            case "IPv4-Addr":
                return self._process_ip(observable)
            case "Phone-Number":
                return self._process_phone(observable)
            case "Url" | "Domain-Name":
                return self._process_url(observable)
            case "Email-Addr":
                return self._process_email(observable)
            case "User-Account":
                return self._process_leak(observable)
            case "Artifact":
                return self._process_artifact(observable)
            case _:
                raise ValueError(
                    f'{observable["entity_type"]} is not a supported entity type.'
                )

    # Start the main loop
    def start(self) -> None:
        """Start the main loop."""
        self.helper.listen(message_callback=self._process_message)
