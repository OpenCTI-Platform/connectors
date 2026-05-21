# -*- coding: utf-8 -*-
"""IPQS enrichment module."""

from os import path
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

# Default and malicious scores applied to Artifact / URL malware scan
# verdicts (the fraud-and-risk-scoring endpoints carry their own per-type
# score and are unchanged).
_DEFAULT_FILE_SCORE = 50
_MALICIOUS_FILE_SCORE = 100

# Default IPQS base URL used when ``IPQS_BASE_URL`` is not configured. Documented
# in ``README.md`` and ``config.yml.sample`` — keep all three in sync.
_DEFAULT_IPQS_BASE_URL = "https://ipqualityscore.com/api/json"


def _make_tlp_marking(definition: str) -> stix2.MarkingDefinition:
    """Return a ``stix2.MarkingDefinition`` for an OpenCTI-specific TLP value.

    Used for ``TLP:CLEAR`` and ``TLP:AMBER+STRICT`` which the platform
    represents as custom marking-definition objects (the STIX 2.1
    library only exposes built-in constants for ``TLP_WHITE`` /
    ``TLP_GREEN`` / ``TLP_AMBER`` / ``TLP_RED``). Building a real
    ``stix2.MarkingDefinition`` lets the connector ship the marking
    object in every bundle so the OpenCTI UI displays the right label
    (e.g. ``TLP:CLEAR`` rather than the legacy ``TLP:WHITE``).
    """
    return stix2.MarkingDefinition(
        id=PyctiMarkingDefinition.generate_id("TLP", definition),
        definition_type="statement",
        definition={"statement": "custom"},
        allow_custom=True,
        x_opencti_definition_type="TLP",
        x_opencti_definition=definition,
    )


# ``TLP:CLEAR`` and ``TLP:AMBER+STRICT`` are OpenCTI-specific markings
# and are not exposed as ``stix2`` constants. We materialise them as
# real ``stix2.MarkingDefinition`` objects (mirroring the convention in
# the OpenCTI Connectors SDK's TLP-marking model) so the connector can
# ship the marking object itself in every emitted bundle and the
# platform can register the right UI label for each one.
_TLP_MAP: Dict[str, stix2.MarkingDefinition] = {
    "TLP:CLEAR": _make_tlp_marking("TLP:CLEAR"),
    "TLP:WHITE": stix2.TLP_WHITE,
    "TLP:GREEN": stix2.TLP_GREEN,
    "TLP:AMBER": stix2.TLP_AMBER,
    "TLP:AMBER+STRICT": _make_tlp_marking("TLP:AMBER+STRICT"),
    "TLP:RED": stix2.TLP_RED,
}

# Reverse lookup ``marking.id -> canonical TLP string``. Used by
# ``_check_max_tlp`` to recover the TLP level when an observable is
# provided in the alternate ``object_marking_refs`` shape (a flat list
# of marking-definition ids rather than the GraphQL ``objectMarking``
# list of dicts). Without this the max-TLP gate would silently fall
# back to ``IPQS_DEFAULT_TLP`` on the alternate shape and could submit
# data for an observable that is actually above ``IPQS_MAX_TLP``.
# ``_observable_marking_refs`` (used downstream for the failure-Note
# marking) already supports both shapes, so the two enforcement
# points are consistent now.
#
# Note: ``pycti.MarkingDefinition.generate_id("TLP", "TLP:CLEAR")``
# collides with the legacy ``stix2.TLP_WHITE`` id by design — both
# represent the least-restrictive TLP level (the "white"/"clear"
# rename is purely a UI label change in OpenCTI). The reverse lookup
# only needs to return *some* valid TLP string that resolves to the
# correct level for the gate; whichever entry wins the dict-build
# collision is fine because ``check_max_tlp`` treats them as
# equivalent.
_MARKING_ID_TO_TLP: Dict[str, str] = {
    marking.id: tlp_string for tlp_string, marking in _TLP_MAP.items()
}


def _normalize_tlp(value: Optional[str], fallback: str = "TLP:CLEAR") -> str:
    """Normalize a TLP marking string to OpenCTI's ``TLP:LEVEL`` format."""
    if not value or not isinstance(value, str):
        return fallback
    normalized = value.strip().upper()
    # Whitespace-only inputs (`"   "`) strip down to an empty string;
    # without this guard we would happily return ``"TLP:"`` and let it
    # propagate into ``_TLP_MAP`` lookups, which raise. Treat an empty
    # post-strip value as missing and use the fallback.
    if not normalized:
        return fallback
    if not normalized.startswith("TLP:"):
        normalized = f"TLP:{normalized}"
    return normalized


def _resolve_tlp(env_var: str, value: Optional[str]) -> stix2.MarkingDefinition:
    """Return the ``stix2.MarkingDefinition`` for a configured TLP string.

    Unknown / mistyped TLP values raise :class:`ValueError` at startup
    listing every supported alias verbatim instead of silently falling
    back to ``TLP:WHITE`` — a silent fallback could downgrade Artifact
    indicators / failure notes from the operator's intended marking to
    a less-restrictive one (e.g. typing ``ANBER`` instead of ``AMBER``
    would have emitted ``TLP:WHITE``-marked notes).
    """
    normalized = _normalize_tlp(value)
    try:
        return _TLP_MAP[normalized]
    except KeyError as exc:
        valid = ", ".join(sorted(_TLP_MAP))
        raise ValueError(
            f"Unsupported {env_var} value {value!r}. Expected one of {valid}."
        ) from exc


class IPQSConnector:
    """IPQS connector.

    Drives two IPQS API families with a single API key:

    * the fraud-and-risk-scoring endpoints (``/ip``, ``/url``,
      ``/email``, ``/phone``) for ``IPv4-Addr``, ``Email-Addr``,
      ``Phone-Number``, ``Domain-Name`` and ``Url`` observables;
    * the malware-file-scanner endpoints (``/malware/scan``,
      ``/malware/lookup``, ``/postback``) for ``Artifact``
      observables — the integration originally proposed as a
      standalone connector in
      `PR #5970 <https://github.com/OpenCTI-Platform/connectors/pull/5970>`_
      now lives here so a single connector serves every IPQS use
      case (see `issue #6199
      <https://github.com/OpenCTI-Platform/connectors/issues/6199>`_).
    """

    _SOURCE_NAME = "IPQS"
    _IP_ENRICH = "ip"
    _URL_ENRICH = "url"
    _EMAIL_ENRICH = "email"
    _PHONE_ENRICH = "phone"

    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = path.dirname(path.abspath(__file__)) + "/config.yml"

        config = (
            load(open(config_file_path, encoding="utf-8"), Loader=FullLoader)
            if path.isfile(config_file_path)
            else {}
        )
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
            id=pycti.Identity.generate_id(self._SOURCE_NAME, "organization"),
            name=self._SOURCE_NAME,
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
        # * ``IPQS_DEFAULT_TLP`` (default ``TLP:CLEAR``) is the marking
        #   applied to STIX objects emitted by the new Artifact /
        #   failure-note branches when the source observable carries no
        #   marking of its own. The fraud-and-risk-scoring branches
        #   produced before this change do **not** use this default —
        #   their markings are unchanged.
        # * ``IPQS_MAX_TLP`` (default ``TLP:AMBER``) gates **every**
        #   enrichment branch (IP / Email / URL / Phone / Artifact)
        #   through ``_check_max_tlp``: observables marked above this
        #   threshold are skipped with an explicit message. Operators
        #   running the previous version with TLP:RED observables must
        #   set ``IPQS_MAX_TLP=TLP:RED`` to keep the existing behaviour.
        #
        # Both values are resolved through ``_resolve_tlp`` which raises
        # :class:`ValueError` on a mistyped / unknown TLP alias instead
        # of silently falling back to ``TLP:WHITE`` (which would have
        # downgraded Artifact indicators / failure notes from the
        # operator's intended marking).
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
        # Validate ``IPQS_MAX_TLP`` at startup too so a typo fails fast
        # instead of letting the gate silently pass everything.
        _resolve_tlp("IPQS_MAX_TLP", self.max_tlp)

    # ------------------------------------------------------------------
    # Helpers shared with the Artifact / failure-note branches
    # ------------------------------------------------------------------
    @staticmethod
    def _is_detected(response: Dict[str, Any]) -> bool:
        """Return ``True`` if at least one malware engine reports a detection."""
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
        """Recursively flatten nested dictionaries / lists into one level.

        Keys are joined using ``sep``; lists are indexed.
        """
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
        """Return the configured default marking reference as a list.

        Returns the OpenCTI-canonical marking-definition id (including the
        proper ``TLP:AMBER+STRICT`` id, which is *not* the same as
        ``stix2.TLP_AMBER`` and would otherwise downgrade the marking).
        """
        if not self.default_tlp_id:
            return []
        return [self.default_tlp_id]

    @staticmethod
    def _observable_marking_refs(observable: Dict[str, Any]) -> List[str]:
        """Extract marking-definition refs from an OpenCTI observable.

        Supports both the GraphQL ``objectMarking`` shape (list of dicts
        with a ``standard_id``) and a plain ``object_marking_refs`` list
        of ids. Returns ``[]`` when the observable carries no marking
        — callers must fall back to ``_default_marking_refs`` (or the
        equivalent helper) in that case.
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
        # Deduplicate while preserving order.
        seen: set = set()
        result: List[str] = []
        for ref in refs:
            if ref not in seen:
                seen.add(ref)
                result.append(ref)
        return result

    def _note_marking_refs(self, observable: Dict[str, Any]) -> List[str]:
        """Return the marking refs to apply to a failure ``Note``.

        Inherits the source observable's markings (so an ``AMBER`` /
        ``AMBER+STRICT`` artifact never produces a less-restrictive
        ``CLEAR`` / ``WHITE`` diagnostic note) and falls back to the
        connector default only when the observable has no marking of
        its own.
        """
        return self._observable_marking_refs(observable) or self._default_marking_refs()

    def _send_failure_note(
        self,
        response: Dict[str, Any],
        observable: Dict[str, Any],
    ) -> None:
        """Create and send a Note when an IPQS malware enrichment failed.

        Used by the Artifact branch so the operator can see in OpenCTI
        why an enrichment did not produce an indicator (invalid input,
        no credits, upstream service issues, ...).

        The Note's deterministic id is salted with the observable
        ``standard_id`` so two unrelated observables that hit the same
        upstream message (e.g. ``"No response received from IPQS API."``)
        produce two distinct notes instead of merging into a single one.

        The Note inherits the source observable's TLP markings — a
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
        note_id = PyctiNote.generate_id(created=None, content=content)
        marking_refs = self._note_marking_refs(observable)
        note = stix2.Note(
            id=note_id,
            abstract="IPQS enrichment failed",
            content=content,
            object_refs=[observable["standard_id"]],
            created_by_ref=self.author,
            confidence=self.helper.connect_confidence_level,
            labels=labels,
            object_marking_refs=marking_refs,
        )
        # Include the configured default marking-definition object in
        # the bundle so OpenCTI-specific markings (``TLP:CLEAR``,
        # ``TLP:AMBER+STRICT``) are registered with the platform by
        # name even when this is the connector's first emission for the
        # observable. The platform deduplicates by ``id`` on subsequent
        # bundles.
        bundle_objects: List[Any] = [self.author, self.default_tlp_marking, note]
        self.helper.send_stix2_bundle(
            stix2.Bundle(*bundle_objects, allow_custom=True).serialize()
        )

    def _process_ip(self, observable):
        """
        Enriches the IP
        """
        response = self.client.get_ipqs_info(
            self._IP_ENRICH, observable["observable_value"]
        )

        builder = IPQSBuilder(
            self.helper, self.author, observable, response.get("fraud_score")
        )

        if self.ip_add_relationships:
            builder.create_asn_belongs_to(response.get("ASN"))

        res_format = ""
        for (
            ip_enrich_field,
            ip_enrich_field_value,
        ) in self.client.ip_enrich_fields.items():
            if ip_enrich_field in response:
                enrich_field_value = response.get(ip_enrich_field)
                res_format = (
                    res_format
                    + f"- **{ip_enrich_field_value}:**    {enrich_field_value} \n"
                )

        labels = builder.ip_address_risk_scoring()

        builder.create_indicator_based_on(
            labels,
            f"""[ipv4-addr:value = '{observable["observable_value"]}']""",
            observable["observable_value"],
            res_format,
        )

        return builder.send_bundle()

    def _process_email(self, observable):
        """
        Enriches the Email.
        """
        response = self.client.get_ipqs_info(
            self._EMAIL_ENRICH, observable["observable_value"]
        )

        builder = IPQSBuilder(
            self.helper, self.author, observable, response.get("fraud_score")
        )

        res_format = ""
        for (
            email_enrich_field,
            email_enrich_field_value,
        ) in self.client.email_enrich_fields.items():
            if email_enrich_field in response:
                enrich_field_value = response.get(email_enrich_field)
                res_format = (
                    res_format
                    + f"- **{email_enrich_field_value}:**    {enrich_field_value} \n"
                )

        labels = builder.email_address_risk_scoring(
            response.get("disposable"), response.get("valid")
        )

        builder.create_indicator_based_on(
            labels,
            f"""[email-addr:value = '{observable["observable_value"]}']""",
            observable["observable_value"],
            res_format,
        )

        return builder.send_bundle()

    def _process_url(self, observable):
        response = self.client.get_ipqs_info(
            self._URL_ENRICH, observable["observable_value"]
        )

        builder = IPQSBuilder(
            self.helper, self.author, observable, response.get("risk_score")
        )

        if self.domain_add_relationships and observable["entity_type"] == "Domain-Name":
            if response.get("ip_address") != "N/A":
                builder.create_ip_resolves_to(response.get("ip_address"))

        res_format = ""
        for (
            url_enrich_field,
            url_enrich_field_value,
        ) in self.client.url_enrich_fields.items():
            if url_enrich_field in response:
                enrich_field_value = response.get(url_enrich_field)
                res_format = (
                    res_format
                    + f"- **{url_enrich_field_value}:**    {enrich_field_value} \n"
                )

        labels = builder.url_risk_scoring(
            response.get("malware"), response.get("phishing")
        )

        builder.create_indicator_based_on(
            labels,
            f"""[{observable["entity_type"].lower()}:value = '{observable["observable_value"]}']""",
            observable["observable_value"],
            res_format,
        )

        return builder.send_bundle()

    def _process_phone(self, observable):
        response = self.client.get_ipqs_info(
            self._PHONE_ENRICH, observable["observable_value"]
        )

        builder = IPQSBuilder(
            self.helper, self.author, observable, response.get("fraud_score")
        )

        res_format = ""
        for (
            phone_enrich_field,
            phone_enrich_field_value,
        ) in self.client.phone_enrich_fields.items():
            if phone_enrich_field in response:
                enrich_field_value = response.get(phone_enrich_field)
                res_format = (
                    res_format
                    + f"- **{phone_enrich_field_value}:**    {enrich_field_value} \n"
                )

        labels = builder.phone_address_risk_scoring(
            response.get("valid"), response.get("active")
        )

        builder.create_indicator_based_on(
            labels,
            f"""[phone-number:value = '{observable["observable_value"]}']""",
            observable["observable_value"],
            res_format,
        )

        return builder.send_bundle()

    # ------------------------------------------------------------------
    # Artifact / malware-file-scanner branch
    #
    # Mirrors the design originally proposed in
    # https://github.com/OpenCTI-Platform/connectors/pull/5970 but lives
    # inside the existing IPQS connector so both API families share a
    # single Docker image, configuration and OpenCTI scope.
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
            # to inspect connector logs. ``_send_failure_note`` is
            # defensive enough to render any ``message`` without
            # leaking the ``payload_bin`` of the source observable.
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
        # the bundle so non-built-in markings (``TLP:CLEAR`` /
        # ``TLP:AMBER+STRICT``) are registered with the platform by name
        # rather than being left as dangling references. OpenCTI
        # deduplicates by ``id`` on subsequent emissions.
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
        """Return ``True`` when the observable's TLP is at or below ``max_tlp``.

        Inspects BOTH marking shapes the connector accepts elsewhere:

        * the GraphQL ``objectMarking`` list (dicts with
          ``definition_type`` / ``definition`` — preferred), and
        * the alternate ``object_marking_refs`` flat list of
          marking-definition ids (resolved back to a canonical
          TLP string via ``_MARKING_ID_TO_TLP``).

        ``_observable_marking_refs`` already accepts both shapes for the
        failure-Note marking-inheritance path; the max-TLP gate must
        check both as well — otherwise an observable carrying its TLP
        in the alternate flat-id shape would silently fall back to
        ``IPQS_DEFAULT_TLP`` and slip past the gate even when the
        actual TLP is above ``IPQS_MAX_TLP``.

        Uses ``IPQS_DEFAULT_TLP`` as a fallback when the observable
        carries no TLP marking in either shape — same behaviour as the
        standalone IPQS Analyzer proposed in PR #5970.
        """
        tlp = self.default_tlp_string
        # Primary: GraphQL ``objectMarking`` (list of dicts with
        # ``definition_type`` + ``definition``).
        for marking_definition in observable.get("objectMarking", []) or []:
            if marking_definition.get("definition_type") == "TLP":
                tlp = _normalize_tlp(
                    marking_definition.get("definition"),
                    fallback=self.default_tlp_string,
                )
                break
        else:
            # Fallback: alternate ``object_marking_refs`` shape (a flat
            # list of marking ids). Resolve known TLP ids back to their
            # canonical TLP string; unknown ids are ignored (they may be
            # PAP or another non-TLP marking definition).
            for ref in observable.get("object_marking_refs", []) or []:
                if isinstance(ref, str):
                    resolved = _MARKING_ID_TO_TLP.get(ref)
                    if resolved is not None:
                        tlp = resolved
                        break
        return OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp)

    def _process_message(self, data: Dict):
        observable = data["enrichment_entity"]

        if observable is None:
            raise ValueError(
                "Observable not found (or the connector does not has access to this observable, "
                "check the group of the connector user)"
            )

        self.helper.log_debug(f"[IPQS] starting enrichment of observable: {observable}")

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
            case "Artifact":
                return self._process_artifact(observable)
            case _:
                raise ValueError(
                    f'{observable["entity_type"]} is not a supported entity type.'
                )

    # Start the main loop
    def start(self):
        """Main method to start."""
        self.helper.listen(message_callback=self._process_message)
