"""IPQS enrichment module."""

from os import path
from pathlib import Path
from typing import Any, Dict, List, Optional

import pycti
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
    """Escape ``value`` for inclusion in a single-quoted STIX pattern literal.

    STIX patterns use single quotes to delimit string literals, with
    backslash as the escape character. Passwords / account logins
    routinely contain ``'`` or ``\\``, so any value that is dropped
    into a ``'<value>'`` literal must escape both characters or the
    resulting pattern is invalid and ``stix2.Indicator`` rejects it
    at creation time.
    """
    return (value or "").replace("\\", "\\\\").replace("'", "\\'")


class IPQSConnector:
    """IPQS connector entry point."""

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
            "IPQS_BASE_URL", ["ipqs", "base_url"], config
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

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _format_response(
        enrich_fields: Dict[str, str], response: Dict[str, Any]
    ) -> str:
        """Render the response as a Markdown bullet list.

        Only the keys present in both ``enrich_fields`` and ``response``
        are rendered, so the indicator description stays scoped to the
        documented field map per endpoint.
        """
        return "\n".join(
            f"- **{field_label}:**    {response.get(field_name)} "
            for field_name, field_label in enrich_fields.items()
            if field_name in response
        )

    # ------------------------------------------------------------------
    # Observable handlers
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
            # ``_query`` already logged the underlying cause (network
            # error, non-2xx HTTP status, non-JSON body or
            # ``success != True`` payload); surface a generic
            # enrichment-failed message that matches what the IP /
            # Email / URL handlers return so operators are not
            # misled into thinking the phone number itself is the
            # problem.
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

    def _process_leak(self, observable):
        """Enriches a User-Account observable via the IPQS Darkweb-Leak API.

        OpenCTI ``User-Account`` observables carry either an
        ``account_login`` (username / email) or a ``credential``
        (password). The connector picks the right IPQS leaked endpoint
        depending on which value is populated; if both are present the
        credential takes precedence (passwords are the more sensitive
        value to know about).
        """
        credential = observable.get("credential") or ""
        account_login = observable.get("account_login") or ""

        # ``public_name`` becomes the ``Indicator.name`` written to
        # OpenCTI for sensitive lookups so the password / login itself
        # never lands in the UI search index. The deterministic STIX
        # pattern still contains the value (it is required by STIX),
        # but it is hidden from the connector logs by ``builder``.
        public_name: Optional[str] = None
        if credential:
            value = credential
            # Passwords / account logins routinely contain `'` and `\`,
            # which would produce an invalid STIX pattern when dropped
            # straight into a single-quoted literal. ``_stix_quote``
            # escapes both characters with the standard STIX backslash
            # rules.
            pattern = f"[user-account:credential = '{_stix_quote(value)}']"
            response = self.client.get_leaked_info(LEAK_PASSWORD, value)
            public_name = (
                f"Leaked credential for {observable.get('standard_id', 'user-account')}"
            )
        elif account_login:
            value = account_login
            pattern = f"[user-account:account_login = '{_stix_quote(value)}']"
            response = self.client.get_leaked_info(LEAK_USERNAME_OR_EMAIL, value)
            # ``account_login`` itself is the public identifier of the
            # account (typically an email or username); we keep it
            # visible as the indicator name and use the standard
            # (non-sensitive) code path below.
        else:
            return (
                "User-Account observable is missing both ``account_login`` "
                "and ``credential``; nothing to enrich."
            )

        if not response:
            return "No leak data found or API error."

        # ``exposed`` and ``plain_text_password`` are encoded by IPQS as
        # native JSON booleans on some payloads and as the strings
        # ``"True"`` / ``"False"`` on others (matching the legacy GET
        # endpoints used by ``_query``). The shared ``to_bool`` helper
        # normalises both so a ``"False"`` payload (non-empty string,
        # therefore truthy under ``bool(...)``) does not silently force
        # the verdict to ``CRITICAL``.
        exposed = to_bool(response.get("exposed"))
        plain_text_password = to_bool(response.get("plain_text_password"))

        # Verdict policy: any exposure -> CRITICAL, otherwise CLEAN.
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
            sensitive=bool(credential),
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
    # Observable fields that are never safe to write to the connector logs
    # (Darkweb-Leak User-Account observables can carry plaintext
    # passwords / account logins, both of which would otherwise leak into
    # any centralised log aggregator).
    _SENSITIVE_OBSERVABLE_FIELDS = ("credential", "account_login")

    @classmethod
    def _redact_observable(cls, observable: Any) -> Any:
        """Return a log-safe copy of ``observable``.

        Drops every value listed in :data:`_SENSITIVE_OBSERVABLE_FIELDS`
        (``credential`` / ``account_login``) and replaces it with a
        ``***REDACTED***`` marker so operators can still see that the
        field was present without leaking its value into the logs.

        The signature is intentionally permissive: this helper is
        called from a debug-logging path, so it must never raise on a
        surprising input shape (e.g. a non-``dict`` payload from a
        future OpenCTI version). Non-``dict`` inputs are returned
        unchanged — the parameter and return types are therefore
        widened to :data:`typing.Any` to reflect that contract and
        keep static analysers honest.
        """
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
        # Never log ``credential`` / ``account_login`` — they are
        # plaintext secrets on Darkweb-Leak User-Account observables.
        self.helper.log_debug(
            "[IPQS] starting enrichment of observable: "
            f"{self._redact_observable(observable)}"
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
            case _:
                raise ValueError(
                    f'{observable["entity_type"]} is not a supported entity type.'
                )

    # Start the main loop
    def start(self) -> None:
        """Start the main loop."""
        self.helper.listen(message_callback=self._process_message)
