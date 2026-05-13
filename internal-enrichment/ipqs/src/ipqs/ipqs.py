"""IPQS enrichment module."""

from os import path
from pathlib import Path
from typing import Any, Dict, List

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
)


class IPQSConnector:
    """IPQS connector entry point."""

    def __init__(self) -> None:
        """Instantiate the connector helper from config."""
        config_file_path = Path(__file__).parent / "config.yml"
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
        builder = IPQSBuilder(
            self.helper, self.author, observable, response.get("fraud_score")
        )
        if self.ip_add_relationships:
            builder.create_asn_belongs_to(response.get("ASN"))

        description = self._format_response(self.client.ip_enrich_fields, response)
        labels = builder.ip_address_risk_scoring()
        builder.create_indicator_based_on(
            labels,
            f"""[ipv4-addr:value = '{observable["observable_value"]}']""",
            observable["observable_value"],
            description,
        )
        return builder.send_bundle()

    def _process_email(self, observable):
        """Enriches the Email."""
        response = self.client.get_ipqs_info(
            EMAIL_ENRICH, observable["observable_value"]
        )
        builder = IPQSBuilder(
            self.helper, self.author, observable, response.get("fraud_score")
        )
        description = self._format_response(self.client.email_enrich_fields, response)
        labels = builder.email_address_risk_scoring(
            response.get("disposable"), response.get("valid")
        )
        builder.create_indicator_based_on(
            labels,
            f"""[email-addr:value = '{observable["observable_value"]}']""",
            observable["observable_value"],
            description,
        )
        return builder.send_bundle()

    def _process_url(self, observable):
        """Enriches a URL or Domain observable."""
        response = self.client.get_ipqs_info(URL_ENRICH, observable["observable_value"])
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
                f"'{observable['observable_value']}']"
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
            return (
                "Invalid/nonexistent phone number or country specified is not "
                "possible."
            )
        builder = IPQSBuilder(
            self.helper, self.author, observable, response.get("fraud_score")
        )
        description = self._format_response(self.client.phone_enrich_fields, response)
        labels = builder.phone_address_risk_scoring(
            response.get("valid"), response.get("active")
        )
        builder.create_indicator_based_on(
            labels,
            f"""[phone-number:value = '{observable["observable_value"]}']""",
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

        if credential:
            value = credential
            pattern = f"[user-account:credential = '{value}']"
            response = self.client.get_leaked_info(LEAK_PASSWORD, value)
        elif account_login:
            value = account_login
            pattern = f"[user-account:account_login = '{value}']"
            response = self.client.get_leaked_info(LEAK_USERNAME_OR_EMAIL, value)
        else:
            return (
                "User-Account observable is missing both ``account_login`` "
                "and ``credential``; nothing to enrich."
            )

        if not response:
            return "No leak data found or API error."

        exposed = bool(response.get("exposed", False))
        plain_text_password = bool(response.get("plain_text_password", False))

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
    def _process_message(self, data: Dict):
        observable = data["enrichment_entity"]
        if observable is None:
            raise ValueError(
                "Observable not found (or the connector does "
                "not has access to this observable, "
                "check the group of the connector user)",
            )
        self.helper.log_debug(f"[IPQS] starting enrichment of observable: {observable}")

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
