"""IPQS enrichment module."""

from os import path
from pathlib import Path
from typing import Dict

import pycti
from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2 import Identity
from yaml import FullLoader, load

from .builder import IPQSBuilder
from .client import IPQSClient
from .constants import (
    SOURCE_NAME,
    IP_ENRICH,
    URL_ENRICH,
    EMAIL_ENRICH,
    PHONE_ENRICH,
    LEAK_ENRICH_USERNAME,
    LEAK_ENRICH_PASSWORD,
)


class IPQSConnector:
    """IPQS connector."""

    def __init__(self) -> None:

        # Instantiate the connector helper from config
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

    def format_response(self, enrich_fields, response):
        """Function to format the response parameters"""
        return "\n".join(
            f"- **{enrich_field_value}:**    {response.get(enrich_field)} "
            for enrich_field, enrich_field_value in enrich_fields.items()
            if enrich_field in response
        )

    def _process_ip(self, observable):
        """Enriches the IP."""
        response = self.client.get_ipqs_info(
            IP_ENRICH,
            observable["observable_value"],
        )

        builder = IPQSBuilder(
            self.helper,
            self.author,
            observable,
            response.get("fraud_score"),
        )

        if self.ip_add_relationships:
            builder.create_asn_belongs_to(response.get("ASN"))

        res_format = self.format_response(self.client.ip_enrich_fields, response)

        labels = builder.ip_address_risk_scoring()

        builder.create_indicator_based_on(
            labels,
            f"""[ipv4-addr:value = '{observable["observable_value"]}']""",
            observable["observable_value"],
            res_format,
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

        res_format = self.format_response(self.client.email_enrich_fields, response)

        labels = builder.email_address_risk_scoring(
            response.get("disposable"),
            response.get("valid"),
        )

        builder.create_indicator_based_on(
            labels,
            f"""[email-addr:value = '{observable["observable_value"]}']""",
            observable["observable_value"],
            res_format,
        )

        return builder.send_bundle()

    def _process_url(self, observable):
        """Enriches URL."""
        response = self.client.get_ipqs_info(
            URL_ENRICH,
            observable["observable_value"],
        )

        builder = IPQSBuilder(
            self.helper,
            self.author,
            observable,
            response.get("risk_score"),
        )

        if self.domain_add_relationships and observable["entity_type"] == "Domain-Name":
            if response.get("ip_address") != "N/A":
                builder.create_ip_resolves_to(response.get("ip_address"))

        res_format = self.format_response(self.client.url_enrich_fields, response)

        labels = builder.url_risk_scoring(
            response.get("malware"),
            response.get("phishing"),
        )

        builder.create_indicator_based_on(
            labels,
            f"""[{observable["entity_type"].lower()}:
            value = '{observable["observable_value"]}']""",
            observable["observable_value"],
            res_format,
        )

        return builder.send_bundle()

    def _process_phone(self, observable):
        """Enriches Phone Numbers."""

        response = self.client.get_ipqs_info(
            PHONE_ENRICH,
            observable["observable_value"],
        )

        if response is None:
            return "Invalid/nonexistent phone number or country specified is not possible."
        else:
            builder = IPQSBuilder(
                self.helper,
                self.author,
                observable,
                response.get("fraud_score"),
            )

            res_format = self.format_response(self.client.phone_enrich_fields, response)

            labels = builder.phone_address_risk_scoring(
                response.get("valid"),
                response.get("active"),
            )

            builder.create_indicator_based_on(
                labels,
                f"""[phone-number:value = '{observable["observable_value"]}']""",
                observable["observable_value"],
                res_format,
            )

            return builder.send_bundle()

    def _process_leak(self, observable):
        """Enriches Leak Email, Username and Password."""
        data = observable.get("credential")
        if data == "":
            value = observable["account_login"]
            pattern = f"[user-account:account_login = '{value}']"
            response = self.client.get_dark_info(LEAK_ENRICH_USERNAME, value)
        else:
            value = observable["credential"]
            pattern = f"[user-account:credential = '{value}']"
            response = self.client.get_dark_info(LEAK_ENRICH_PASSWORD, value)
        if not response:
            return "No leak data found or API error."
        exposed = bool(response.get("exposed", False))
        plain_text_password = bool(response.get("plain_text_password", False))
        src = response.get("source")
        if isinstance(src, list):
            sources_list = src
        elif src in (None, ""):
            sources_list = []
        else:
            sources_list = [str(src)]
        first_seen = response.get("first_seen") or {}

        # Score policy: exposed or plain-text password => 100 else 0
        score = 100 if exposed or plain_text_password else 0

        builder = IPQSBuilder(self.helper, self.author, observable, score)

        # Build concise description
        fields = []

        def add(label, val):
            """Leak API response Params"""
            fields.append(f"- {label}: {val}") if val else None

        add("Success", response.get("success"))
        add("Exposed", exposed)
        add("Plain Text Password", plain_text_password)
        if sources_list:
            add("Source", ", ".join(map(str, sources_list)))
        if isinstance(first_seen, dict):
            parts = []
            if first_seen.get("human"):
                parts.append(f"human={first_seen['human']}")
            if first_seen.get("iso"):
                parts.append(f"iso={first_seen['iso']}")
            if first_seen.get("timestamp") is not None:
                parts.append(f"timestamp={first_seen['timestamp']}")
            if parts:
                add("First Seen", "; ".join(parts))
        if response.get("message"):
            add("Message", response.get("message"))

        res_format = "\n".join(fields) if fields else "- No leak details available"

        # Verdict label
        labels = builder.leak_risk_scoring(exposed, plain_text_password)

        builder.create_indicator_based_on(
            labels=labels,
            pattern=pattern,
            indicator_value=value,
            description=res_format,
        )

        return builder.send_bundle()

    def _process_message(self, data: Dict):
        observable = data["enrichment_entity"]

        if observable is None:
            raise ValueError(
                "Observable not found (or the connector does "
                "not has access to this observable, "
                "check the group of the connector user)",
            )
        self.helper.log_debug(
            f"[IPQS] starting enrichment of observable:" f" {observable}"
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
                    f'{observable["entity_type"]} ' f"is not a supported entity type."
                )

    # Start the main loop
    def start(self) -> None:
        """Start the main loop."""
        self.helper.listen(message_callback=self._process_message)
