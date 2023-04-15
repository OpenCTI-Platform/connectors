# -*- coding: utf-8 -*-
"""IPQS enrichment module."""
from os import path

from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2 import Identity
from yaml import FullLoader, load

from .builder import IPQSBuilder
from .client import IPQSClient


class IPQSConnector:
    """IPQS connector."""

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
            "IPQS_BASE_URL", ["ipqs", "base_url"], config
        )

        self.author = Identity(
            name=self._SOURCE_NAME,
            identity_class="Organization",
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

    def _process_message(self, data):
        observable = self.helper.api.stix_cyber_observable.read(id=data["entity_id"])

        if observable is None:
            raise ValueError(
                "Observable not found (or the connector does not has access to this observable, "
                "check the group of the connector user)"
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
            case _:
                raise ValueError(
                    f'{observable["entity_type"]} is not a supported entity type.'
                )

    # Start the main loop
    def start(self):
        """Main method to start."""
        self.helper.listen(self._process_message)
