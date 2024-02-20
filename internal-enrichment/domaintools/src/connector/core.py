# -*- coding: utf-8 -*-
"""DomainTools enrichment module."""

from datetime import datetime
from pathlib import Path

import domaintools
import stix2
import validators
import yaml
from pycti import Identity, OpenCTIConnectorHelper, get_config_variable

from .builder import DtBuilder
from .constants import DEFAULT_RISK_SCORE, DOMAIN_FIELDS, EMAIL_FIELDS, EntityType


class DomainToolsConnector:
    """DomainTools connector."""

    _DEFAULT_AUTHOR = "DomainTools"
    _CONNECTOR_RUN_INTERVAL_SEC = 60 * 60

    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = Path(__file__).parent.parent.resolve() / "config.yml"
        config = (
            yaml.load(open(config_file_path, encoding="utf-8"), Loader=yaml.FullLoader)
            if config_file_path.is_file()
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config, True)

        # DomainTools
        api_username = get_config_variable(
            "DOMAINTOOLS_API_USERNAME",
            ["domaintools", "api_username"],
            config,
        )
        api_key = get_config_variable(
            "DOMAINTOOLS_API_KEY",
            ["domaintools", "api_key"],
            config,
        )
        self.api = domaintools.API(api_username, api_key)

        self.max_tlp = get_config_variable(
            "DOMAINTOOLS_MAX_TLP", ["domaintools", "max_tlp"], config
        )

        self.author = stix2.Identity(
            id=Identity.generate_id(self._DEFAULT_AUTHOR, "organization"),
            name=self._DEFAULT_AUTHOR,
            identity_class="organization",
            description=" DomainTools is a leading provider of Whois and other DNS"
            " profile data for threat intelligence enrichment."
            " It is a part of the Datacenter Group (DCL Group SA)."
            " DomainTools data helps security analysts investigate malicious"
            " activity on their networks.",
            confidence=self.helper.connect_confidence_level,
        )
        self.helper.metric.state("idle")

    def _enrich_domaintools(self, builder, opencti_entity) -> str:
        """
        Enrich observable using DomainTools API.

        The source of the relationship is always the domain-name.
        When enriching an ipv4-addr, multiple entries will be returned.
        Each entry is added as an enrichment with the domain-name as source.

        Parameters
        ----------
        builder : DtBuilder
            Builder to enrich the observable and create the bundle.
        opencti_entity: dict
            Observable received from OpenCTI.

        Returns
        -------
        str
            String informing the state of the enrichment.
        """
        self.helper.log_info("Starting enrichment using DomainTools API.")
        self.helper.log_info(f"Type of the observable: {opencti_entity['entity_type']}")
        if opencti_entity["entity_type"] == "Domain-Name":
            results = (
                self.api.iris_investigate(opencti_entity["observable_value"])
                .response()
                .get("results", ())
            )
        elif opencti_entity["entity_type"] == "IPv4-Addr":
            results = (
                self.api.iris_investigate(ip=opencti_entity["observable_value"])
                .response()
                .get("results", ())
            )
        else:
            self.helper.log_error(
                f"Entity type of the observable: {opencti_entity['entity_type']} not supported."
            )
            raise ValueError(
                f"Entity type of the observable: {opencti_entity['entity_type']} not supported."
            )

        for entry in results:
            self.helper.log_info(f"Starting enrichment of domain {entry['domain']}")
            # Retrieve common properties for all relationships.
            builder.reset_score()
            score = entry.get("domain_risk", {}).get("risk_score", DEFAULT_RISK_SCORE)
            builder.set_score(score)
            # Get the creation date / expiration date for the validity.
            creation_date = entry.get("create_date", {}).get("value", "")
            expiration_date = entry.get("expiration_date", {}).get("value", "")
            if creation_date != "" and expiration_date != "":
                creation_date = datetime.strptime(creation_date, "%Y-%m-%d")
            if expiration_date != "":
                expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")

            if creation_date >= expiration_date:
                self.helper.log_warning(
                    f"Expiration date {expiration_date} not after creation date {creation_date}, not using dates."
                )
                creation_date = ""
                expiration_date = ""

            # In case of IP enrichment, create the domain as it might not exist.
            domain_source_id = (
                builder.create_domain(entry["domain"])
                if opencti_entity["entity_type"] == "IPv4-Addr"
                else opencti_entity["standard_id"]
            )

            # Get ip
            for ip in entry.get("ip", ()):
                if "address" in ip:
                    ip_id = builder.link_domain_resolves_to(
                        domain_source_id,
                        ip["address"]["value"],
                        EntityType.IPV4,
                        creation_date,
                        expiration_date,
                        "domain-ip",
                    )
                    if ip_id is not None:
                        for asn in ip.get("asn", ()):
                            builder.link_ip_belongs_to_asn(
                                ip_id,
                                asn["value"],
                                creation_date,
                                expiration_date,
                            )

            # Get domains (name-server / mx)
            for category, description in DOMAIN_FIELDS.items():
                for values in entry.get(category, ()):
                    if (domain := values["domain"]["value"]) != entry["domain"]:
                        if not validators.domain(domain):
                            self.helper.metric.inc("error_count")
                            self.helper.log_warning(
                                f"[DomainTools] domain {domain} is not correctly "
                                "formatted. Skipping."
                            )
                            continue
                        new_domain_id = builder.link_domain_resolves_to(
                            domain_source_id,
                            domain,
                            EntityType.DOMAIN_NAME,
                            creation_date,
                            expiration_date,
                            description,
                        )
                        # Add the related ips of the name server to the newly created domain.
                        if new_domain_id is not None:
                            for ip in values.get("ip", ()):
                                builder.link_domain_resolves_to(
                                    new_domain_id,
                                    ip["value"],
                                    EntityType.IPV4,
                                    creation_date,
                                    expiration_date,
                                    f"{description}-ip",
                                )

            # Emails
            for category, description in EMAIL_FIELDS.items():
                emails = (
                    entry.get(category, ())
                    if "contact" not in category
                    else entry.get(category, {}).get("email", ())
                )
                for email in emails:
                    builder.link_domain_related_to_email(
                        domain_source_id,
                        email["value"],
                        creation_date,
                        expiration_date,
                        description,
                    )

            # Domains of emails
            for domain in entry.get("email_domain", ()):
                if domain["value"] != entry["domain"]:
                    builder.link_domain_resolves_to(
                        domain_source_id,
                        domain["value"],
                        EntityType.DOMAIN_NAME,
                        creation_date,
                        expiration_date,
                        "email_domain",
                    )

            # Redirects (red)
            if (red := entry.get("redirect_domain", {}).get("value", "")) not in (
                domain_source_id,
                "",
            ):
                builder.link_domain_resolves_to(
                    domain_source_id,
                    red,
                    EntityType.DOMAIN_NAME,
                    creation_date,
                    expiration_date,
                    "redirect",
                )

        if len(builder.bundle) > 1:
            builder.send_bundle()
            self.helper.log_info(
                f"[DomainTools] inserted {len(builder.bundle)} entries."
            )
            return f"Observable found on DomainTools, {len(builder.bundle)} knowledge attached."
        return "Observable not found on DomainTools."

    def _process_file(self, stix_objects, opencti_entity):
        self.helper.metric.state("running")
        self.helper.metric.inc("run_count")

        builder = DtBuilder(self.helper, self.author, stix_objects)

        # Enrichment using DomainTools API.
        result = self._enrich_domaintools(builder, opencti_entity)
        self.helper.metric.state("idle")
        return result

    def _process_message(self, data):
        stix_objects = data["stix_objects"]
        opencti_entity = data["opencti_entity"]

        # Extract TLP
        tlp = "TLP:CLEAR"
        for marking_definition in opencti_entity.get("objectMarking", []):
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )

        return self._process_file(stix_objects, opencti_entity)

    def start(self):
        """Start the main loop."""
        self.helper.listen(message_callback=self._process_message, auto_resolution=True)
