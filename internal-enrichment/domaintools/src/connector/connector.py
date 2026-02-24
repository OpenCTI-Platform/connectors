"""DomainTools enrichment module."""

from datetime import datetime
from typing import Dict

import domaintools
import validators
from connectors_sdk.models import OrganizationAuthor
from pycti import OpenCTIConnectorHelper

from .builder import DtBuilder
from .constants import DEFAULT_RISK_SCORE, DOMAIN_FIELDS, EMAIL_FIELDS, EntityType


class DomainToolsConnector:
    """DomainTools connector."""

    _DEFAULT_AUTHOR = "DomainTools"
    _CONNECTOR_RUN_INTERVAL_SEC = 60 * 60

    def __init__(self, config, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        self.api = domaintools.api.API(
            self.config.domaintools.api_username,
            self.config.domaintools.api_key.get_secret_value(),
        )
        self.max_tlp = self.config.domaintools.max_tlp
        self.author = OrganizationAuthor(
            name=self._DEFAULT_AUTHOR,
            description="DomainTools is a leading provider of Whois and other DNS profile data for "
            "threat intelligence enrichment. It is a part of the Datacenter Group (DCL Group SA). "
            "DomainTools data helps security analysts investigate malicious activity on their networks.",
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
            builder.reset_score()
            score = entry.get("domain_risk", {}).get("risk_score", DEFAULT_RISK_SCORE)
            builder.set_score(score)
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
            domain_source_id = (
                builder.create_domain(entry["domain"])
                if opencti_entity["entity_type"] == "IPv4-Addr"
                else opencti_entity["standard_id"]
            )
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
                                ip_id, asn["value"], creation_date, expiration_date
                            )
            for category, description in DOMAIN_FIELDS.items():
                for values in entry.get(category, ()):
                    if (domain := values["domain"]["value"]) != entry["domain"]:
                        if not validators.domain(domain):
                            self.helper.metric.inc("error_count")
                            self.helper.log_warning(
                                f"[DomainTools] domain {domain} is not correctly formatted. Skipping."
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
        result = self._enrich_domaintools(builder, opencti_entity)
        self.helper.metric.state("idle")
        return result

    def _process_message(self, data: Dict):
        opencti_entity = data["enrichment_entity"]
        tlp = "TLP:CLEAR"
        for marking_definition in opencti_entity.get("objectMarking", []):
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]
        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )
        stix_objects = data["stix_objects"]
        return self._process_file(stix_objects, opencti_entity)

    def run(self):
        """Start the main loop."""
        self.helper.listen(message_callback=self._process_message)
