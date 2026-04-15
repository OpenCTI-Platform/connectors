from connector.settings import ConnectorSettings
from connector.use_cases.enrich_domain import DomainEnricher
from connector.use_cases.enrich_ipv4 import Ipv4Enricher
from connectors_sdk.models import OrganizationAuthor
from criminalip_client import CriminalIpClient
from pycti import OpenCTIConnectorHelper


class CriminalIPConnector:
    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        self.token = self.config.criminal_ip.token.get_secret_value()
        self.max_tlp = self.config.criminal_ip.max_tlp
        self.client = CriminalIpClient(helper=self.helper, token=self.token)

        self.author = OrganizationAuthor(
            name="Criminal IP",
            description="Criminal IP Cyber Threat Intelligence",
        )

        self.domain_enricher = DomainEnricher(
            connector_logger=self.helper.connector_logger,
            client=self.client,
            author=self.author,
        )
        self.ipv4_enricher = Ipv4Enricher(
            connector_logger=self.helper.connector_logger,
            client=self.client,
            author=self.author,
        )

    def _extract_and_check_markings(self, entity):
        tlp = "TLP:CLEAR"
        for marking_definition in entity.get("objectMarking", []):
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        is_valid = OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp)
        if not is_valid:
            raise ValueError(
                "[CONNECTOR] TLP of the observable is greater than MAX TLP,"
                " skipping enrichment"
            )
        return tlp

    def process_message(self, data: dict) -> str:
        try:
            opencti_entity = data["enrichment_entity"]
            self._extract_and_check_markings(opencti_entity)

            stix_objects = data["stix_objects"]
            stix_entity = data["stix_entity"]

            obs_value = stix_entity["value"]
            obs_type = stix_entity["type"]

            self.helper.connector_logger.info(
                "[CONNECTOR] Processing entity",
                {"type": obs_type, "value": obs_value},
            )

            # Add author to bundle
            enrichment_objects = [self.author.to_stix2_object()]

            if obs_type == "ipv4-addr":
                enrichment_objects += self.ipv4_enricher.process_ipv4_enrichment(
                    obs_value
                )

            elif obs_type == "domain-name":
                enrichment_objects += self.domain_enricher.process_domain_scan(
                    obs_value
                )

            else:
                return f"[CONNECTOR] Unsupported type: {obs_type}"

            if len(enrichment_objects) <= 1:  # only author, no real data
                return f"[CONNECTOR] No enrichment data found for {obs_value}"

            # Merge with existing stix objects and send
            all_objects = stix_objects + enrichment_objects
            bundle = self.helper.stix2_create_bundle(all_objects)
            bundles_sent = self.helper.send_stix2_bundle(bundle)

            self.helper.connector_logger.info(
                "[CONNECTOR] Enrichment complete",
                {"bundles_sent": len(bundles_sent), "value": obs_value},
            )
            return f"Sent {len(bundles_sent)} bundle(s) for import"

        except Exception as e:
            self.helper.connector_logger.error(
                "[CONNECTOR] Error during enrichment",
                {"error_message": str(e)},
            )
            # Send back original objects for playbook compatibility
            self.helper.send_stix2_bundle(
                self.helper.stix2_create_bundle(data["stix_objects"])
            )
            raise e

    def run(self) -> None:
        self.helper.listen(message_callback=self.process_message)
