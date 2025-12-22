from connector.converter_to_stix import ConverterToStix
from kaspersky_client import KasperskyClient
from pycti import OpenCTIConnectorHelper


class DomainEnricher:
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        client: KasperskyClient,
        sections: str,
        zone_octi_score_mapping: dict,
        converter_to_stix: ConverterToStix,
    ):
        self.helper = helper
        self.client = client
        self.sections = sections
        self.zone_octi_score_mapping = zone_octi_score_mapping
        self.converter_to_stix = converter_to_stix

    def process_domain_enrichment(self, observable: dict) -> list:
        """
        Collect intelligence from the source for a Domain-Name/Hostname type
        """
        octi_objects = []
        self.helper.connector_logger.info("[CONNECTOR] Starting enrichment...")

        # Retrieve domain
        obs_domain = observable["value"]

        # Get entity data from api client
        self.client.get_domain_info(obs_domain, self.sections)

        return octi_objects
