from connector.converter_to_stix import ConverterToStix
from connector.use_cases.common import BaseUseCases
from kaspersky_client import KasperskyClient
from pycti import OpenCTIConnectorHelper


class UrlEnricher(BaseUseCases):
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        client: KasperskyClient,
        sections: str,
        zone_octi_score_mapping: dict,
        converter_to_stix: ConverterToStix,
    ):
        BaseUseCases.__init__(self, helper, converter_to_stix)
        self.helper = helper
        self.client = client
        self.sections = sections
        self.zone_octi_score_mapping = zone_octi_score_mapping
        self.converter_to_stix = converter_to_stix

    def process_url_enrichment(self, observable: dict) -> list:
        """
        Collect intelligence from the source for an URL type
        """
        octi_objects = []
        self.helper.connector_logger.info("[CONNECTOR] Starting enrichment...")

        # Retrieve domain
        obs_domain = observable["value"]

        # Get entity data from api client
        self.client.get_url_info(obs_domain, self.sections)
        return octi_objects
