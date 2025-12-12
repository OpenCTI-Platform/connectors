from connector.converter_to_stix import ConverterToStix
from connector.utils import check_quota
from kaspersky_client import KasperskyClient
from pycti import OpenCTIConnectorHelper


class Ipv4Enricher:
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

    def process_ipv4_enrichment(self, observable: dict) -> list:
        """
        Collect intelligence from the source for an IPV4 type
        """
        octi_objects = []
        self.helper.connector_logger.info("[CONNECTOR] Starting enrichment...")

        # Retrieve ipv4
        obs_ipv4 = observable["value"]

        # Get entity data from api client
        entity_data = self.client.get_ipv4_info(obs_ipv4, self.sections)

        # Check Quota
        if check_quota(entity_data["LicenseInfo"]):
            self.helper.connector_logger.warning(
                "[CONNECTOR] The daily quota has been exceeded",
                {
                    "day_requests": entity_data["LicenseInfo"]["DayRequests"],
                    "day_quota": entity_data["LicenseInfo"]["DayQuota"],
                },
            )

        return octi_objects
