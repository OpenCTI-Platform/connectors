"""Connector to enrich IOCs with Recorded Future data"""

from pycti import OpenCTIConnectorHelper
from .config_loader import ConnectorConfig
from .rf_client import RFClient, RFClientError
from .rf_to_stix2 import ConversionError, EnrichedIndicator, EnrichedVulnerability

from rflib import APP_VERSION


class RFEnrichmentConnector:
    """Enrichment connector class"""

    def __init__(self, config: ConnectorConfig, helper: OpenCTIConnectorHelper):
        """Instantiate the connector with config variables"""
        self.config = config
        self.helper = helper

        self.rf_client = RFClient(self.config.recorded_future.token, APP_VERSION)

    @staticmethod
    def to_rf_type(observable_type: str) -> str:
        """
        Translates an OCTI observable type to its RF equivalent

        Args:
            observable_type (str): An OCTI observable type

        Returns:
            Recorded Future object type as string
        """

        match observable_type:
            case "IPv4-Addr" | "IPv6-Addr":
                return "ip"
            case "Domain-Name":
                return "domain"
            case "Url":
                return "url"
            case "StixFile":
                return "hash"
            case _:
                return None

    @staticmethod
    def generate_pattern(ioc: str, data_type: str, algorithm: str = None) -> str:
        """
        Generates the appropiate STIX2 pattern for an IOC

        Args:
            ioc (str): the indicator being enriched
            data_type (str): the OpenCTI data type of the indicator
            algorithm (str): The hash algorithm, if data_type is hash

        Returns the STIX2 pattern as a string
        """

        if data_type == "StixFile":
            return f"[file:hashes.'{algorithm.lower()}' = '{ioc}']"

        return f"[{data_type.lower()}:value = '{ioc}']"

    def enrich_observable(self, rf_type: str, octi_entity: dict) -> EnrichedIndicator:
        # Extract IOC from entity data
        observable_value = octi_entity["observable_value"]
        observable_id = octi_entity["standard_id"]

        self.helper.connector_logger.info(
            "Enriching observable...",
            {"observable_id": observable_id, "observable_value": observable_value},
        )

        data = self.rf_client.get_observable_enrichment(rf_type, observable_value)

        max_risk_score = self.config.recorded_future.create_indicator_threshold
        create_indicator = data["risk"]["score"] >= max_risk_score
        indicator = EnrichedIndicator(
            type_=data["entity"]["type"],
            observable_id=observable_id,
            opencti_helper=self.helper,
            create_indicator=create_indicator,
        )
        indicator.from_json(
            name=data["entity"]["name"],
            risk=data["risk"]["score"],
            evidenceDetails=data["risk"]["evidenceDetails"],
            links=data["links"],
        )

        return indicator

    def enrich_vulnerability(self, octi_entity: dict) -> object:
        vulnerability_id = octi_entity["standard_id"]
        vulnerability_name = octi_entity["name"]

        self.helper.connector_logger.info(
            "Enriching vulnerability...",
            {
                "vulnerability_id": vulnerability_id,
                "vulnerability_name": vulnerability_name,
            },
        )

        data = self.rf_client.get_vulnerability_enrichment(vulnerability_name)

        vulnerability = EnrichedVulnerability(
            name=vulnerability_name,
            description=octi_entity["description"],
            opencti_helper=self.helper,
        )
        vulnerability.from_json(
            commonNames=data["commonNames"],
            cvss=data["cvss"],
            cvssv3=data["cvssv3"],
            cvssv4=data["cvssv4"],
            intelCard=data["intelCard"],
            lifecycleStage=data["lifecycleStage"],
        )

        return vulnerability

    def _process_message(self, data: dict) -> str | list[str]:
        """
        Listener that is triggered when someone enriches an Observable or a Vulnerability on OpenCTI.

        Notes:
            - In case of success, return a success message a string
            - In case of error, return an error message **in a list**, e.g. ["An error occured"] (backward compatibility)
        """

        try:
            enrichment_entity = data["enrichment_entity"]

            tlp = "TLP:CLEAR"
            for marking_definition in enrichment_entity["objectMarking"]:
                if marking_definition["definition_type"] == "TLP":
                    tlp = marking_definition["definition"]

            if not self.helper.check_max_tlp(
                tlp, self.config.recorded_future.info_max_tlp
            ):
                message = f"Do not send any data, TLP of the observable is ({tlp}), "
                f"which is greater than MAX TLP: ({self.config.recorded_future.info_max_tlp})"
                self.helper.connector_logger.warning(message)
                return message

            entity_type = enrichment_entity["entity_type"]

            enriched_object = None
            try:
                if entity_type == "Vulnerability":
                    enriched_object = self.enrich_vulnerability(enrichment_entity)
                elif rf_type := self.to_rf_type(entity_type):
                    enriched_object = self.enrich_observable(rf_type, enrichment_entity)
                else:
                    message = f"Recorded Future enrichment does not support type {entity_type}"
                    self.helper.connector_logger.error(message)
                    return [message]  # error message MUST be returned as a list

            except (RFClientError, ConversionError) as err:
                self.helper.connector_logger.error(err)
                return [repr(err)]  # error message MUST be returned as a list

            self.helper.connector_logger.info("Sending bundle...")

            bundle = enriched_object.to_json_bundle()
            bundles_sent = self.helper.send_stix2_bundle(bundle)

            message = f"Sent {len(bundles_sent)} stix bundle(s) for worker import"
            self.helper.connector_logger.info(message)
            return message

        except Exception as err:
            self.helper.connector_logger.error(
                "An unexpected error occured", {"error": err}
            )
            return [
                f"An unexpected error occured: {repr(err)}. "
                "See connector's log for more details."
            ]  # error message MUST be returned as a list

    def start(self):
        """Start the main loop"""
        self.helper.listen(message_callback=self._process_message)
