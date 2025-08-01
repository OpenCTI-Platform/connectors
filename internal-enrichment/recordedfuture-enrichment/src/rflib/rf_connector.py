"""Connector to enrich IOCs with Recorded Future data"""

from connectors_sdk.models import octi
from pycti import OpenCTIConnectorHelper
from rf_client import RFClient, RFClientError
from rflib import APP_VERSION

from .config_loader import ConnectorConfig
from .rf_to_stix2 import ConversionError, EnrichedIndicator
from .use_cases.enrich_vulnerability import (
    VulnerabilityEnricher,
    VulnerabilityEnrichmentError,
)


class RFEnrichmentConnector:
    """Enrichment connector class"""

    def __init__(self, config: ConnectorConfig, helper: OpenCTIConnectorHelper):
        """Instantiate the connector with config variables"""
        self.config = config
        self.helper = helper

        self.rf_client = RFClient(self.config.recorded_future.token, APP_VERSION)

        self.vulnerability_enricher = VulnerabilityEnricher(
            helper=self.helper, tlp_level="red"
        )

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

    def enrich_vulnerability(
        self, octi_entity: dict
    ) -> list[octi.BaseIdentifiedEntity]:
        vulnerability_id = octi_entity.get("standard_id")
        vulnerability_name = octi_entity.get("name")

        self.helper.connector_logger.info(
            "Enriching vulnerability...",
            {
                "vulnerability_id": vulnerability_id,
                "vulnerability_name": vulnerability_name,
            },
        )

        vulnerability_enrichment = self.rf_client.get_vulnerability_enrichment(
            name=vulnerability_name,
            optional_fields=self.config.recorded_future.vulnerability_enrichment_optional_fields,
        )

        return self.vulnerability_enricher.process_vulnerability_enrichment(
            octi_vulnerability_data=octi_entity,
            vulnerability_enrichment=vulnerability_enrichment,
        )

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
                message = f"Do not send any data, TLP of the entity is ({tlp}), "
                f"which is greater than MAX TLP: ({self.config.recorded_future.info_max_tlp})"
                self.helper.connector_logger.warning(message)
                return message

            entity_type = enrichment_entity["entity_type"]

            enriched_object = None
            try:
                if entity_type == "Vulnerability":
                    octi_objects = self.enrich_vulnerability(enrichment_entity)

                    self.helper.connector_logger.info("Sending bundle...")

                    bundle = self.helper.stix2_create_bundle(
                        [
                            octi_objects.to_stix2_object()
                            for octi_objects in octi_objects
                        ]
                    )
                    bundles_sent = self.helper.send_stix2_bundle(
                        bundle=bundle,
                        cleanup_inconsistent_bundle=False,  # TODO: change to True
                    )

                    message = (
                        f"Sent {len(bundles_sent)} stix bundle(s) for worker import"
                    )
                    self.helper.connector_logger.info(message)

                    return message

                elif rf_type := self.to_rf_type(entity_type):
                    enriched_object = self.enrich_observable(rf_type, enrichment_entity)

                    self.helper.connector_logger.info("Sending bundle...")

                    bundle = enriched_object.to_json_bundle()
                    bundles_sent = self.helper.send_stix2_bundle(bundle)

                    message = (
                        f"Sent {len(bundles_sent)} stix bundle(s) for worker import"
                    )
                    self.helper.connector_logger.info(message)

                    return message
                else:
                    message = f"Recorded Future enrichment does not support type {entity_type}"
                    self.helper.connector_logger.error(message)
                    return [message]  # error message MUST be returned as a list

            except (RFClientError, ConversionError) as err:
                self.helper.connector_logger.error(err)
                return [repr(err)]  # error message MUST be returned as a list

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
