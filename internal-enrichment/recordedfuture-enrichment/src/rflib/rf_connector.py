"""Connector to enrich IOCs with Recorded Future data"""

from connectors_sdk.models import octi
from pycti import OpenCTIConnectorHelper
from rf_client import RFClient, RFClientError, RFClientNotFoundError
from rflib import APP_VERSION

from .config_loader import ConnectorConfig
from .use_cases.enrich_observable import ObservableEnricher, ObservableEnrichmentError
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
        self.observable_enricher = ObservableEnricher(
            helper=self.helper,
            tlp_level="amber+strict",
            indicator_creation_threshold=self.config.recorded_future.create_indicator_threshold,
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

    def enrich_observable(self, octi_entity: dict) -> list[octi.BaseIdentifiedEntity]:
        observable_type = octi_entity["entity_type"]
        observable_value = octi_entity["observable_value"]
        observable_id = octi_entity["standard_id"]

        self.helper.connector_logger.info(
            "Enriching observable...",
            {
                "observable_id": observable_id,
                "observable_value": observable_value,
            },
        )

        data = self.rf_client.get_observable_enrichment(
            self.to_rf_type(observable_type),
            observable_value,
        )

        return self.observable_enricher.process_observable_enrichment(
            observable_enrichment=data,
        )

    def enrich_vulnerability(
        self, octi_entity: dict
    ) -> list[octi.BaseIdentifiedEntity]:
        vulnerability_id = octi_entity["standard_id"]
        vulnerability_name = octi_entity["name"]

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
            - In case of error, raise the error (pycti will handle it)
        """
        enrichment_completed = False  # Enrichment state flag

        original_stix_objects: list[dict] = data["stix_objects"]
        enrichment_entity: dict = data["enrichment_entity"]

        entity_type: str = enrichment_entity["entity_type"]
        entity_stix_id: str = enrichment_entity["standard_id"]

        try:
            if entity_type.lower() not in self.config.connector.scope:
                message = (
                    f"Recorded Future enrichment does not support type {entity_type}"
                )
                self.helper.connector_logger.error(message)
                raise ValueError(message)  # pycti will send it to OCTI

            tlp = "TLP:CLEAR"
            for marking_definition in enrichment_entity["objectMarking"]:
                if marking_definition["definition_type"] == "TLP":
                    tlp = marking_definition["definition"]

            if not self.helper.check_max_tlp(
                tlp, self.config.recorded_future.info_max_tlp
            ):
                message = f"Do not send any data, TLP of the entity is ({tlp}), "
                f"which is greater than MAX TLP: ({self.config.recorded_future.info_max_tlp})"
                self.helper.connector_logger.warning(
                    message,
                    {
                        "entity_type": entity_type,
                        "entity_stix_id": entity_stix_id,
                    },
                )
                return message

            octi_objects = []
            if entity_type == "Vulnerability":
                octi_objects = self.enrich_vulnerability(enrichment_entity)
            else:
                octi_objects = self.enrich_observable(enrichment_entity)

            self.helper.connector_logger.info(
                "Sending bundle...",
                {
                    "entity_type": entity_type,
                    "entity_stix_id": entity_stix_id,
                },
            )

            bundle_objects = original_stix_objects + [
                octi_object.to_stix2_object() for octi_object in octi_objects
            ]
            bundle = self.helper.stix2_create_bundle(bundle_objects)
            bundles_sent = self.helper.send_stix2_bundle(
                bundle=bundle,
                cleanup_inconsistent_bundle=True,
            )

            enrichment_completed = True

            message = f"Sent {len(bundles_sent)} stix bundle(s) for worker import"
            self.helper.connector_logger.info(
                message,
                {
                    "entity_type": entity_type,
                    "entity_stix_id": entity_stix_id,
                },
            )

            return message

        except RFClientNotFoundError as err:
            self.helper.connector_logger.warning(
                str(err),
                {
                    "entity_type": entity_type,
                    "entity_stix_id": entity_stix_id,
                    "error": err,
                },
            )
            return str(err)  # do not display error on OCTI
        except (
            RFClientError,
            ObservableEnrichmentError,
            VulnerabilityEnrichmentError,
        ) as err:
            self.helper.connector_logger.error(
                str(err),
                {
                    "entity_type": entity_type,
                    "entity_stix_id": entity_stix_id,
                    "error": err,
                },
            )
            raise err  # pycti will send it to OCTI

        except Exception as err:
            self.helper.connector_logger.error(
                "An unexpected error occured",
                {
                    "entity_type": entity_type,
                    "entity_stix_id": entity_stix_id,
                    "error": err,
                },
            )
            raise err  # pycti will send it to OCTI

        finally:
            # Ensure objects in original bundle are always sent back,
            # even if they have not been enriched (for compatibility with playbooks)
            if not enrichment_completed:
                bundle = self.helper.stix2_create_bundle(original_stix_objects)
                self.helper.send_stix2_bundle(bundle)

    def start(self):
        """Start the main loop"""
        self.helper.listen(message_callback=self._process_message)
