"""Connector to enrich IOCs with Recorded Future data"""

import os
from pathlib import Path

import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable
from rflib import (
    APP_VERSION,
    ConversionError,
    EnrichedIndicator,
    EnrichedVulnerability,
    RFClient,
)


class RFEnrichmentConnector:
    """Enrichment connector class"""

    def __init__(self):
        """Instantiate the connector with config variables"""
        config_file_path = Path(__file__).parents[1].joinpath("config.yml")
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        # Hardcode connector's type - not configurable anymore
        config["connector"] = config.get("connector", {})
        config["connector"]["type"] = "INTERNAL_ENRICHMENT"

        self.helper = OpenCTIConnectorHelper(config, playbook_compatible=True)

        self.token = get_config_variable(
            "RECORDED_FUTURE_TOKEN",
            ["recordedfuture-enrichment", "token"],
            config,
        )
        self.max_tlp = get_config_variable(
            "RECORDED_FUTURE_INFO_MAX_TLP",
            ["recordedfuture-enrichment", "max_tlp"],
            config,
        )

        self.create_indicator_threshold = get_config_variable(
            "RECORDED_FUTURE_CREATE_INDICATOR_THRESHOLD",
            ["recordedfuture-enrichment", "create_indicator_threshold"],
            config,
            True,
            0,
        )

        self.work_id = None

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
    def generate_pattern(ioc, data_type, algorithm=None):
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
            "enriching observable {} with ID {}".format(observable_value, observable_id)
        )
        rf_client = RFClient(self.token, self.helper, APP_VERSION)
        reason, enrichment_data = rf_client.full_enrichment(observable_value, rf_type)

        if enrichment_data:
            create_indicator = (
                enrichment_data["risk"]["score"] >= self.create_indicator_threshold
            )
            indicator = EnrichedIndicator(
                type_=enrichment_data["entity"]["type"],
                observable_id=observable_id,
                opencti_helper=self.helper,
                create_indicator=create_indicator,
            )
            indicator.from_json(
                name=enrichment_data["entity"]["name"],
                risk=enrichment_data["risk"]["score"],
                evidenceDetails=enrichment_data["risk"]["evidenceDetails"],
                links=enrichment_data["links"],
            )
            return indicator
        else:
            return f"No Stix bundle(s) imported, request message returned ({reason})."

    def enrich_vulnerability(self, octi_entity: dict) -> object:
        vulnerability_id = octi_entity["standard_id"]
        vulnerability_name = octi_entity["name"]

        self.helper.connector_logger.info(
            "enriching vulnerability {} with ID {}".format(
                vulnerability_name, vulnerability_id
            )
        )
        rf_client = RFClient(self.token, self.helper, APP_VERSION)
        reason, data = rf_client.get_vulnerability_enrichment(vulnerability_name)

        if data:
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
        else:
            return f"No Stix bundle(s) imported, request message returned ({reason})."

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

            if not self.helper.check_max_tlp(tlp, self.max_tlp):
                msg = f"Do not send any data, TLP of the observable is ({tlp}), which is greater than MAX TLP: ({self.max_tlp})"
                self.helper.connector_logger.warning(msg)
                return msg

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
                    return [message]
            except ConversionError as err:
                self.helper.connector_logger.error(err)
                return [repr(err)]

            if isinstance(enriched_object, (EnrichedIndicator, EnrichedVulnerability)):
                bundle = enriched_object.to_json_bundle()
            else:
                return "No Stix bundle(s) imported."

            self.helper.connector_logger.info("Sending bundle...")
            bundles_sent = self.helper.send_stix2_bundle(bundle)

            return f"Sent {len(bundles_sent)} stix bundle(s) for worker import"

        except Exception as err:
            self.helper.connector_logger.error(
                "An unexpected error occured", {"error": err}
            )
            return [
                f"An unexpected error occured: {repr(err)}. "
                "See connector's log for more details."
            ]

    def start(self):
        """Start the main loop"""
        self.helper.listen(message_callback=self._process_message)
