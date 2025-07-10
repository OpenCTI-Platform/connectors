"""Connector to enrich IOCs with Recorded Future data"""

import os
from pathlib import Path

import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable
from rflib import APP_VERSION, EnrichedIndicator, RFClient


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
    def map_octi_type_to_rf_type(entity_type: str) -> str:
        """
        Translates an OCTI entity type to its RF equivalent

        Args:
            entity_type (str): An OCTI entity type

        Returns:
            Recorded Future object type as string
        """

        match entity_type:
            case "IPv4-Addr" | "IPv6-Addr":
                return "ip"
            case "Domain-Name":
                return "domain"
            case "Url":
                return "url"
            case "StixFile":
                return "hash"

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

    def _process_message(self, data):
        """
        Listener that is triggered when someone enriches an Observable
        in the OpenCTI platform
        """

        observable = data["enrichment_entity"]
        # Extract IOC from entity data
        observable_value = observable["observable_value"]
        observable_id = observable["standard_id"]
        entity_type = observable["entity_type"]

        friendly_name = f"Enrich: {observable_value}"
        self.work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )

        tlp = "TLP:CLEAR"
        for marking_definition in observable["objectMarking"]:
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        if not self.helper.check_max_tlp(tlp, self.max_tlp):
            msg = f"Do not send any data, TLP of the observable is ({tlp}), which is greater than MAX TLP: ({self.max_tlp})"
            self.helper.connector_logger.warning(msg)
            return msg

        # Convert to RF types
        rf_type = self.map_octi_type_to_rf_type(entity_type)
        if rf_type is None:
            message = f"Recorded Future enrichment does not support type {entity_type}"
            self.helper.connector_logger.error(message)
            # Returned value should always be a string but a string is never displayed as an error in the UI.
            # But a list is displayed as en arror because it raises a BAD_USER_INPUT on OpenCTI... 🥲
            return [message]

        enriched_object = self.enrich_observable(rf_type, data=observable)
        if isinstance(enriched_object, EnrichedIndicator):
            self.helper.connector_logger.info("Sending bundle...")
            bundle = enriched_object.to_json_bundle()
            bundles_sent = self.helper.send_stix2_bundle(bundle)
            return f"Sent {len(bundles_sent)} stix bundle(s) for worker import"
        else:
            return "No Stix bundle(s) imported."

    def start(self):
        """Start the main loop"""
        self.helper.listen(message_callback=self._process_message)
