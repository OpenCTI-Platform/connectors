"""Connector to enrich IOCs with Recorded Future data"""

import os

import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable
from rflib import APP_VERSION, EnrichedIndicator, RFClient


class RFEnrichmentConnector:
    """Enrichment connector class"""

    def __init__(self):
        """Instantiate the connector with config variables"""
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        self.work_id = None
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

        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )

    @staticmethod
    def map_stix2_type_to_rf(entity_type):
        """
        Translates a STIX2 indicator type to its RF equivalent

        Args:
            entity_type (str): A STIX2 observable type

        Returns a Recorded Future IOC type as string
        """

        if entity_type in ("IPv4-Addr", "IPv6-Addr"):
            return "ip"
        elif entity_type == "Domain-Name":
            return "domain"
        elif entity_type == "Url":
            return "url"
        if entity_type == "StixFile":
            return "hash"
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
            self.helper.log_warning(msg)
            return msg

        # Convert to RF types
        rf_type = self.map_stix2_type_to_rf(entity_type)
        if rf_type is None:
            message = f"Recorded Future enrichment does not support type {entity_type}"
            self.helper.log_error(message)
            return [message]

        self.helper.log_info(
            "enriching observable {} with ID {}".format(observable_value, observable_id)
        )
        rf_client = RFClient(self.token, self.helper, APP_VERSION)
        reason, data = rf_client.full_enrichment(observable_value, rf_type)

        if data:
            create_indicator = data["risk"]["score"] >= self.create_indicator_threshold
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
            self.helper.log_info("Sending bundle...")
            indicator_bundle = indicator.to_json_bundle()
            if indicator_bundle:
                bundles_sent = self.helper.send_stix2_bundle(
                    indicator_bundle, update=self.update_existing_data
                )
                return f"Sent {len(bundles_sent)} stix bundle(s) for worker import"
            else:
                return "No Stix bundle(s) imported."
        else:
            return f"No Stix bundle(s) imported, request message returned ({reason})."

    def start(self):
        """Start the main loop"""
        self.helper.listen(message_callback=self._process_message)


if __name__ == "__main__":
    RF = RFEnrichmentConnector()
    RF.start()
