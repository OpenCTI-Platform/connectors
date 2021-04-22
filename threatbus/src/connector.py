import atexit
import json
import os
from pycti import OpenCTIConnectorHelper, get_config_variable
from sseclient import Event
from stix2 import Indicator, Sighting, parse
from threatbus.data import Operation, ThreatBusSTIX2Constants
from typing import Union
import yaml

from threatbus_connector_helper import ThreatBusConnectorHelper


class ThreatBusConnector(object):
    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        # Connector configuration
        self.entity_name = get_config_variable(
            "CONNECTOR_ENTITY_NAME", ["connector", "entity_name"], config
        )
        self.entity_desc = get_config_variable(
            "CONNECTOR_ENTITY_DESCRIPTION", ["connector", "entity_description"], config
        )
        self.threatbus_entity = None

        # Custom configuration for Threat Bus ZeroMQ-App plugin endpoint
        self.threatbus_zmq_host = get_config_variable(
            "THREATBUS_ZMQ_HOST", ["threatbus", "zmq_host"], config
        )
        self.threatbus_zmq_port = get_config_variable(
            "THREATBUS_ZMQ_PORT", ["threatbus", "zmq_port"], config
        )

        # Helper initialization
        self.opencti_helper = OpenCTIConnectorHelper(config)
        zmq_endpoint = f"{self.threatbus_zmq_host}:{self.threatbus_zmq_port}"
        self.threatbus_helper = ThreatBusConnectorHelper(
            zmq_endpoint,
            self._report_sighting,
            self.opencti_helper.log_info,
            self.opencti_helper.log_error,
            subscribe_topic="stix2/sighting",
            publish_topic="stix2/indicator",
        )

    def _get_threatbus_entity(self) -> int:
        """
        Get the Threat Bus OpenCTI entity. Creates a new entity if it does not
        exist yet.
        """

        # Use cached:
        if self.threatbus_entity is not None:
            return self.threatbus_entity

        # Try and fetch existing:
        threatbus_entity = (
            self.opencti_helper.api.stix_domain_object.get_by_stix_id_or_name(
                name=self.entity_name
            )
        )
        if threatbus_entity is not None and threatbus_entity.get("id", None):
            self.threatbus_entity = threatbus_entity
            return self.threatbus_entity

        # Create a new one:
        self.opencti_helper.log_info(
            f"Creating new OpenCTI Threat Bus entity '{self.entity_name}'"
        )
        self.threatbus_entity = self.opencti_helper.api.identity.create(
            type="Organization",
            name=self.entity_name,
            description=self.entity_desc,
        )
        return self.threatbus_entity

    def _report_sighting(self, msg: str):
        """
        Converts a JSON string to a STIX-2 Sighting and reports it to OpenCTI.
        @param msg The JSON string
        """
        try:
            sighting: Sighting = parse(msg, allow_custom=True)
        except Exception as e:
            self.opencti_helper.log_error(
                f"Error parsing message from Threat Bus. Expected a STIX-2 Sighting: {e}"
            )
            return
        if type(sighting) is not Sighting:
            self.opencti_helper.log_error(
                f"Error parsing message from Threat Bus. Expected a STIX-2 Sighting: {sighting}"
            )
            return
        entity_id = self._get_threatbus_entity().get("id", None)
        resp = self.opencti_helper.api.stix_sighting_relationship.create(
            fromId=sighting.sighting_of_ref,
            toId=entity_id,
            createdBy=entity_id,
            first_seen=sighting.first_seen.astimezone().strftime("%Y-%m-%dT%H:%M:%SZ")
            if sighting.get("first_seen")
            else None,
            last_seen=sighting.last_seen.astimezone().strftime("%Y-%m-%dT%H:%M:%SZ")
            if sighting.get("last_seen")
            else None,
            confidence=50,
            externalReferences=[sighting.sighting_of_ref],
            count=1,
        )
        self.opencti_helper.log_info(f"Created sighting {resp}")

    def _map_to_threatbus(
        self, data: dict, opencti_action: str
    ) -> Union[Indicator, None]:
        """
        Inspects the given OpenCTI data point and either returns a valid STIX-2
        Indicator or None.
        @param data A dict object with OpenCTI SSE data
        @param opencti_action A string indicating what happened to this item
            (either `create`, `update` or `delete`)
        @return a STIX-2 Indicator or None
        """
        opencti_id: str = data.get("x_opencti_id", None)
        if not opencti_id:
            self.opencti_helper.log_error(
                "Cannot process data without 'x_opencti_id' field"
            )
            return
        indicator: dict = self.opencti_helper.api.indicator.read(id=opencti_id)
        if not indicator:
            # we are only interested in indicators at this time
            return
        # overwrite custom OpenCTI ID
        indicator["id"] = indicator.get("standard_id")
        if opencti_action == "update":
            indicator[
                ThreatBusSTIX2Constants.X_THREATBUS_UPDATE.value
            ] = Operation.EDIT.value
        if opencti_action == "delete":
            indicator[
                ThreatBusSTIX2Constants.X_THREATBUS_UPDATE.value
            ] = Operation.REMOVE.value
        return Indicator(**indicator, allow_custom=True)

    def _process_message(self, sse_msg: Event):
        """
        Invoked for every incoming SSE message from the OpenCTI endpoint
        @param sse_msg: the received SSE Event
        """
        try:
            data: dict = json.loads(sse_msg.data).get("data", None)
            if not data:
                return
            indicator = self._map_to_threatbus(data, sse_msg.event)
            if not indicator:
                return
            self.threatbus_helper.send(indicator.serialize())

        except Exception as e:
            self.opencti_helper.log_error(
                f"Error forwarding indicator to Threat Bus: {e}"
            )

    def start(self):
        self.opencti_helper.log_info("Starting Threat Bus connector")

        # Fork a new Thread to communicate with Threat Bus
        self.threatbus_helper.start()
        atexit.register(self.threatbus_helper.stop)

        # Send the main loop into a busy loop for processing OpenCTI events
        self.opencti_helper.listen_stream(self._process_message)


if __name__ == "__main__":
    tb_connector = ThreatBusConnector()
    tb_connector.start()
