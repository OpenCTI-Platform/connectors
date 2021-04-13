import json
import os
from pycti import OpenCTIConnectorHelper, get_config_variable
from sseclient import Event
from stix2 import Indicator
from threatbus.data import Operation, ThreatBusSTIX2Constants
from typing import Union
import yaml
import zmq


class ThreatBusConnector(object):
    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        # Custom configuration for Threat Bus ZeroMQ-App plugin endpoint
        self.threatbus_zmq_host = get_config_variable(
            "THREATBUS_ZMQ_HOST", ["threatbus", "zmq_host"], config
        )
        self.threatbus_zmq_receive_port = get_config_variable(
            "THREATBUS_ZMQ_RECEIVE_PORT", ["threatbus", "zmq_receive_port"], config
        )

    def _send_to_threatbus(self, indicator: Indicator):
        """
        Sends a STIX-2 Indicator to Threat Bus. Requires the ZeroMQ App plugin
        to be installed and configured to accept data on the same port that this
        connector is instructed to use via its `config.yaml` file.
        @param indicator The STIX-2 indicator to send
        """
        socket = zmq.Context().socket(zmq.PUB)
        socket.connect(
            f"tcp://{self.threatbus_zmq_host}:{self.threatbus_zmq_receive_port}"
        )
        encoded = indicator.serialize()
        socket.send_string(f"stix2/indicator {encoded}")
        self.helper.log_info(f"Sending: {encoded}")

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
            self.helper.log_error("Cannot process data without 'x_opencti_id' field")
            return
        indicator: dict = self.helper.api.indicator.read(id=opencti_id)
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
            self._send_to_threatbus(indicator)

        except Exception as e:
            self.helper.log_error(f"Error forwarding indicator to Threat Bus: {e}")

    def start(self):
        self.helper.log_info("Starting Threat Bus connector")
        # listen to OpenCTI events of the connector's host
        self.helper.listen_stream(self._process_message)


if __name__ == "__main__":
    tb_connector = ThreatBusConnector()
    tb_connector.start()
