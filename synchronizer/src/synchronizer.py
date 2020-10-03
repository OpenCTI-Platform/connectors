################################
# OpenCTI Synchronizer         #
################################

import os
import yaml
import json

from pycti import OpenCTIConnectorHelper, get_config_variable, StixCyberObservableTypes


class SynchronizerConnector:
    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
        self.remote_opencti_url = get_config_variable(
            "REMOTE_OPENCTI_URL", ["remote_opencti", "url"], config
        )
        self.remote_opencti_token = get_config_variable(
            "REMOTE_OPENCTI_TOKEN", ["remote_opencti", "token"], config
        )
        self.remote_opencti_events = get_config_variable(
            "REMOTE_OPENCTI_EVENTS", ["remote_opencti", "events"], config
        ).split(",")

    def _process_message(self, msg):
        data = json.loads(msg.data)
        try:
            if "create" in self.remote_opencti_events and msg.event == "create":
                bundle = json.dumps({"objects": [data["data"]]})
                self.helper.send_stix2_bundle(bundle)
            elif "update" in self.remote_opencti_events and msg.event == "update":
                bundle = json.dumps({"objects": [data["data"]]})
                self.helper.send_stix2_bundle(bundle)
            elif "delete" in self.remote_opencti_events and msg.event == "delete":
                if data["data"]["type"] == "relationship":
                    self.helper.api.stix_core_relationship.delete(id=data["data"]["id"])
                elif StixCyberObservableTypes.has_value(data["data"]["type"]):
                    self.helper.api.stix_cyber_observable.delete(id=data["data"]["id"])
                else:
                    self.helper.api.stix_domain_object.delete(id=data["data"]["id"])
        except:
            pass

    def start(self):
        self.helper.listen_stream(
            self._process_message, self.remote_opencti_url, self.remote_opencti_token
        )


if __name__ == "__main__":
    SynchronizerInstance = SynchronizerConnector()
    SynchronizerInstance.start()
