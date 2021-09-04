################################
# OpenCTI Synchronizer         #
################################

import os
import yaml
import json

from pycti import OpenCTIConnectorHelper, get_config_variable


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
        self.remote_opencti_live_stream_id = get_config_variable(
            "REMOTE_OPENCTI_LIVE_STREAM_ID",
            ["remote_opencti", "live_stream_id"],
            config,
        )
        self.remote_opencti_ssl_verify = get_config_variable(
            "REMOTE_OPENCTI_SSL_VERIFY", ["remote_opencti", "ssl_verify"], config
        )
        self.remote_opencti_token = get_config_variable(
            "REMOTE_OPENCTI_TOKEN", ["remote_opencti", "token"], config
        )
        self.remote_opencti_start_timestamp = get_config_variable(
            "REMOTE_OPENCTI_START_TIMESTAMP",
            ["remote_opencti", "start_timestamp"],
            config,
        )

    def _process_message(self, msg):
        if (
            msg.event == "create"
            or msg.event == "update"
            or msg.event == "merge"
            or msg.event == "delete"
        ):
            self.helper.log_info("Processing event " + msg.id)
            data = json.loads(msg.data)
            if msg.event == "create":
                bundle = {
                    "type": "bundle",
                    "x_opencti_event_version": data["version"],
                    "objects": [data["data"]],
                }
                self.helper.api.stix2.import_bundle(bundle, True)
            elif msg.event == "update":
                bundle = {
                    "type": "bundle",
                    "x_opencti_event_version": data["version"],
                    "objects": [data["data"]],
                }
                self.helper.api.stix2.import_bundle(bundle, True)
            elif msg.event == "merge":
                sources = data["data"]["x_opencti_context"]["sources"]
                object_ids = list(map(lambda element: element["id"], sources))
                self.helper.api.stix_core_object.merge(
                    id=data["data"]["id"], object_ids=object_ids
                )
            elif msg.event == "delete":
                self.helper.api.stix.delete(id=data["data"]["id"])

    def start(self):
        self.helper.listen_stream(
            self._process_message,
            self.remote_opencti_url,
            self.remote_opencti_token,
            self.remote_opencti_ssl_verify,
            self.remote_opencti_start_timestamp,
            self.remote_opencti_live_stream_id,
        )


if __name__ == "__main__":
    SynchronizerInstance = SynchronizerConnector()
    SynchronizerInstance.start()
