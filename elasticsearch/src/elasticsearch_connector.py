#######################################
# Elasticsearch Connector for OpenCTI #
#######################################

import os
import yaml
import json

from elasticsearch import Elasticsearch
from pycti import OpenCTIConnectorHelper, get_config_variable


class ElasticsearchConnector:
    def __init__(self):
        # Initialize parameters and OpenCTI helper
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        self.elasticsearch_url = get_config_variable(
            "ELASTICSEARCH_URL", ["elasticsearch", "url"], config
        )
        self.elasticsearch_ssl_verify = get_config_variable(
            "ELASTICSEARCH_SSL_VERIFY",
            ["elasticsearch", "ssl_verify"],
            config,
            False,
            True,
        )
        self.elasticsearch_login = get_config_variable(
            "ELASTICSEARCH_LOGIN", ["elasticsearch", "login"], config
        )
        self.elasticsearch_password = get_config_variable(
            "ELASTICSEARCH_PASSWORD", ["elasticsearch", "password"], config
        )
        self.elasticsearch_index = get_config_variable(
            "ELASTICSEARCH_INDEX", ["elasticsearch", "index"], config
        )

        if (
            self.helper.connect_live_stream_id is None
            or self.helper.connect_live_stream_id == "ChangeMe"
        ):
            raise ValueError("Missing Live Stream ID")

        # Initilize connection to Elastic
        if (
            self.elasticsearch_login is not None
            and len(self.elasticsearch_login) > 0
            and self.elasticsearch_password is not None
            and len(self.elasticsearch_password) > 0
        ):
            self.elasticsearch = Elasticsearch(
                [self.elasticsearch_url],
                verify_certs=self.elasticsearch_ssl_verify,
                http_auth=(
                    self.elasticsearch_login,
                    self.elasticsearch_password,
                ),
            )
        else:
            self.elasticsearch = Elasticsearch(
                [self.elasticsearch_url],
                verify_certs=self.elasticsearch_ssl_verify,
            )

    def _index(self, payload):
        self.elasticsearch.index(
            index=self.elasticsearch_index, id=payload["id"], body=payload
        )

    def _delete(self, id):
        self.elasticsearch.delete(index=self.elasticsearch_index, id=id)

    def _process_message(self, msg):
        try:
            data = json.loads(msg.data)["data"]
        except:
            raise ValueError("Cannot process the message: " + msg)
        # Handle creation
        if msg.event == "create":
            self.helper.log_info("[CREATE] Processing data {" + data["id"] + "}")
            return self._index(data)
        # Handle update
        if msg.event == "update":
            self.helper.log_info("[UPDATE] Processing data {" + data["id"] + "}")
            return self._index(data)
        # Handle delete
        elif msg.event == "delete":
            self.helper.log_info("[DELETE] Processing data {" + data["id"] + "}")
            return self._delete(data["id"])
        return None

    def start(self):
        self.helper.listen_stream(self._process_message)


if __name__ == "__main__":
    ElasticsearchInstance = ElasticsearchConnector()
    ElasticsearchInstance.start()
