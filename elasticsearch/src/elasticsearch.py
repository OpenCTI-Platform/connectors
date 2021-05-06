################################
# Elasticsearch Connector for OpenCTI #
################################

import os
import yaml
import json
import requests

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

        self.elasticsearch_url = get_config_variable("ELASTICSEARCH_URL", ["elasticsearch", "url"], config)
        self.elasticsearch_ssl_verify = get_config_variable(
            "ELASTICSEARCH_SSL_VERIFY", ["elasticsearch", "ssl_verify"], config, False, True
        )
        self.elasticsearch_login = get_config_variable(
            "ELASTICSEARCH_LOGIN", ["elasticsearch", "login"], config
        )
        self.elasticsearch_password = get_config_variable(
            "ELASTICSEARCH_PASSWORD", ["elasticsearch", "password"], config
        )
        self.elasticsearch_owner = get_config_variable(
            "ELASTICSEARCH_OWNER", ["elasticsearch", "owner"], config
        )
        self.elasticsearch_app = get_config_variable("ELASTICSEARCH_APP", ["elasticsearch", "app"], config)

        if (
            self.helper.connect_live_stream_id is None
            or self.helper.connect_live_stream_id == "ChangeMe"
        ):
            raise ValueError("Missing Live Stream ID")

        # Initialize the KV Store
        self._query("post", "/config", {"name": self.helper.connect_live_stream_id})

    def _query(self, method, uri, payload=None, is_json=False):
        self.helper.log_info("Query " + method + " on " + uri)
        url = (
            self.elasticsearch_url
            + "/servicesNS/"
            + self.elasticsearch_owner
            + "/"
            + self.elasticsearch_app
            + "/storage/collections"
            + uri
        )
        if method == "get":
            r = requests.get(
                url,
                auth=(self.elasticsearch_login, self.elasticsearch_password),
                params=payload,
                verify=self.elasticsearch_ssl_verify,
            )
        elif method == "post":
            if is_json:
                headers = {"content-type": "application/json"}
                print(payload)
                r = requests.post(
                    url,
                    auth=(self.elasticsearch_login, self.elasticsearch_password),
                    headers=headers,
                    json=payload,
                    verify=self.elasticsearch_ssl_verify,
                )
            else:
                r = requests.post(
                    url,
                    auth=(self.elasticsearch_login, self.elasticsearch_password),
                    data=payload,
                    verify=self.elasticsearch_ssl_verify,
                )
        elif method == "delete":
            r = requests.delete(
                url,
                auth=(self.elasticsearch_login, self.elasticsearch_password),
                verify=self.elasticsearch_ssl_verify,
            )
        else:
            raise ValueError("Unsupported method")

        if r.status_code < 500:
            print(r.text)
            try:
                return r.json()
            except:
                return r.text
        else:
            self.helper.log_info(r.text)

    def _process_message(self, msg):
        try:
            data = json.loads(msg.data)["data"]
        except:
            raise ValueError("Cannot process the message: " + msg)
        # Handle creation
        if msg.event == "create":
            self.helper.log_info("[CREATE] Processing data {" + data["id"] + "}")
            data["_key"] = data["id"]
            return self._query(
                "post", "/data/" + self.helper.connect_live_stream_id, data, True
            )
        # Handle update
        if msg.event == "update":
            self.helper.log_info("[UPDATE] Processing data {" + data["id"] + "}")
            data["_key"] = data["id"]
            return self._query(
                "post",
                "/data/" + self.helper.connect_live_stream_id + "/" + data["id"],
                data,
                True,
            )
        # Handle delete
        elif msg.event == "delete":
            self.helper.log_info("[DELETE] Processing data {" + data["id"] + "}")
            return self._query(
                "delete",
                "/data/" + self.helper.connect_live_stream_id + "/" + data["id"],
                data,
            )
        return None

    def start(self):
        self.helper.listen_stream(self._process_message)


if __name__ == "__main__":
    ElasticsearchInstance = ElasticsearchConnector()
    ElasticsearchInstance.start()
