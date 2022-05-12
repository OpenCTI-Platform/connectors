################################
# Splunk Connector for OpenCTI #
################################

import json
import os

import requests
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable


class SplunkConnector:
    def __init__(self):
        # Initialize parameters and OpenCTI helper
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        self.splunk_url = get_config_variable("SPLUNK_URL", ["splunk", "url"], config)
        self.splunk_ssl_verify = get_config_variable(
            "SPLUNK_SSL_VERIFY", ["splunk", "ssl_verify"], config, False, True
        )
        self.splunk_login = get_config_variable(
            "SPLUNK_LOGIN", ["splunk", "login"], config
        )
        self.splunk_password = get_config_variable(
            "SPLUNK_PASSWORD", ["splunk", "password"], config
        )
        self.splunk_owner = get_config_variable(
            "SPLUNK_OWNER", ["splunk", "owner"], config
        )
        self.splunk_app = get_config_variable("SPLUNK_APP", ["splunk", "app"], config)
        self.splunk_kv_store_name = get_config_variable(
            "SPLUNK_KV_STORE_NAME", ["splunk", "kv_store_name"], config
        )

        if (
            self.helper.connect_live_stream_id is None
            or self.helper.connect_live_stream_id == "ChangeMe"
        ):
            raise ValueError("Missing Live Stream ID")

        # Initialize the KV Store
        self._query("post", "/config", {"name": self.splunk_kv_store_name})

    def _query(self, method, uri, payload=None, is_json=False):
        self.helper.log_info("Query " + method + " on " + uri)
        url = (
            self.splunk_url
            + "/servicesNS/"
            + self.splunk_owner
            + "/"
            + self.splunk_app
            + "/storage/collections"
            + uri
        )
        if method == "get":
            r = requests.get(
                url,
                auth=(self.splunk_login, self.splunk_password),
                params=payload,
                verify=self.splunk_ssl_verify,
            )
        elif method == "post":
            if is_json:
                headers = {"content-type": "application/json"}
                r = requests.post(
                    url,
                    auth=(self.splunk_login, self.splunk_password),
                    headers=headers,
                    json=payload,
                    verify=self.splunk_ssl_verify,
                )
            else:
                r = requests.post(
                    url,
                    auth=(self.splunk_login, self.splunk_password),
                    data=payload,
                    verify=self.splunk_ssl_verify,
                )
        elif method == "delete":
            r = requests.delete(
                url,
                auth=(self.splunk_login, self.splunk_password),
                verify=self.splunk_ssl_verify,
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
            self.helper.log_info(
                "[CREATE] Processing data {" + data["x_opencti_id"] + "}"
            )
            data["_key"] = data["x_opencti_id"]
            return self._query("post", "/data/" + self.splunk_kv_store_name, data, True)
        # Handle update
        if msg.event == "update":
            self.helper.log_info(
                "[UPDATE] Processing data {" + data["x_opencti_id"] + "}"
            )
            data["_key"] = data["x_opencti_id"]
            return self._query(
                "post",
                "/data/" + self.splunk_kv_store_name + "/" + data["x_opencti_id"],
                data,
                True,
            )
        # Handle delete
        elif msg.event == "delete":
            self.helper.log_info(
                "[DELETE] Processing data {" + data["x_opencti_id"] + "}"
            )
            return self._query(
                "delete",
                "/data/" + self.splunk_kv_store_name + "/" + data["x_opencti_id"],
                data,
            )
        return None

    def start(self):
        self.helper.listen_stream(self._process_message)


if __name__ == "__main__":
    SplunkInstance = SplunkConnector()
    SplunkInstance.start()
