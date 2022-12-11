################################
# Splunk Connector for OpenCTI #
################################

import json
import os
import queue
import threading

import requests
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable
from stix_shifter.stix_translation import stix_translation

q = queue.Queue()


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

        self.splunk_url = get_config_variable(
            "SPLUNK_URL", ["splunk", "url"], config
        ).split(",")
        self.splunk_login = get_config_variable(
            "SPLUNK_LOGIN", ["splunk", "login"], config
        ).split(",")
        self.splunk_password = get_config_variable(
            "SPLUNK_PASSWORD", ["splunk", "password"], config
        ).split(",")
        self.splunk_owner = get_config_variable(
            "SPLUNK_OWNER", ["splunk", "owner"], config
        ).split(",")
        self.splunk_ssl_verify = get_config_variable(
            "SPLUNK_SSL_VERIFY", ["splunk", "ssl_verify"], config, False, True
        )
        self.splunk_app = get_config_variable("SPLUNK_APP", ["splunk", "app"], config)
        self.splunk_kv_store_name = get_config_variable(
            "SPLUNK_KV_STORE_NAME", ["splunk", "kv_store_name"], config
        )
        self.splunk_ignore_types = get_config_variable(
            "SPLUNK_IGNORE_TYPES", ["splunk", "ignore_types"], config
        ).split(",")

        if (
            self.helper.connect_live_stream_id is None
            or self.helper.connect_live_stream_id == "ChangeMe"
        ):
            raise ValueError("Missing Live Stream ID")

        # Initialize the threads
        thread1 = threading.Thread(target=self._query_worker)
        thread2 = threading.Thread(target=self._query_worker)
        thread3 = threading.Thread(target=self._query_worker)
        thread4 = threading.Thread(target=self._query_worker)
        thread1.start()
        thread2.start()
        thread3.start()
        thread4.start()

        # Initialize the KV Store
        self._distribute_works("post", "/config", {"name": self.splunk_kv_store_name})

    def _query(
        self,
        splunk_url,
        splunk_login,
        splunk_password,
        splunk_owner,
        method,
        uri,
        payload=None,
        is_json=False,
    ):
        self.helper.log_info(
            "Query "
            + method
            + " on "
            + uri
            + " (url="
            + splunk_url
            + ", login="
            + splunk_login
            + ")"
        )
        url = (
            splunk_url
            + "/servicesNS/"
            + splunk_owner
            + "/"
            + self.splunk_app
            + "/storage/collections"
            + uri
        )
        if (
            "type" in payload
            and payload["type"] == "indicator"
            and payload["pattern_type"].startswith("stix")
        ):
            try:
                translation = stix_translation.StixTranslation()
                response = translation.translate(
                    "splunk", "query", "{}", payload["pattern"]
                )
                payload["splunk_queries"] = response
                parsed = translation.translate(
                    "splunk", "parse", "{}", payload["pattern"]
                )
                if "parsed_stix" in parsed:
                    payload["mapped_values"] = []
                    for value in parsed["parsed_stix"]:
                        formatted_value = {}
                        formatted_value[value["attribute"]] = value["value"]
                        payload["mapped_values"].append(formatted_value)
            except:
                try:
                    splitted = payload["pattern"].split(" = ")
                    key = splitted[0].replace("[", "")
                    value = splitted[1].replace("'", "").replace("]", "")
                    formatted_value = {}
                    formatted_value[key] = value
                    payload["mapped_values"] = [formatted_value]
                except:
                    payload["mapped_values"] = []
                    pass
        if method == "get":
            r = requests.get(
                url,
                auth=(splunk_login, splunk_password),
                params=payload,
                verify=self.splunk_ssl_verify,
            )
        elif method == "post":
            if is_json:
                headers = {"content-type": "application/json"}
                r = requests.post(
                    url,
                    auth=(splunk_login, splunk_password),
                    headers=headers,
                    json=payload,
                    verify=self.splunk_ssl_verify,
                )
            else:
                r = requests.post(
                    url,
                    auth=(splunk_login, splunk_password),
                    data=payload,
                    verify=self.splunk_ssl_verify,
                )
        elif method == "delete":
            r = requests.delete(
                url,
                auth=(splunk_login, splunk_password),
                verify=self.splunk_ssl_verify,
            )
        else:
            raise ValueError("Unsupported method")

        if r.status_code < 500:
            try:
                return r.json()
            except:
                return r.text
        else:
            self.helper.log_info(r.text)

    def _query_worker(self):
        while True:
            item = q.get()
            self._query(
                item["splunk_url"],
                item["splunk_login"],
                item["splunk_password"],
                item["splunk_owner"],
                item["method"],
                item["uri"],
                item["data"],
                item["is_json"],
            )
            q.task_done()

    def _distribute_works(self, method, uri, data, is_json=False):
        for x, url in enumerate(self.splunk_url):
            if (
                len(self.splunk_login) - 1 < x
                or len(self.splunk_password) - 1 < x
                or len(self.splunk_owner) - 1 < x
            ):
                raise ValueError(
                    "Login, password or owner do not have the same number of items as URLs"
                )
            item = {
                "splunk_url": url,
                "splunk_login": self.splunk_login[x],
                "splunk_password": self.splunk_password[x],
                "splunk_owner": self.splunk_owner[x],
                "method": method,
                "uri": uri,
                "data": data,
                "is_json": is_json,
            }
            q.put(item)
        return "Sent " + str(len(self.splunk_url)) + " jobs for execution"

    def _process_message(self, msg):
        try:
            data = json.loads(msg.data)["data"]
        except:
            raise ValueError("Cannot process the message: " + msg)
        # Handle creation
        if data["type"] in self.splunk_ignore_types:
            self.helper.log_info(
                "[EVENT] Ignoring received event with type " + data["type"]
            )
            return None
        if msg.event == "create":
            self.helper.log_info(
                "[CREATE] Processing data {"
                + OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
                + "}"
            )
            # Do any processing needed
            data["_key"] = OpenCTIConnectorHelper.get_attribute_in_extension("id", data)

            # Distribute the works on parallel threads for ingestion
            return self._distribute_works(
                "post", "/data/" + self.splunk_kv_store_name, data, True
            )
        # Handle update
        if msg.event == "update":
            self.helper.log_info(
                "[UPDATE] Processing data {"
                + OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
                + "}"
            )
            data["_key"] = OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
            return self._distribute_works(
                "post",
                "/data/"
                + self.splunk_kv_store_name
                + "/"
                + OpenCTIConnectorHelper.get_attribute_in_extension("id", data),
                data,
                True,
            )
        # Handle delete
        elif msg.event == "delete":
            self.helper.log_info(
                "[DELETE] Processing data {"
                + OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
                + "}"
            )
            return self._distribute_works(
                "delete",
                "/data/"
                + self.splunk_kv_store_name
                + "/"
                + OpenCTIConnectorHelper.get_attribute_in_extension("id", data),
                data,
            )
        return None

    def start(self):
        self.helper.listen_stream(self._process_message)


if __name__ == "__main__":
    SplunkInstance = SplunkConnector()
    SplunkInstance.start()
