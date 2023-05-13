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


def sanitize_key(key):
    """Sanitize key name for Splunk usage

    Splunk KV store keys cannot contain ".". Also, keys containing
    unusual characters like "'" make their usage less convenient
    when writing SPL queries.

    Args:
        key (str): value to sanitize

    Returns:
        str: sanitized result
    """
    return key.replace(".", ":").replace("'", "")


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
        self.splunk_token = get_config_variable(
            "SPLUNK_TOKEN", ["splunk", "token"], config
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
        splunk_token,
        splunk_owner,
        method,
        uri,
        payload=None,
        is_json=False,
    ):
        if "type" in payload and payload["type"] in self.splunk_ignore_types:
            self.helper.log_info("Ignoring " + payload["id"])
            return

        self.helper.log_info(
            "Query " + method + " on " + uri + " (url=" + splunk_url + ")"
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
        payload["stream_name"] = self.helper.get_stream_collection()["name"]
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
                        formatted_value[sanitize_key(value["attribute"])] = value[
                            "value"
                        ]
                        payload["mapped_values"].append(formatted_value)
            except:
                try:
                    splitted = payload["pattern"].split(" = ")
                    key = sanitize_key(splitted[0].replace("[", ""))
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
                headers={"Authorization": "Bearer " + splunk_token},
                params=payload,
                verify=self.splunk_ssl_verify,
            )
        elif method == "post":
            if is_json:
                r = requests.post(
                    url,
                    headers={
                        "Authorization": "Bearer " + splunk_token,
                        "content-type": "application/json",
                    },
                    json=payload,
                    verify=self.splunk_ssl_verify,
                )
            else:
                r = requests.post(
                    url,
                    headers={"Authorization": "Bearer " + splunk_token},
                    data=payload,
                    verify=self.splunk_ssl_verify,
                )
        elif method == "delete":
            r = requests.delete(
                url,
                headers={"Authorization": "Bearer " + splunk_token},
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
                item["splunk_token"],
                item["splunk_owner"],
                item["method"],
                item["uri"],
                item["data"],
                item["is_json"],
            )
            q.task_done()

    def _distribute_works(self, method, uri, data, is_json=False):
        for x, url in enumerate(self.splunk_url):
            if len(self.splunk_token) - 1 < x or len(self.splunk_owner) - 1 < x:
                raise ValueError(
                    "Token or owner do not have the same number of items as URLs"
                )
            item = {
                "splunk_url": url,
                "splunk_token": self.splunk_token[x],
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
            # Handle creation
            if msg.event == "create":
                self.helper.log_info(
                    "[CREATE] Processing data {"
                    + OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
                    + "}"
                )
                # Do any processing needed
                data["_key"] = OpenCTIConnectorHelper.get_attribute_in_extension(
                    "id", data
                )

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
                data["_key"] = OpenCTIConnectorHelper.get_attribute_in_extension(
                    "id", data
                )
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

        except Exception as e:
            self.helper.log_error("[ERROR] Failed processing data {" + str(e) + "}")
            self.helper.log_error("[ERROR] Message data {" + str(msg) + "}")
            return None

    def start(self):
        self.helper.listen_stream(self._process_message)


if __name__ == "__main__":
    SplunkInstance = SplunkConnector()
    SplunkInstance.start()
