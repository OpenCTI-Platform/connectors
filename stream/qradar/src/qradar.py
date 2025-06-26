################################
# Qradar Connector for OpenCTI #
################################

import json
import logging
import os
import sys
import time

import requests
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable
from stix_shifter.stix_translation import stix_translation


def fix_loggers() -> None:
    logging.getLogger(
        "stix_shifter_modules.splunk.stix_translation.query_translator"
    ).setLevel(logging.CRITICAL)
    logging.getLogger("stix_shifter.stix_translation.stix_translation").setLevel(
        logging.CRITICAL
    )
    logging.getLogger(
        "stix_shifter_utils.stix_translation.stix_translation_error_mapper"
    ).setLevel(logging.CRITICAL)


class QRadarConnector:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        # Configuration
        self.helper = OpenCTIConnectorHelper(config)
        self.qradar_url = get_config_variable("QRADAR_URL", ["qradar", "url"], config)
        self.qradar_ssl_verify = get_config_variable(
            "QRADAR_SSL_VERIFY", ["qradar", "ssl_verify"], config, default=True
        )
        self.qradar_token = get_config_variable(
            "QRADAR_TOKEN", ["qradar", "token"], config
        )
        self.qradar_reference_name = get_config_variable(
            "QRADAR_REFERENCE_NAME",
            ["qradar", "reference_name"],
            config,
            default="OpenCTI",
        )

        self.base_url_sets = self.qradar_url + "/api/reference_data_collections/sets"
        self.base_url_set_entries = (
            self.qradar_url + "/api/reference_data_collections/set_entries"
        )
        self.headers = {"SEC": self.qradar_token}

        try:
            self._initialize_reference_sets()
        except Exception as ex:
            self.helper.connector_logger.error(
                "Unable to initialize collection sets, shutting down { "
                + str(ex)
                + " }"
            )
            sys.exit(0)

    def _initialize_reference_sets(self):
        """
        :return:
        """
        # Collections sets
        self.collection_sets = {
            "ipv4-addr": {
                "name": self.qradar_reference_name + " - " + "IPv4 Addresses",
                "type": "IP",
                "qradar_id": None,
            },
            "ipv6-addr": {
                "name": self.qradar_reference_name + " - " + "IPv6 Addresses",
                "type": "ALNIC",
                "qradar_id": None,
            },
            "domain-name": {
                "name": self.qradar_reference_name + " - " + "Domain Names",
                "type": "ALNIC",
                "qradar_id": None,
            },
            "hostname": {
                "name": self.qradar_reference_name + " - " + "Hostnames",
                "type": "ALNIC",
                "qradar_id": None,
            },
            "url": {
                "name": self.qradar_reference_name + " - " + "URLs",
                "type": "ALNIC",
                "qradar_id": None,
            },
            "email-addr": {
                "name": self.qradar_reference_name + " - " + "Email Addresses",
                "type": "ALNIC",
                "qradar_id": None,
            },
            "file-md5": {
                "name": self.qradar_reference_name + " - " + "MD5 File Hashes",
                "type": "ALNIC",
                "qradar_id": None,
            },
            "file-sha1": {
                "name": self.qradar_reference_name + " - " + "SHA1 File Hashes",
                "type": "ALNIC",
                "qradar_id": None,
            },
            "file-sha256": {
                "name": self.qradar_reference_name + " - " + "SHA256 File Hashes",
                "type": "ALNIC",
                "qradar_id": None,
            },
            "file-sha512": {
                "name": self.qradar_reference_name + " - " + "SHA512 File Hashes",
                "type": "ALNIC",
                "qradar_id": None,
            },
        }

        # Initialize OpenCTI collection sets
        r = requests.get(
            url=self.base_url_sets, headers=self.headers, verify=self.qradar_ssl_verify
        )
        r.raise_for_status()
        data = r.json()
        for key in self.collection_sets.keys():
            already_exist = False
            for collection_set in data:
                if collection_set["name"] == self.collection_sets[key]["name"]:
                    self.collection_sets[key]["qradar_id"] = collection_set["id"]
                    already_exist = True
            if not already_exist:
                r = requests.post(
                    url=self.base_url_sets,
                    json={
                        "name": self.collection_sets[key]["name"],
                        "entry_type": self.collection_sets[key]["type"],
                    },
                    headers=self.headers,
                    verify=self.qradar_ssl_verify,
                )
                r.raise_for_status()
                result = r.json()
                self.collection_sets[key]["qradar_id"] = result["id"]

    def _search_object(self, collection_set_id, internal_id):
        r = requests.get(
            url=self.base_url_set_entries,
            params={
                "filter": "collection_id="
                + str(collection_set_id)
                + ' and notes="'
                + internal_id
                + '"'
            },
            headers=self.headers,
            verify=self.qradar_ssl_verify,
        )
        r.raise_for_status()
        result = r.json()
        if len(result) > 0:
            return result[0]
        else:
            return None

    def _create_object(self, collection_set_id, data):
        internal_id = OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
        try:
            external_references = OpenCTIConnectorHelper.get_attribute_in_extension(
                "external_references", data
            )
            if external_references is not None and len(external_references) > 0:
                source = external_references[0]["source_name"]
            else:
                source = "OpenCTI"
            body = {
                "collection_id": collection_set_id,
                "notes": internal_id,
                "source": source,
                "value": data["value"],
            }
            r = requests.post(
                url=self.base_url_set_entries,
                json=body,
                headers=self.headers,
                verify=self.qradar_ssl_verify,
            )
            r.raise_for_status()
        except Exception as ex:
            self.helper.connector_logger.error(
                "[Creating] Failed processing data { " + str(ex) + " }"
            )

    def _update_object(self, collection_set_id, data):
        internal_id = OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
        try:
            resolved_object = self._search_object(collection_set_id, internal_id)
            if resolved_object is not None:
                external_references = OpenCTIConnectorHelper.get_attribute_in_extension(
                    "external_references", data
                )
                if external_references is not None and len(external_references) > 0:
                    source = "OpenCTI - " + external_references[0]["source_name"]
                else:
                    source = "OpenCTI"
                body = {
                    "collection_id": collection_set_id,
                    "notes": internal_id,
                    "source": source,
                    "value": data["value"],
                }
                r = requests.post(
                    url=self.base_url_set_entries + "/" + str(resolved_object["id"]),
                    json=body,
                    headers=self.headers,
                    verify=self.qradar_ssl_verify,
                )
                r.raise_for_status()
        except Exception as ex:
            self.helper.connector_logger.error(
                "[Updating] Failed processing data { " + str(ex) + " }"
            )

    def _delete_object(self, collection_set_id, data):
        internal_id = OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
        try:
            resolved_object = self._search_object(collection_set_id, internal_id)
            if resolved_object is not None:
                r = requests.delete(
                    url=self.base_url_set_entries + "/" + str(resolved_object["id"]),
                    headers=self.headers,
                    verify=self.qradar_ssl_verify,
                )
                r.raise_for_status()
        except Exception as ex:
            self.helper.connector_logger.error(
                "[Deleting] Failed processing data { " + str(ex) + " }"
            )

    def _process_indicator(self, data):
        final_data = []
        internal_id = OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
        try:
            translation = stix_translation.StixTranslation()
            parsed = translation.translate("splunk", "parse", "{}", data["pattern"])
            if "parsed_stix" in parsed:
                results = parsed["parsed_stix"]
                for result in results:
                    result_data = data.copy()
                    stix_value = result["value"]
                    if result["attribute"] in [
                        "domain-name:value",
                        "hostname:value",
                        "ipv4-addr:value",
                        "ipv6-addr:value",
                        "url:value",
                        "email-addr:value",
                    ]:
                        stix_type = result["attribute"].replace(":value", "")
                        result_data["type"] = stix_type
                        result_data["value"] = stix_value
                        final_data.append(result_data)
                    elif result["attribute"] == "file:hashes.MD5":
                        result_data["type"] = "file-md5"
                        result_data["value"] = stix_value
                        final_data.append(result_data)
                    elif result["attribute"] == "file:hashes.'SHA-1'":
                        result_data["type"] = "file-sha1"
                        result_data["value"] = stix_value
                        final_data.append(result_data)
                    elif result["attribute"] == "file:hashes.'SHA-256'":
                        result_data["type"] = "file-sha256"
                        result_data["value"] = stix_value
                        final_data.append(result_data)
                    elif result["attribute"] == "file:hashes.'SHA-512'":
                        result_data["type"] = "file-sha512"
                        result_data["value"] = stix_value
                        final_data.append(result_data)
                return final_data
        except:
            self.helper.connector_logger.warning(
                "[Processing] Cannot convert STIX indicator { " + internal_id + "}"
            )
            return []

    def _process_message(self, msg):
        try:
            data = json.loads(msg.data)["data"]
            if data["type"] == "indicator" and data["pattern_type"].startswith("stix"):
                indicator_data = self._process_indicator(data)
            elif data["type"] == "file":
                indicator_data = []
                if "hashes" in data and "MD5" in data["hashes"]:
                    data_md5 = data.copy()
                    data_md5["type"] = "file-md5"
                    data_md5["value"] = data["hashes"]["MD5"]
                    indicator_data.append(data_md5)
                if "hashes" in data and "SHA-1" in data["hashes"]:
                    data_sha1 = data.copy()
                    data_sha1["type"] = "file-sha1"
                    data_sha1["value"] = data["hashes"]["SHA-1"]
                    indicator_data.append(data_sha1)
                if "hashes" in data and "SHA-256" in data["hashes"]:
                    data_sha256 = data.copy()
                    data_sha256["type"] = "file-sha256"
                    data_sha256["value"] = data["hashes"]["SHA-256"]
                    indicator_data.append(data_sha256)
                if "hashes" in data and "SHA-512" in data["hashes"]:
                    data_sha512 = data.copy()
                    data_sha512["type"] = "file-sha512"
                    data_sha512["value"] = data["hashes"]["SHA-512"]
                    indicator_data.append(data_sha512)
            else:
                indicator_data = [data]

            for d in indicator_data:
                if d["type"] in [
                    "ipv4-addr",
                    "ipv6-addr",
                    "domain-name",
                    "hostname",
                    "url",
                    "email-addr",
                    "file",
                    "file-md5",
                    "file-sha1",
                    "file-sha256",
                    "file-sha512",
                ]:
                    # Resolve the collection set
                    collection_set_id = None
                    if (
                        d["type"] in self.collection_sets
                        and self.collection_sets[d["type"]]["qradar_id"] is not None
                    ):
                        collection_set_id = self.collection_sets[d["type"]]["qradar_id"]

                    if collection_set_id is None:
                        self.helper.connector_logger.error(
                            "[Processing] Cannot find the QRadar collection set for { "
                            + d["type"]
                            + " }"
                        )
                    else:
                        if msg.event == "create":
                            self._create_object(collection_set_id, d)
                        elif msg.event == "update":
                            self._update_object(collection_set_id, d)
                        elif msg.event == "delete":
                            self._delete_object(collection_set_id, d)
        except Exception as ex:
            self.helper.connector_logger.error(
                "[Processing] Failed processing data { " + str(ex) + " }"
            )
            self.helper.connector_logger.error(
                "[Processing] Message data { " + str(msg) + " }"
            )
            return None

    def start(self):
        self.helper.listen_stream(self._process_message)


if __name__ == "__main__":
    fix_loggers()
    try:
        connector = QRadarConnector()
        connector.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
