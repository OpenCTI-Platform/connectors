import os.path

import yaml
import json
import time
import sys
import requests

from pycti import OpenCTIConnectorHelper, get_config_variable
import logging


class HarfangLabConnector:
    def __init__(self):
        # Initialize parameters and OpenCTI helper
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        # Initialiaze the Harfang Lab API
        self.harfanglab_url = get_config_variable("HARFANGLAB_URL", ["harfanglab", "url"], config)

        # TODO is basic auth needed/used?
        self.harfanglab_ssl_verify = get_config_variable(
            "HARFLANGLAB_SSL_VERIFY", ["harfanglab", "ssl_verify"], config, False, True
        )
        self.harfanglab_token = get_config_variable(
            "HARFLANGLAB_TOKEN", ["harfanglab", "token"], config
        )
        self.harfanglab_login = get_config_variable(
            "HARFLANGLAB_LOGIN", ["harfanglab", "login"], config
        )
        self.harfanglab_password = get_config_variable(
            "HARFLANGLAB_PASSWORD", ["harfanglab", "password"], config
        )
        self.api_url = (
                self.harfanglab_url
                + "/api/data/threat_intelligence"
        )
        self.headers = {
            "Accept": "application/json",
            "Authorization": "Token " + self.harfanglab_token
        }
        self.harfanglab_source_list_name = get_config_variable(
            "HARFLANGLAB_SOURCE_LIST_NAME", ["harfanglab", "source_list_name"], config
        )
        self.harfanglab_indicator_delete = get_config_variable(
            "HARFLANGLAB_INDICATOR_DELETE", ["harfanglab", "indicator_delete"], config
        )
        self.source_list = {
            "name": self.harfanglab_source_list_name,
            "description": "Cyber Threat Intelligence knowledge imported from OpenCTI.",
            "enabled": True,
        }

        # Check Live Stream ID
        if (
                self.helper.connect_live_stream_id is None
                or self.helper.connect_live_stream_id == "ChangeMe"
        ):
            raise ValueError("Missing Live Stream ID")

        # Yara Pattern
        self.create_or_get_entity_source("YaraSource", "yara")
        # Sigma Pattern
        self.create_or_get_entity_source("SigmaSource", "sigma")
        # Stix Pattern
        self.create_or_get_entity_source("IOCSource", "stix")

    def create_or_get_entity_source(self, uri, pattern):
        response = self._query("get", f"/{uri}/", {'search': self.harfanglab_source_list_name})
        list_of_sources = response['results']

        source = self.find_source_match(list_of_sources)
        if source is None:
            create_source = self._query("post", f"/{uri}/", self.source_list)
            if pattern == 'yara':
                self.yara_list_id = create_source['id']
                return self.helper.log_info(f'Yara Source ID create = {self.yara_list_id}')
            elif pattern == 'sigma':
                self.sigma_list_id = create_source['id']
                return self.helper.log_info(f'Sigma Source ID create = {self.sigma_list_id}')
            else:
                self.stix_list_id = create_source['id']
                return self.helper.log_info(f'Stix Source ID create = {self.stix_list_id}')
        else:
            if pattern == 'yara':
                self.yara_list_id = source['id']
                return self.helper.log_info(f'Yara Source ID existing = {self.yara_list_id}')
            elif pattern == 'sigma':
                self.sigma_list_id = source['id']
                return self.helper.log_info(f'Sigma Source ID existing = {self.sigma_list_id}')
            else:
                self.stix_list_id = source['id']
                return self.helper.log_info(f'Stix Source ID existing = {self.stix_list_id}')

    def find_source_match(self, source):
        return next((x for x in source if x["name"] == self.harfanglab_source_list_name), None)

    def _process_message(self, msg):
        # _process_message
        try:
            data = json.loads(msg.data)["data"]
        except:
            raise ValueError("Cannot process the message")

        # Handle create
        if msg.event == "create":
            if data["type"] == "indicator" and data["revoked"] is False and OpenCTIConnectorHelper.get_attribute_in_extension("detection", data) is True:
                self.create_indicator(data, "yara", "YaraFile", self.yara_list_id)
                self.create_indicator(data, "sigma", "SigmaRule", self.sigma_list_id)
                self.create_indicator(data, "stix", "IOCRule", self.stix_list_id)
            return

        # Handle update
        if msg.event == "update":
            if data["type"] == "indicator":
                self.update_indicator(data, msg, "yara", "YaraFile", self.yara_list_id)
                self.update_indicator(data, msg, "sigma", "SigmaRule", self.sigma_list_id)
                self.update_indicator(data, msg, "stix", "IOCRule", self.stix_list_id)
            return

        # Handle delete
        if msg.event == "delete":
            return

    def create_indicator(self, data, pattern, uri, list_id):
        if data["pattern_type"] == f"{pattern}":
            self.helper.log_info(
                f"[CREATE] Processing {pattern} indicator" + " {"
                + OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
                + "}"
            )

            payload = self.pattern_payload(data, pattern, list_id)
            response = self._query("post", f"/{uri}/", payload)

            # TODO handle case where status contains many elements ?
            # Be careful sometimes there is a return response HarfangLab {'status':[]}
            if not response['status']:
                return self.helper.log_error(f"Error missing value")
            elif response['status'][0]['status'] is False:
                # {"ERROR", "message": "Error duplicate_rule = A rule with this ID already exists"}
                return self.helper.log_error(f"Error {response['status'][0]['code']} = {response['status'][0]['content']}")
            elif response is None:
                return self.helper.log_error(f"[CREATE] Indicator {pattern} not created")
            else:
                return self.helper.log_info(f"[CREATE] Indicator {pattern} created = {response['status'][0]['id']}")

    def update_indicator(self, data, msg, pattern, uri, list_id):
        if data["pattern_type"] == f"{pattern}":
            self.helper.log_info(
                f"[UPDATE] Processing {pattern} indicator" + " {"
                + OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
                + "}"
            )

            indicator_previous_name = json.loads(msg.data)['context']['reverse_patch'][0]['value']

            # TODO Problem
            response_name_indicator = self._query("get", f"/{uri}/?search={indicator_previous_name}")

            response_element = next((x for x in response_name_indicator['results'] if x["name"] == indicator_previous_name), None)

            if response_element is None:
                # TODO : Creates an indicator when response_element is None
                msg_log = f'[UPDATE] The searched name of the {pattern} indicator ({indicator_previous_name}) does not exist in HarfangLab'
                return self.helper.log_error(msg_log),
            else:
                response_id = response_element['id']

                payload = self.pattern_payload(data, pattern, list_id)
                response = self._query("put", f"/{uri}/{response_id}/", payload)

                # TODO handle case where status contains many elements
                if response is None:
                    return self.helper.log_error(f"[UPDATE] Indicator {pattern} not updated = {response_id}")
                else:
                    return self.helper.log_info(f"[UPDATE] Indicator {pattern} updated = {response_id}")

    def pattern_payload(self, data, pattern, list_id):
        if pattern == 'yara':
            return {
                "content": data["pattern"],
                "name": data["name"],
                "source_id": list_id,

                "enabled": True,
                "hl_local_testing_status": "in_progress",
                "hl_status": "stable"
            }
        elif pattern == 'sigma':
            return {
                "content": data["pattern"],
                "name": data["name"],
                "source_id": list_id,

                "enabled": True,
                "hl_local_testing_status": "in_progress",
                "hl_status": "stable",
                # "block_on_agent": True,
                # "rule_level_override": "critical"
            }
        elif pattern == "stix":
            return {
                # "source_id": list_id,
                # "type": ["domain_name", "filename", "filepath", "hash", "ip_both", "ip_dst", "ip_src", "url"],
                # "value": data,

                # "enabled": True,
                # "hl_local_testing_status": "in_progress",
                # "hl_status": "stable",
                # "description": "string",
                # "comment": "string",
                # "category": "string",
                # "info": "string",
                # "reference": ["string"]
            }
        else:
            raise ValueError("Unsupported Pattern")

    def _query(self, method, uri, payload=None):
        if method == "get":
            response = requests.get(
                self.api_url + uri,
                headers=self.headers,
                params=payload,
                )
        elif method == "post":
            response = requests.post(
                self.api_url + uri,
                headers=self.headers,
                json=payload,
                )
        elif method == "put":
            response = requests.put(
                self.api_url + uri,
                headers=self.headers,
                json=payload,
            )
        elif method == "delete":
            response = requests.delete(
                self.api_url + uri,
                headers=self.headers,
                json=payload,
            )
        else:
            raise ValueError("Unsupported method")
        if response.status_code == 200 or response.status_code == 201:
            try:
                return response.json()
            except:
                return response.text
        elif response.status_code == 400:
            msg_log = f"Status code 400 : Bad Request = {json.loads(response.content)}"
            return self.helper.log_error(msg_log)
        elif response.status_code == 401:
            msg_log = "Status code 401 : Query failed, permission denied"
            self.helper.log_error(msg_log)
            raise ValueError(msg_log)
        else:
            self.helper.log_info(f"{response.text}")

    def start(self):
        self.helper.listen_stream(self._process_message)


if __name__ == "__main__":
    try:
        HarfangLabInstance = HarfangLabConnector()
        HarfangLabInstance.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
