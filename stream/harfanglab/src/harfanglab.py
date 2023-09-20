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
        self.harfanglab_rule_maturity = get_config_variable(
            "HARFLANGLAB_RULE_MATURITY", ["harfanglab", "rule_maturity"], config
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

        source = self.find_data_name_match(list_of_sources, self.harfanglab_source_list_name)
        if source is None:
            create_source = self._query("post", f"/{uri}/", self.source_list)
            if pattern == 'yara':
                self.yara_list_id = create_source['id']
                return self.helper.log_info(f'Yara Source ID create = {self.yara_list_id}')
            elif pattern == 'sigma':
                self.sigma_list_id = create_source['id']
                return self.helper.log_info(f'Sigma Source ID create = {self.sigma_list_id}')
            elif pattern == 'stix':
                self.stix_list_id = create_source['id']
                return self.helper.log_info(f'Stix Source ID create = {self.stix_list_id}')
            else:
                raise ValueError("Unsupported Pattern Type")
        else:
            if pattern == 'yara':
                self.yara_list_id = source['id']
                return self.helper.log_info(f'Yara Source ID existing = {self.yara_list_id}')
            elif pattern == 'sigma':
                self.sigma_list_id = source['id']
                return self.helper.log_info(f'Sigma Source ID existing = {self.sigma_list_id}')
            elif pattern == 'stix':
                self.stix_list_id = source['id']
                return self.helper.log_info(f'Stix Source ID existing = {self.stix_list_id}')
            else:
                raise ValueError("Unsupported Pattern Type")

    def _process_message(self, msg):
        try:
            data = json.loads(msg.data)["data"]
            entity = self.helper.api.indicator.read(
                id=OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
            )

        except:
            raise ValueError("Cannot process the message")

        # Handle create
        if msg.event == "create":
            if data["type"] == "indicator": #and data["revoked"] is False and OpenCTIConnectorHelper.get_attribute_in_extension("detection", data) is True:
                if data['pattern_type'] == "yara":
                    self.create_indicator(data, "yara", "YaraFile")
                elif data['pattern_type'] == "sigma":
                    self.create_indicator(data, "sigma", "SigmaRule")
                elif data['pattern_type'] == "stix":
                    self.create_observable(entity, "stix", "IOCRule")
                else:
                    raise ValueError("Unsupported Pattern Type")
            return

        # Handle update
        if msg.event == "update":
            if data["type"] == "indicator":
                if data['pattern_type'] == "yara":
                    self.update_indicator(data, msg, "yara", "YaraFile", self.yara_list_id)
                elif data['pattern_type'] == "sigma":
                    self.update_indicator(data, msg, "sigma", "SigmaRule", self.sigma_list_id)
                elif data['pattern_type'] == "stix":
                    self.update_indicator(data, msg, "stix", "IOCRule", self.stix_list_id)
                else:
                    raise ValueError("Unsupported Pattern Type")
            return

        # Handle delete
        if msg.event == "delete":
            if data["type"] == "indicator":
                if data['pattern_type'] == "yara":
                    self.delete_indicator(data, "yara", "YaraFile")
                elif data['pattern_type'] == "sigma":
                    self.delete_indicator(data, "sigma", "SigmaRule")
                elif data['pattern_type'] == "stix":
                    self.delete_indicator(data, "stix", "IOCRule")
                else:
                    raise ValueError("Unsupported Pattern")
            return

    def create_observable(self, entity, pattern, uri):
        if entity["pattern_type"] == f"{pattern}":
            self.helper.log_info(f"[CREATE] Processing {pattern} observable" + " {" + entity['id'] + "}")

        observables = entity['observables']
        if not observables:
            return self.helper.log_error(f"[CREATE] The indicator has no observable, creation failure")
        for observable in observables:
            if observable['entity_type'] == "StixFile" or observable['entity_type'] == "Artifact":
                observable['entity_type'] = 'hash'
            elif observable['entity_type'] == "Domain-Name" or observable['entity_type'] == "Hostname":
                observable['entity_type'] = 'domain_name'
            elif observable['entity_type'] == "IPv4-Addr" or observable['entity_type'] == "IPv6-Addr":
                observable['entity_type'] = 'ip_both'
            elif observable['entity_type'] == "Url":
                observable['entity_type'] = 'url'
            else:
                self.helper.log_error(f"The observable type {observable['entity_type']} has not been identified")

            indicator_id = entity['standard_id']
            indicator_score = entity['x_opencti_score']
            observable["comment"] = {
                "indicator_id": indicator_id,
                "indicator_score": indicator_score
            }

            payload = self.pattern_payload(entity, True, observable)
            response = self._query("post", f"/{uri}/", payload)

            if response is None:
                self.helper.log_error(f"[CREATE] The observable type not created")
            elif response['status_code'] == 201:
                self.helper.log_info(f"[CREATE] The observable type created = {response['response']['id']}")
        return

    def create_indicator(self, data, pattern, uri):
        if data["pattern_type"] == f"{pattern}":
            self.helper.log_info(
                f"[CREATE] Processing {pattern} indicator" + " {"
                + OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
                + "}"
            )

            payload = self.pattern_payload(data)
            if len(payload['name']) > 100:
                payload['name'] = payload['name'][0:99]
            response = self._query("post", f"/{uri}/", payload)

            # TODO handle case where status contains many elements ?
            if response is None:
                return self.helper.log_error(f"[CREATE] Indicator {pattern} not created")
            # Be careful sometimes there is a return response HarfangLab {'status':[]}
            elif not response['status']:
                return self.helper.log_error(f"Error missing value")
            elif response['status'][0]['status'] is False:
                return self.helper.log_error(f"Error {response['status'][0]['code']} = {response['status'][0]['content']}")
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
            response_name_indicator = self._query("get", f"/{uri}/?search={indicator_previous_name}&source_id={list_id}")
            response_element = self.find_data_name_match(response_name_indicator['results'], indicator_previous_name)

            if response_element is None:
                # UPSERT
                if data["pattern_type"] == "yara":
                    self.create_indicator(data, "yara", "YaraFile")
                elif data["pattern_type"] == "sigma":
                    self.create_indicator(data, "sigma", "SigmaRule")
                elif data["pattern_type"] == "stix":
                    entity = self.helper.api.indicator.read(
                        id=OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
                    )
                    self.create_observable(entity, "stix", "IOCRule")
                else:
                    raise ValueError("Unsupported Pattern")
                return
            else:
                response_id = response_element['id']

                payload = self.pattern_payload(data)
                response = self._query("put", f"/{uri}/{response_id}/", payload)

                # TODO handle case where status contains many elements
                if response is None:
                    return self.helper.log_error(f"[UPDATE] Indicator {pattern} not updated = {response_id}")
                else:
                    return self.helper.log_info(f"[UPDATE] Indicator {pattern} updated = {response_id}")

    def delete_indicator(self, data, pattern, uri):
        if data["pattern_type"] == f"{pattern}":
            self.helper.log_info(
                f"[DELETE] Processing {pattern} indicator" + " {"
                + OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
                + "}"
            )

        indicator_name = data['name']
        if len(data['name']) > 100:
            indicator_name = data['name'][0:99]
        response_name_indicator = self._query("get", f"/{uri}/?search={indicator_name}")
        response_element = self.find_data_name_match(response_name_indicator['results'], indicator_name)

        if self.harfanglab_indicator_delete is True:
            if response_element is None:
                msg_log = f'[DELETE] The searched name of the {pattern} indicator ({indicator_name}) does not exist in HarfangLab'
                return self.helper.log_error(msg_log),
            else:
                response_id = response_element['id']
                response = self._query("delete", f"/{uri}/{response_id}/")

                if response is None:
                    return self.helper.log_info(f"[DELETE] Indicator {pattern} deleted = {response_id}")
                else:
                    return self.helper.log_error(f"[DELETE] Indicator {pattern} not deleted = {response_id}")
        else:
            if response_element is None:
                msg_log = f'[DISABLE] The searched name of the {pattern} indicator ({indicator_name}) does not exist in HarfangLab'
                return self.helper.log_error(msg_log),
            else:
                response_id = response_element['id']
                payload = self.pattern_payload(data, self.harfanglab_indicator_delete)
                response = self._query("put", f"/{uri}/{response_id}/", payload)

            if response is None:
                return self.helper.log_error(f"[DISABLE] Indicator {pattern} not disabled = {response_id}")
            else:
                return self.helper.log_info(f"[DISABLE] Indicator {pattern} disabled = {response_id}")


    def find_data_name_match(self, data, name):
        return next((x for x in data if x["name"] == name), None)

    def pattern_payload(self, data, enabled=True, observable=None):
        if data["pattern_type"] == 'yara':
            return {
                "content": data["pattern"],
                "name": data["name"],
                "source_id": self.yara_list_id,

                "enabled": enabled,
                # Local testing status : [ in_progress, rejected, validated ]
                "hl_local_testing_status": "in_progress",
                # status : [ experimental, stable, testing ]
                "hl_status": self.harfanglab_rule_maturity
                # "last_modifier": {"username": "string"},
            }
        elif data["pattern_type"] == 'sigma':
            return {
                "content": data["pattern"],
                "name": data["name"],
                "source_id": self.sigma_list_id,

                "enabled": enabled,
                "hl_local_testing_status": "in_progress",
                "hl_status": self.harfanglab_rule_maturity,
                # "block_on_agent": True,
                # Rule level override: [ critical, high, informational, low, medium ]
                # "rule_level_override": "critical"
                # "last_modifier": {"username": "string"},
            }
        elif data["pattern_type"] == "stix":
            return {
                "source_id": self.stix_list_id,
                # "type": ["domain_name", "filename", "filepath", "hash", "ip_both", "ip_dst", "ip_src", "url"],
                "type": observable['entity_type'],
                "value": observable['observable_value'],

                "enabled": enabled,
                "comment": json.dumps(observable['comment']),
                "hl_status": self.harfanglab_rule_maturity,
                # "hl_local_testing_status": "in_progress",
                # "description": data['description'],
                # "last_modifier": {"username": "string"},
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
            )
        else:
            raise ValueError("Unsupported method")
        if response.status_code == 200:
            try:
                return response.json()
            except:
                return response.text
        elif response.status_code == 201:
            msg_log = f"Status code 201 : Resource was created"
            self.helper.log_info(msg_log)
            return {'response': response.json(), 'status_code': response.status_code}
        elif response.status_code == 204:
            msg_log = f"Status code 204 : Resource deleted successfully"
            return self.helper.log_info(msg_log)
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
