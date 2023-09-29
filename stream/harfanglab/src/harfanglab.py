import json
import os.path
import sys
import time

import requests
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable


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

        # Create or get existing list Yara Pattern
        self.create_or_get_entity_source("YaraSource", "yara")
        # Create or get existing list Sigma Pattern
        self.create_or_get_entity_source("SigmaSource", "sigma")
        # Create or get existing list Stix Pattern
        self.create_or_get_entity_source("IOCSource", "stix")

    def create_or_get_entity_source(self, uri, pattern_type):
        response = self._query("get", f"/{uri}/", {"search": self.harfanglab_source_list_name})
        list_of_sources = response["results"]
        source = self.find_data_name_match(list_of_sources, self.harfanglab_source_list_name)

        if source is None:
            create_source = self._query("post", f"/{uri}/", self.source_list)
            self.check_pattern_type_and_get_list_id(pattern_type, create_source["response"], "create")
        else:
            self.check_pattern_type_and_get_list_id(pattern_type, source, "existing")

    def check_pattern_type_and_get_list_id(self, pattern_type, source, info):
        if pattern_type == "yara":
            self.yara_list_id = source["id"]
            self.helper.log_info(f'Yara Source ID {info} = {self.yara_list_id}')
        elif pattern_type == "sigma":
            self.sigma_list_id = source["id"]
            self.helper.log_info(f'Sigma Source ID {info} = {self.sigma_list_id}')
        elif pattern_type == "stix":
            self.stix_list_id = source["id"]
            self.helper.log_info(f"Stix Source ID {info} = {self.stix_list_id}")
        else:
            self.helper.log_error(f"Unsupported Pattern Type = {pattern_type}")
        return

    def _process_message(self, msg):
        data_type = json.loads(msg.data)["data"]["type"]
        if data_type != "indicator" and data_type != "relationship":
            return
        try:
            data = json.loads(msg.data)["data"]
        except Exception:
            raise ValueError("Cannot process the message")

        # Handle create
        if msg.event == "create":
            if data["type"] == "indicator":
                if data["pattern_type"] == "yara":
                    self.create_indicator(data, "yara", "YaraFile", self.yara_list_id)
                elif data["pattern_type"] == "sigma":
                    self.create_indicator(data, "sigma", "SigmaRule", self.sigma_list_id)
                elif data["pattern_type"] == "stix":
                    self.create_observable(data, "stix", "IOCRule")
                else:
                    self.helper.log_error("[CREATE] Unsupported pattern type")

            elif data["type"] == "relationship":
                if data["relationship_type"] == "based-on":
                    self.create_observable(data, "stix", "IOCRule")
                else:
                    return
            return

        # Handle update
        if msg.event == "update":
            if data["type"] == "indicator":
                if data["pattern_type"] == "yara":
                    self.update_indicator(data, msg, "yara", "YaraFile", self.yara_list_id)
                elif data["pattern_type"] == "sigma":
                    self.update_indicator(data, msg, "sigma", "SigmaRule", self.sigma_list_id)
                elif data["pattern_type"] == "stix":
                    return
                else:
                    self.helper.log_error("[UPDATE] Unsupported pattern type")
            return

        # Handle delete
        if msg.event == "delete":
            if data["type"] == "indicator":
                if data["pattern_type"] == "yara":
                    self.delete_indicator(data, "yara", "YaraFile")
                elif data["pattern_type"] == "sigma":
                    self.delete_indicator(data, "sigma", "SigmaRule")
                elif data["pattern_type"] == "stix":
                    self.delete_observable(data, "stix", "IOCRule")
                else:
                    self.helper.log_error("[DELETE] Unsupported pattern type")

            elif data["type"] == "relationship":
                if data["relationship_type"] == "based-on":
                    self.delete_observable(data, "stix", "IOCRule")
                else:
                    return
            return

    def create_observable(self, data, pattern, uri):
        self.helper.log_info(f"[CREATE] Processing {pattern} observable {data['id']}")

        if data["type"] == "relationship":
            entity = self.helper.api.indicator.read(
                id=OpenCTIConnectorHelper.get_attribute_in_extension("source_ref", data)
            )
            new_observable = {}
            new_observable["id"] = OpenCTIConnectorHelper.get_attribute_in_extension("target_ref", data)
            new_observable["observable_value"] = OpenCTIConnectorHelper.get_attribute_in_extension("target_value", data)
            new_observable["entity_type"] = OpenCTIConnectorHelper.get_attribute_in_extension("target_type", data)
            new_observable["description"] = entity["description"]
            self.check_and_create_observable_id(new_observable, pattern, uri, entity)
        else:
            entity = self.helper.api.indicator.read(
                id=OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
            )
            if not entity["observables"]:
                return self.helper.log_error("[CREATE] The indicator has no observables")
            else:
                return self.helper.log_info("[CREATE] The process between indicator stix and observables has been completed")
        return

    def check_and_create_observable_id(self, data, pattern, uri, entity):
        get_observable = self._query("get", f"/{uri}/?search={data['observable_value']}&source_id={self.stix_list_id}")

        if get_observable["count"] > 0:
            result = get_observable["results"][0]
            observable_id = result["id"]
            is_enabled_observable = result["enabled"]

            if is_enabled_observable is False:
                new_observable = self.observable_object(result)
                payload = self.pattern_payload(entity, True, new_observable)
                response = self._query("put", f"/{uri}/{observable_id}/", payload)

                if response is None:
                    return self.helper.log_error(f"[UPDATE] Failed to reactivate existing observable {pattern} = {observable_id}")
                else:
                    return self.helper.log_info(f"[UPDATE] Successful reactivation of existing observable {pattern} = {observable_id}")
            else:
                return self.helper.log_error("[CREATE] A rule with this ID already exists")
        else:
            payload = self.build_observable(entity, data)
            response = self._query("post", f"/{uri}/", payload)

            if response is None:
                self.helper.log_error("[CREATE] The observable type not created")
            elif response["status_code"] == 201:
                self.helper.log_info(f"[CREATE] The observable type created = {response['response']['id']}")
            else:
                return

    def delete_observable(self, data, pattern, uri):
        indicator_delete = "[DELETE]" if self.harfanglab_indicator_delete else "[DISABLE]"
        self.helper.log_info(f"{indicator_delete} Processing {pattern} observable {data['id']}")

        if data["type"] == "relationship":
            entity = self.helper.api.indicator.read(
                id=OpenCTIConnectorHelper.get_attribute_in_extension("source_ref", data)
            )
            observable_value = OpenCTIConnectorHelper.get_attribute_in_extension("target_value", data)
            self.check_and_delete_observable_id(entity, pattern, uri, observable_value)
        else:
            entity = self.helper.api.indicator.read(
                id=OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
            )
            observables = entity["observables"]
            if not observables:
                self.helper.log_error(f"{indicator_delete} The indicator has no observables")
            else:
                for observable in observables:
                    observable_value = observable["observable_value"]
                    self.check_and_delete_observable_id(entity, pattern, uri, observable_value)
            return

    def check_and_delete_observable_id(self, entity, pattern, uri, observable_value):
        indicator_delete = "[DELETE]" if self.harfanglab_indicator_delete else "[DISABLE]"
        get_observable = self._query("get", f"/{uri}/?search={observable_value}&source_id={self.stix_list_id}")

        if get_observable["count"] > 0:

            observable = get_observable["results"][0]
            observable_id = observable["id"]
            observable_comment = json.loads(observable["comment"])
            indicator_id, indicator_score, indicator_platforms = observable_comment.values()

            if entity["standard_id"] == indicator_id:
                if self.harfanglab_indicator_delete is True:
                    response = self._query("delete", f"/{uri}/{observable_id}/")

                    if response is None:
                        self.helper.log_info(f"[DELETE] Observable {pattern} deleted = {observable_id}")
                    else:
                        self.helper.log_error(f"[DELETE] Observable {pattern} not deleted = {observable_id}")
                else:
                    new_observable = self.observable_object(observable)
                    payload = self.pattern_payload(entity, self.harfanglab_indicator_delete, new_observable)
                    response = self._query("put", f"/{uri}/{observable_id}/", payload)

                    if response is None:
                        self.helper.log_error(f"[DISABLE] Observable {pattern} not disabled = {observable_id}")
                    else:
                        self.helper.log_info(f"[DISABLE] Observable {pattern} disabled = {observable_id}")
            else:
                msg_log = f"{indicator_delete} The request failed because the indicator id in the comment of the observable is different"
                self.helper.log_error(msg_log)
        else:
            msg_log = f"{indicator_delete} The searched observable does not exist in HarfangLab"
            return self.helper.log_error(msg_log),

    def create_indicator(self, data, pattern, uri, source_list_id):
        self.helper.log_info(
            f"[CREATE] Processing {pattern} indicator" + " {"
            + OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
            + "}"
        )

        get_indicator = self._query("get", f"/{uri}/?search={data['name']}&source_id={source_list_id}")
        if get_indicator["count"] > 0:
            indicator = get_indicator["results"][0]
            indicator_id = indicator["id"]
            enabled_indicator = indicator["enabled"]

            indicator["pattern_type"] = data["pattern_type"]
            indicator["name"] = data["name"]
            indicator["content"] = data["pattern"]

            if enabled_indicator is False:
                payload = self.pattern_payload(indicator, True)
                response = self._query("put", f"/{uri}/{indicator_id}/", payload)

                if response is None:
                    return self.helper.log_error(f"[UPDATE] Failed to reactivate existing indicator {pattern} = {indicator_id}")
                else:
                    return self.helper.log_info(f"[UPDATE] Successful reactivation of existing indicator {pattern} = {indicator_id}")
            elif enabled_indicator is True and self.harfanglab_indicator_delete == "false":
                payload = self.pattern_payload(indicator, False)
                response = self._query("put", f"/{uri}/{indicator_id}/", payload)

                if response is None:
                    return self.helper.log_error(f"[UPDATE] Failed to deactivate existing indicator {pattern} = {indicator_id}")
                else:
                    return self.helper.log_info(f"[UPDATE] Successful deactivate of existing indicator {pattern} = {indicator_id}")
            else:
                return
        else:
            data["content"] = data["pattern"]
            payload = self.pattern_payload(data)
            payload["name"] = self.check_length_indicator_name(data)

            response = self._query("post", f"/{uri}/", payload)
            if response is None:
                return self.helper.log_error(f"[CREATE] Indicator {pattern} not created")
            # Be careful sometimes there is a return response HarfangLab {'status':[]}
            elif not response["status"]:
                return self.helper.log_error("Error missing value")
            elif response["status"][0]["status"] is False:
                return self.helper.log_error(f"Error {response['status'][0]['code']} = {response['status'][0]['content']}")
            else:
                response_status = response["status"][0]
                return self.helper.log_info(f"[CREATE] Indicator {pattern} created = {response_status['id']}")

    def update_indicator(self, data, msg, pattern, uri, source_list_id):
        self.helper.log_info(
            f"[UPDATE] Processing {pattern} indicator" + " {"
            + OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
            + "}"
        )

        data_context = json.loads(msg.data)["context"]
        check_patch_path = data_context["patch"][0]["path"]

        if check_patch_path == "/name":
            indicator_previous_name = data_context["reverse_patch"][0]["value"]
            get_indicator = self._query("get", f"/{uri}/?search={indicator_previous_name}&source_id={source_list_id}")
            indicator_matched = self.find_data_name_match(get_indicator["results"], indicator_previous_name)
        else:
            indicator_name = data["name"]
            get_indicator = self._query("get", f"/{uri}/?search={indicator_name}&source_id={source_list_id}")
            indicator_matched = self.find_data_name_match(get_indicator["results"], indicator_name)

        if indicator_matched is None:
            # UPSERT
            if data["pattern_type"] == "yara":
                self.create_indicator(data, "yara", "YaraFile", self.yara_list_id)
            elif data["pattern_type"] == "sigma":
                self.create_indicator(data, "sigma", "SigmaRule", self.sigma_list_id)
            elif data["pattern_type"] == "stix":
                entity = self.helper.api.indicator.read(
                    id=OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
                )
                self.create_observable(entity, "stix", "IOCRule")
            else:
                raise ValueError("Unsupported Pattern")
            return

        else:
            data["content"] = data["pattern"]
            payload = self.pattern_payload(data)
            indicator_id = indicator_matched["id"]
            response = self._query("put", f"/{uri}/{indicator_id}/", payload)

            if response is None:
                return self.helper.log_error(f"[UPDATE] Indicator {pattern} not updated = {indicator_id}")
            else:
                return self.helper.log_info(f"[UPDATE] Indicator {pattern} updated = {indicator_id}")

    def delete_indicator(self, data, pattern, uri):
        indicator_delete = "[DELETE]" if self.harfanglab_indicator_delete else "[DISABLE]"
        self.helper.log_info(
            f"{indicator_delete} Processing {pattern} indicator" + " {"
            + OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
            + "}"
        )

        indicator_name = self.check_length_indicator_name(data)
        get_indicator = self._query("get", f"/{uri}/?search={indicator_name}")
        indicator_matched = self.find_data_name_match(get_indicator["results"], indicator_name)

        if self.harfanglab_indicator_delete is True:
            if indicator_matched is None:
                msg_log = f"[DELETE] The searched name of the {pattern} indicator does not exist in HarfangLab"
                return self.helper.log_error(msg_log),
            else:
                indicator_id = indicator_matched["id"]
                response = self._query("delete", f"/{uri}/{indicator_id}/")

                if response is None:
                    return self.helper.log_info(f"[DELETE] Indicator {pattern} deleted = {indicator_id}")
                else:
                    return self.helper.log_error(f"[DELETE] Indicator {pattern} not deleted = {indicator_id}")
        else:
            if indicator_matched is None:
                msg_log = f"[DISABLE] The searched name of the {pattern} indicator does not exist in HarfangLab"
                return self.helper.log_error(msg_log),
            else:
                indicator_id = indicator_matched["id"]
                data["name"] = self.check_length_indicator_name(data)
                data["content"] = data["pattern"]

                payload = self.pattern_payload(data, self.harfanglab_indicator_delete)
                response = self._query("put", f"/{uri}/{indicator_id}/", payload)

            if response is None:
                return self.helper.log_error(f"[DISABLE] Indicator {pattern} not disabled = {indicator_id}")
            else:
                return self.helper.log_info(f"[DISABLE] Indicator {pattern} disabled = {indicator_id}")

    def build_observable(self, entity, observable):
        if observable["entity_type"] == "StixFile" or observable["entity_type"] == "Artifact":
            observable["entity_type"] = "hash"
        elif observable["entity_type"] == "Domain-Name" or observable["entity_type"] == "Hostname":
            observable["entity_type"] = "domain_name"
        elif observable["entity_type"] == "IPv4-Addr" or observable["entity_type"] == "IPv6-Addr":
            observable["entity_type"] = "ip_both"
        elif observable["entity_type"] == "Url":
            observable["entity_type"] = "url"
        else:
            self.helper.log_error(f"The observable type {observable['entity_type']} is not processed")

        indicator_id = entity["standard_id"]
        indicator_score = entity["x_opencti_score"]
        indicator_platforms = entity["x_mitre_platforms"]

        observable["description"] = entity["description"]
        observable["comment"] = {
            "indicator_id": indicator_id,
            "indicator_score": indicator_score,
            "indicator_platforms": indicator_platforms
        }

        return self.pattern_payload(entity, True, observable)

    @staticmethod
    def observable_object(observable):
        new_observable = {}
        new_observable["entity_type"] = observable["type"]
        new_observable["observable_value"] = observable["value"]
        new_observable["comment"] = json.loads(observable["comment"])
        new_observable["description"] = observable["description"]
        return new_observable

    @staticmethod
    def check_length_indicator_name(data):
        if len(data["name"]) > 100:
            return data["name"][0:99]
        else:
            return data["name"]

    @staticmethod
    def find_data_name_match(data, name):
        return next((x for x in data if x["name"] == name), None)

    def pattern_payload(self, data, enabled=True, observable=None):
        if data["pattern_type"] == "yara":
            return {
                "content": data["content"],
                "name": data["name"],
                "source_id": self.yara_list_id,

                "enabled": enabled,
                "hl_local_testing_status": "in_progress",
                "hl_status": self.harfanglab_rule_maturity
            }
        elif data["pattern_type"] == "sigma":
            return {
                "content": data["content"],
                "name": data["name"],
                "source_id": self.sigma_list_id,

                "enabled": enabled,
                "hl_local_testing_status": "in_progress",
                "hl_status": self.harfanglab_rule_maturity,
            }
        elif data["pattern_type"] == "stix":
            return {
                "source_id": self.stix_list_id,
                "type": observable["entity_type"],
                "value": observable["observable_value"],

                "enabled": enabled,
                "comment": json.dumps(observable["comment"]),
                "hl_status": self.harfanglab_rule_maturity,
                "description": observable["description"],
            }
        else:
            raise ValueError("Unsupported Pattern")

    def _query(self, method, uri, payload=None):
        if method == "get":
            response = requests.get(
                self.api_url + uri,
                headers=self.headers,
                params=payload,
                verify=self.harfanglab_ssl_verify,
                )
        elif method == "post":
            response = requests.post(
                self.api_url + uri,
                headers=self.headers,
                json=payload,
                verify=self.harfanglab_ssl_verify,
                )
        elif method == "put":
            response = requests.put(
                self.api_url + uri,
                headers=self.headers,
                json=payload,
                verify=self.harfanglab_ssl_verify,
            )
        elif method == "delete":
            response = requests.delete(
                self.api_url + uri,
                headers=self.headers,
                verify=self.harfanglab_ssl_verify,
            )
        else:
            raise ValueError("Unsupported method")
        if response.status_code == 200:
            try:
                return response.json()
            except:
                return response.text
        elif response.status_code == 201:
            msg_log = "Status code 201 : Resource was created"
            self.helper.log_info(msg_log)
            return {"response": response.json(), "status_code": response.status_code}
        elif response.status_code == 204:
            msg_log = "Status code 204 : Resource deleted successfully"
            return self.helper.log_info(msg_log)
        elif response.status_code == 400:
            msg_log = f"Status code 400 : Bad Request = {json.loads(response.content)}"
            return self.helper.log_error(msg_log)
        elif response.status_code == 401:
            msg_log = "Status code 401 : Query failed, permission denied"
            self.helper.log_error(msg_log)
            raise ValueError(msg_log)
        elif response.status_code == 500:
            msg_log = "Status code 500 : Internal Server Error"
            self.helper.log_error(msg_log)
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
