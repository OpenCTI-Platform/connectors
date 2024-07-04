################################################
# HarfangLab Connector for OpenCTI             #
################################################

import json
import os.path
import sys
import time

import requests
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable
from sightings import Sightings
from stix_shifter.stix_translation import stix_translation


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

        # Initialize the Harfang Lab API
        self.harfanglab_url = get_config_variable(
            "HARFANGLAB_URL", ["harfanglab", "url"], config
        )

        self.harfanglab_ssl_verify = get_config_variable(
            "HARFANGLAB_SSL_VERIFY", ["harfanglab", "ssl_verify"], config, False, True
        )
        self.harfanglab_token = get_config_variable(
            "HARFANGLAB_TOKEN", ["harfanglab", "token"], config
        )
        self.harfanglab_login = get_config_variable(
            "HARFANGLAB_LOGIN", ["harfanglab", "login"], config
        )
        self.harfanglab_password = get_config_variable(
            "HARFANGLAB_PASSWORD", ["harfanglab", "password"], config
        )
        self.api_url = self.harfanglab_url + "/api/data/threat_intelligence"
        self.headers = {
            "Accept": "application/json",
            "Authorization": "Token " + self.harfanglab_token,
        }
        self.harfanglab_source_list_name = get_config_variable(
            "HARFANGLAB_SOURCE_LIST_NAME", ["harfanglab", "source_list_name"], config
        )
        self.harfanglab_remove_indicator = get_config_variable(
            "HARFANGLAB_REMOVE_INDICATOR", ["harfanglab", "remove_indicator"], config
        )
        self.harfanglab_rule_maturity = get_config_variable(
            "HARFANGLAB_RULE_MATURITY", ["harfanglab", "rule_maturity"], config
        )
        self.harfanglab_import_security_events_as_incidents = get_config_variable(
            "HARFANGLAB_IMPORT_SECURITY_EVENTS_AS_INCIDENTS",
            ["harfanglab", "import_security_events_as_incidents"],
            config,
        )
        self.harfanglab_import_threats_as_case_incidents = get_config_variable(
            "HARFANGLAB_IMPORT_THREATS_AS_CASE_INCIDENTS",
            ["harfanglab", "import_threats_as_case_incidents"],
            config,
        )
        self.harfanglab_import_security_events_filters_by_status = get_config_variable(
            "HARFANGLAB_IMPORT_SECURITY_EVENTS_FILTERS_BY_STATUS",
            ["harfanglab", "import_security_events_filters_by_status"],
            config,
        )
        self.harfanglab_import_filters_by_alert_type = get_config_variable(
            "HARFANGLAB_IMPORT_FILTERS_BY_ALERT_TYPE",
            ["harfanglab", "import_filters_by_alert_type"],
            config,
        )
        self.harfanglab_default_markings = get_config_variable(
            "HARFANGLAB_DEFAULT_MARKINGS", ["harfanglab", "default_markings"], config
        )
        self.source_list = {
            "name": self.harfanglab_source_list_name,
            "description": "Cyber Threat Intelligence knowledge imported from OpenCTI, and any changes must be made only to it.",
            "enabled": True,
        }
        self.default_score = get_config_variable(
            "HARFANGLAB_DEFAULT_SCORE", ["harfanglab", "default_score"]
        )

        # Check config parameters
        if (
            self.harfanglab_remove_indicator is None
            or self.harfanglab_remove_indicator
            != bool(self.harfanglab_remove_indicator)
        ):
            raise ValueError(
                "Missing or incorrect value in configuration parameter 'Remove Indicator'"
            )

        if (
            self.harfanglab_rule_maturity is None
            or self.harfanglab_rule_maturity not in ("stable", "testing")
        ):
            raise ValueError(
                "Missing or incorrect value in configuration parameter 'Rule Maturity'"
            )

        if (
            self.helper.connect_live_stream_id is None
            or self.helper.connect_live_stream_id == "ChangeMe"
        ):
            raise ValueError(
                "Missing or incorrect value in configuration parameter 'Live Stream ID'"
            )
        if (
            self.harfanglab_import_security_events_as_incidents is None
            or self.harfanglab_import_security_events_as_incidents
            != bool(self.harfanglab_import_security_events_as_incidents)
        ):
            raise ValueError(
                "Missing or incorrect value in configuration parameter 'Import security events as sightings'"
            )
        if (
            self.harfanglab_import_threats_as_case_incidents is None
            or self.harfanglab_import_threats_as_case_incidents
            != bool(self.harfanglab_import_threats_as_case_incidents)
        ):
            raise ValueError(
                "Missing or incorrect value in configuration parameter 'Import threads as incidents'"
            )
        if (
            self.harfanglab_import_threats_as_case_incidents is True
            and self.harfanglab_import_security_events_as_incidents is False
        ):
            raise ValueError(
                "If 'import_threats_as_case_incidents' is True then 'import_security_events_as_incidents' must be True"
            )

        self.check_config_filters(
            self.harfanglab_import_security_events_filters_by_status,
            ["new", "investigating", "false_positive", "closed"],
            4,
        )
        self.check_config_filters(
            self.harfanglab_import_filters_by_alert_type, ["yara", "sigma", "ioc"], 3
        )

        # Create or get existing list Yara Pattern
        self.create_or_get_entity_source("YaraSource", "yara")
        # Create or get existing list Sigma Pattern
        self.create_or_get_entity_source("SigmaSource", "sigma")
        # Create or get existing list Stix Pattern
        self.create_or_get_entity_source("IOCSource", "stix")

    @staticmethod
    def check_config_filters(check_filters, valid_filters, max_len_filters):
        result = check_filters.lower().replace(" ", "").split(",")
        if len(result) <= max_len_filters:
            for item in result:
                if not item in valid_filters:
                    raise ValueError(
                        f"Missing or incorrect value in configuration parameter, for import sightings with filters, valid filters : {valid_filters}"
                    )
        else:
            raise ValueError(
                "The length of the list allowed in the configuration parameter is exceeded 'Import sightings with status or alert type filters'"
            )

    def create_or_get_entity_source(self, uri, pattern_type):
        response = self._query(
            "get", f"/{uri}/", {"search": self.harfanglab_source_list_name}
        )
        list_of_sources = response["results"]
        source = self.find_data_name_match(
            list_of_sources, self.harfanglab_source_list_name
        )

        if source is None:
            create_source = self._query("post", f"/{uri}/", self.source_list)
            self.check_pattern_type_and_get_list_id(
                pattern_type, create_source["response"], "create"
            )
        else:
            self.check_pattern_type_and_get_list_id(pattern_type, source, "existing")

    def check_pattern_type_and_get_list_id(self, pattern_type, source, info):
        if pattern_type == "yara":
            self.yara_list_id = source["id"]
            self.helper.connector_logger.info(
                "[STREAM] Yara Source ID",
                {"Source_status": info, "source_id": self.yara_list_id},
            )
        elif pattern_type == "sigma":
            self.sigma_list_id = source["id"]
            self.helper.connector_logger.info(
                "[STREAM] Sigma Source ID",
                {"Source_status": info, "source_id": self.sigma_list_id},
            )
        elif pattern_type == "stix":
            self.stix_list_id = source["id"]
            self.helper.connector_logger.info(
                "[STREAM] Stix Source ID",
                {"Source_status": info, "source_id": self.stix_list_id},
            )
        else:
            return self.helper.connector_logger.error(
                "[ERROR] Unsupported Pattern Type", {"pattern_type": pattern_type}
            )

    def _process_message(self, msg):
        try:
            data = json.loads(msg.data)["data"]
        except Exception:
            raise ValueError("Cannot process the message")

        data_type = json.loads(msg.data)["data"]["type"]
        if data_type != "indicator" and data_type != "relationship":
            return

        # Handle create
        if msg.event == "create":
            if data["type"] == "indicator":
                if data["pattern_type"] == "yara":
                    self.create_indicator(data, "yara", "YaraFile", self.yara_list_id)
                elif data["pattern_type"] == "sigma":
                    self.create_indicator(
                        data, "sigma", "SigmaRule", self.sigma_list_id
                    )
                elif data["pattern_type"] == "stix":
                    self.create_indicator(data, "stix", "IOCRule", self.stix_list_id)
                else:
                    self.helper.connector_logger.error(
                        "[ERROR] Unsupported Pattern Type during event create",
                        {"pattern_type": data["pattern_type"]},
                    )

            elif data["type"] == "relationship":
                if data["relationship_type"] == "based-on":
                    self.create_observable(data, "stix", "IOCRule", self.stix_list_id)
                else:
                    return
            return

        # Handle update
        if msg.event == "update":
            if data["type"] == "indicator":
                if data["pattern_type"] == "yara":
                    self.update_indicator(msg, "yara", "YaraFile", self.yara_list_id)
                elif data["pattern_type"] == "sigma":
                    self.update_indicator(msg, "sigma", "SigmaRule", self.sigma_list_id)
                elif data["pattern_type"] == "stix":
                    self.update_indicator(msg, "stix", "IOCRule", self.stix_list_id)
                else:
                    self.helper.connector_logger.error(
                        "[ERROR] Unsupported Pattern Type during event update",
                        {"pattern_type": data["pattern_type"]},
                    )
            return

        # Handle delete
        if msg.event == "delete":
            if data["type"] == "indicator":
                if data["pattern_type"] == "yara":
                    self.delete_indicator(data, "yara", "YaraFile", self.yara_list_id)
                elif data["pattern_type"] == "sigma":
                    self.delete_indicator(
                        data, "sigma", "SigmaRule", self.sigma_list_id
                    )
                elif data["pattern_type"] == "stix":
                    self.delete_indicator(data, "stix", "IOCRule", self.stix_list_id)
                else:
                    self.helper.connector_logger.error(
                        "[ERROR] Unsupported Pattern Type during event delete",
                        {"pattern_type": data["pattern_type"]},
                    )

            elif data["type"] == "relationship":
                if data["relationship_type"] == "based-on":
                    self.delete_observable(data, "stix", "IOCRule", self.stix_list_id)
                else:
                    return
            return

    def log_info_process(self, data, method):
        data_id = OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
        pattern_type = data["pattern_type"] if "pattern_type" in data else None
        return self.helper.connector_logger.info(
            "[PROCESS] The process is started",
            {
                "method": method,
                "pattern_type": pattern_type,
                "entity_type": data["type"],
                "id": data_id,
            },
        )

    def create_indicator(self, data, pattern_type, uri, source_list_id):
        entity = self.helper.api.indicator.read(
            id=OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
        )
        self.log_info_process(data, "[CREATE]")

        if pattern_type == "stix":
            indicators = self.stix_translation_parser(data, entity)
            indicator_values = []
            for indicator in indicators:
                indicator_values.append(indicator["value"])
                indicator_matched = self.get_and_match_element(
                    data, uri, indicator["value"], source_list_id
                )

                self.process_create_indicator(
                    data, entity, uri, pattern_type, indicator_matched
                )

            observables = entity["observables"]
            for observable in observables:
                if (
                    "observable_value" in observable
                    and observable["observable_value"] in indicator_values
                ):
                    continue
                observable_matched = self.get_and_match_element(
                    data, uri, observable["observable_value"], source_list_id
                )
                if (
                    observable_matched is not None
                    and observable_matched["enabled"] is False
                ):
                    observable_id = observable_matched["id"]
                    new_observable = self.build_stix_observable_object(
                        observable_matched, entity, True, True
                    )
                    response = self._query(
                        "put", f"/{uri}/{observable_id}/", new_observable
                    )

                    if response is None:
                        self.helper.connector_logger.error(
                            "[ERROR] Failure reactivated of existing observable",
                            {
                                "pattern_type": pattern_type,
                                "observable_id": observable_id,
                            },
                        )
                    else:
                        self.helper.connector_logger.info(
                            "[UPDATE] Successful reactivated of existing observable",
                            {
                                "pattern_type": pattern_type,
                                "observable_id": observable_id,
                            },
                        )
                else:
                    new_observable = self.build_stix_observable_object(
                        observable, entity, True, True
                    )
                    if new_observable is None:
                        return

                    observable_matched = self.get_and_match_element(
                        data, uri, new_observable["value"], source_list_id
                    )
                    if observable_matched is None:
                        response = self._query("post", f"/{uri}/", new_observable)

                        if response is None:
                            self.helper.connector_logger.error(
                                "[ERROR] Failure observable created",
                                {"pattern_type": pattern_type},
                            )
                        elif response["status_code"] == 201:
                            self.helper.connector_logger.info(
                                "[CREATE] Successful observable created",
                                {
                                    "pattern_type": pattern_type,
                                    "observable_id": response["response"]["id"],
                                },
                            )

        else:
            indicator_name = self.truncate_indicator_name(data)
            indicator_matched = self.get_and_match_element(
                data, uri, indicator_name, source_list_id
            )
            self.process_create_indicator(
                data, entity, uri, pattern_type, indicator_matched
            )

    def process_create_indicator(
        self, data, entity, uri, pattern_type, indicator_matched
    ):
        if indicator_matched is not None:
            indicator_id = indicator_matched["id"]
            enabled_indicator = indicator_matched["enabled"]

            if enabled_indicator is False:
                if pattern_type == "stix":
                    indicator = self.build_stix_indicator_object(
                        indicator_matched, entity, True, True
                    )
                else:
                    indicator = self.build_yara_sigma_indicator_object(
                        indicator_matched, entity, True, True
                    )

                response = self._query("put", f"/{uri}/{indicator_id}/", indicator)
                if response is None:
                    return self.helper.connector_logger.error(
                        "[ERROR] Failed reactivated existing indicator",
                        {"pattern_type": pattern_type, "indicator_id": indicator_id},
                    )
                else:
                    return self.helper.connector_logger.info(
                        "[ENABLE] Successful reactivated of existing indicator",
                        {"pattern_type": pattern_type, "indicator_id": indicator_id},
                    )
        else:
            if pattern_type == "stix":
                indicators = self.stix_translation_parser(data, entity)

                for indicator in indicators:
                    response = self._query("post", f"/{uri}/", indicator)

                    if response is None:
                        self.helper.connector_logger.error(
                            "[ERROR] Failed to create indicator",
                            {"pattern_type": pattern_type},
                        )
                    elif response["status_code"] == 201:
                        self.helper.connector_logger.info(
                            "[CREATE] Successful indicator created",
                            {
                                "pattern_type": pattern_type,
                                "response_id": response["response"]["id"],
                            },
                        )
            else:
                indicator = self.build_yara_sigma_indicator_object(data, entity, True)
                response = self._query("post", f"/{uri}/", indicator)

                if response is None:
                    return self.helper.connector_logger.error(
                        "[ERROR] Failed to create indicator",
                        {"pattern_type": pattern_type},
                    )
                # Be careful sometimes there is a return response HarfangLab {'status':[]}
                elif not response["status"]:
                    return self.helper.connector_logger.error(
                        "[ERROR] Missing value", {"pattern_type": pattern_type}
                    )
                elif response["status"][0]["status"] is False:
                    return self.helper.connector_logger.error(
                        "[ERROR] An error has occurred",
                        {
                            "status_code": response["status"][0]["code"],
                            "message": response["status"][0]["content"],
                        },
                    )
                else:
                    response_status_id = response["status"][0]["id"]
                    return self.helper.connector_logger.info(
                        "[CREATE] Successful indicator created",
                        {
                            "pattern_type": pattern_type,
                            "indicator_id": response_status_id,
                        },
                    )

    def update_indicator(self, msg, pattern_type, uri, source_list_id):
        data = json.loads(msg.data)["data"]
        entity = self.helper.api.indicator.read(
            id=OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
        )
        self.log_info_process(data, "[UPDATE]")
        data_context = json.loads(msg.data)["context"]
        check_patch_path = data_context["patch"][0]["path"]
        data_reverse_patch = data_context["reverse_patch"]

        if pattern_type == "stix":

            if check_patch_path == "/pattern":
                indicator_previous_value = data_context["reverse_patch"][0]["value"]
                new_data = data.copy()
                new_data["pattern"] = indicator_previous_value

                indicators_list_parsed = self.stix_translation_parser(new_data, entity)
                for indicator_parsed in indicators_list_parsed:
                    new_indicator_matched = self.get_and_match_element(
                        data,
                        uri,
                        indicator_parsed["value"],
                        source_list_id,
                        data_reverse_patch,
                    )

                    if new_indicator_matched:
                        new_data["id"] = json.loads(new_indicator_matched["comment"])[
                            "indicator_id"
                        ]
                        self.delete_indicator(
                            new_data, pattern_type, uri, source_list_id
                        )

            indicators = self.stix_translation_parser(data, entity)
            indicator_values = []
            for indicator in indicators:
                indicator_values.append(indicator["value"])
                indicator_matched = self.get_and_match_element(
                    data, uri, indicator["value"], source_list_id, data_reverse_patch
                )
                self.process_update_indicator(
                    data, entity, uri, pattern_type, indicator_matched
                )

            observables = entity["observables"]
            for observable in observables:
                if (
                    "observable_value" in observable
                    and observable["observable_value"] in indicator_values
                ):
                    continue
                observable_matched = self.get_and_match_element(
                    data,
                    uri,
                    observable["observable_value"],
                    source_list_id,
                    data_reverse_patch,
                )
                self.process_update_observable(
                    data, entity, uri, pattern_type, observable_matched
                )

        else:
            data_context = json.loads(msg.data)["context"]
            check_patch_path = data_context["patch"][0]["path"]

            if check_patch_path == "/name":
                indicator_previous_name = data_context["reverse_patch"][0]["value"]
                indicator_matched = self.get_and_match_element(
                    data,
                    uri,
                    indicator_previous_name,
                    source_list_id,
                    data_reverse_patch,
                )

                self.process_update_indicator(
                    data, entity, uri, pattern_type, indicator_matched
                )
            else:
                indicator_name = self.truncate_indicator_name(data)
                indicator_matched = self.get_and_match_element(
                    data, uri, indicator_name, source_list_id, data_reverse_patch
                )
                self.process_update_indicator(
                    data, entity, uri, pattern_type, indicator_matched
                )

    def process_update_indicator(
        self, data, entity, uri, pattern_type, indicator_matched
    ):
        if indicator_matched is None:
            # UPSERT
            if data["pattern_type"] == "yara":
                self.create_indicator(data, "yara", "YaraFile", self.yara_list_id)
            elif data["pattern_type"] == "sigma":
                self.create_indicator(data, "sigma", "SigmaRule", self.sigma_list_id)
            elif data["pattern_type"] == "stix":
                self.create_indicator(data, "stix", "IOCRule", self.stix_list_id)
            else:
                return self.helper.connector_logger.error(
                    "[ERROR] Unsupported Pattern", {"pattern_type": pattern_type}
                )
            return
        else:
            indicator_id = indicator_matched["id"]
            if pattern_type == "stix":
                indicator = self.build_stix_indicator_object(
                    indicator_matched, entity, indicator_matched["enabled"], True
                )
                indicator["source"] = indicator["source_id"]
            else:
                indicator = self.build_yara_sigma_indicator_object(
                    data, entity, indicator_matched["enabled"]
                )

            response = self._query("put", f"/{uri}/{indicator_id}/", indicator)
            if response is None:
                return self.helper.connector_logger.error(
                    "[ERROR] Failure indicator updated",
                    {"pattern_type": pattern_type, "indicator_id": indicator_id},
                )
            else:
                return self.helper.connector_logger.info(
                    "[UPDATE] Successful indicator updated",
                    {"pattern_type": pattern_type},
                )

    def process_update_observable(
        self, data, entity, uri, pattern_type, observable_matched
    ):
        if observable_matched is None:
            return self.helper.connector_logger.error(
                "[ERROR] The searched for observable does not exist in HarfangLab",
                {"pattern_type": pattern_type},
            )
        else:
            observable_id = observable_matched["id"]
            observable_matched["description"] = data.get(
                "description", "No description"
            )
            observable = self.build_stix_observable_object(
                observable_matched, entity, observable_matched["enabled"], True
            )

            response = self._query("put", f"/{uri}/{observable_id}/", observable)
            if response is None:
                return self.helper.connector_logger.error(
                    "[ERROR] Failure observable updated",
                    {"pattern_type": pattern_type, "observable_id": observable_id},
                )
            else:
                return self.helper.connector_logger.info(
                    "[UPDATE] Successful observable updated",
                    {"pattern_type": pattern_type, "observable_id": observable_id},
                )

    def delete_indicator(self, data, pattern_type, uri, source_list_id):
        entity = self.helper.api.indicator.read(
            id=OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
        )
        config_remove_indicator = (
            "[DELETE]" if self.harfanglab_remove_indicator else "[DISABLE]"
        )
        self.log_info_process(data, config_remove_indicator)

        if pattern_type == "stix":
            if entity is not None:

                indicators = self.stix_translation_parser(data, entity)
                indicator_values = []
                for indicator in indicators:
                    indicator_values.append(indicator["value"])
                    if indicator["type"] is not None:
                        indicator_matched = self.get_and_match_element(
                            data, uri, indicator["value"], source_list_id
                        )
                        self.process_delete_indicator(
                            data,
                            entity,
                            uri,
                            pattern_type,
                            config_remove_indicator,
                            indicator_matched,
                        )

                observables = entity["observables"]
                for observable in observables:
                    if (
                        "observable_value" in observable
                        and observable["observable_value"] in indicator_values
                    ):
                        continue
                    observable_matched = self.get_and_match_element(
                        data, uri, observable["observable_value"], source_list_id
                    )
                    self.process_delete_observable(
                        data,
                        entity,
                        uri,
                        pattern_type,
                        config_remove_indicator,
                        observable_matched,
                    )
            else:
                ioc_list = self._query(
                    "get", f"/{uri}/?search={data['id']}&source_id={source_list_id}"
                )

                for ioc in ioc_list["results"]:
                    self.process_delete_indicator(
                        ioc,
                        entity,
                        uri,
                        pattern_type,
                        config_remove_indicator,
                        ioc,
                    )

        else:
            indicator_name = self.truncate_indicator_name(data)
            indicator_matched = self.get_and_match_element(
                data, uri, indicator_name, source_list_id
            )
            if indicator_matched:
                self.process_delete_indicator(
                    data,
                    entity,
                    uri,
                    pattern_type,
                    config_remove_indicator,
                    indicator_matched,
                )

    def process_delete_indicator(
        self,
        data,
        entity,
        uri,
        pattern_type,
        config_remove_indicator,
        indicator_matched,
    ):
        if indicator_matched is None:
            return self.helper.connector_logger.info(
                "[INFO] The searched for indicator does not exist in HarfangLab",
                {"process": config_remove_indicator, "pattern_type": pattern_type},
            )
        else:
            indicator_id = indicator_matched["id"]
            if self.harfanglab_remove_indicator is True:
                response = self._query("delete", f"/{uri}/{indicator_id}/")

                if response is None:
                    return self.helper.connector_logger.info(
                        "[INFO] Successful indicator deleted",
                        {
                            "process": config_remove_indicator,
                            "pattern_type": pattern_type,
                            "indicator_id": indicator_id,
                        },
                    )
                else:
                    return self.helper.connector_logger.error(
                        "[ERROR] Failure indicator deleted",
                        {
                            "process": config_remove_indicator,
                            "pattern_type": pattern_type,
                            "indicator_id": indicator_id,
                        },
                    )

            elif self.harfanglab_remove_indicator is False:
                if pattern_type == "stix":
                    indicator = self.build_stix_indicator_object(
                        indicator_matched, entity, False, True
                    )
                else:
                    indicator = self.build_yara_sigma_indicator_object(
                        data, entity, False
                    )
                response = self._query("put", f"/{uri}/{indicator_id}/", indicator)

                if response is None:
                    return self.helper.connector_logger.error(
                        "[ERROR] Failure indicator deactivation",
                        {
                            "process": config_remove_indicator,
                            "pattern_type": pattern_type,
                            "indicator_id": indicator_id,
                        },
                    )
                else:
                    return self.helper.connector_logger.info(
                        "[INFO] Successful indicator deactivation",
                        {
                            "process": config_remove_indicator,
                            "pattern_type": pattern_type,
                            "indicator_id": indicator_id,
                        },
                    )

    def create_observable(self, data, pattern_type, uri, source_list_id):
        entity = self.helper.api.indicator.read(
            id=OpenCTIConnectorHelper.get_attribute_in_extension("source_ref", data)
        )
        self.log_info_process(data, "[CREATE]")

        observable = self.build_stix_observable_object(data, entity, True)
        if observable is not None:
            observable_value = observable["value"]
            observable_matched = self.get_and_match_element(
                data, uri, observable_value, source_list_id
            )

            self.process_create_observable(
                observable, uri, pattern_type, observable_matched
            )

    def process_create_observable(self, data, uri, pattern_type, observable_matched):
        if observable_matched is not None:
            observable_id = observable_matched["id"]
            enabled_observable = observable_matched["enabled"]

            observable_comment_id = json.loads(data["comment"])["indicator_id"]
            observable_matched_comment_id = json.loads(observable_matched["comment"])[
                "indicator_id"
            ]

            if observable_comment_id == observable_matched_comment_id:
                if enabled_observable is False:
                    data["enabled"] = True
                    response = self._query("put", f"/{uri}/{observable_id}/", data)

                    if response is None:
                        return self.helper.connector_logger.error(
                            "[ERROR] Failed reactivated existing observable",
                            {
                                "pattern_type": pattern_type,
                                "observable_id": observable_id,
                            },
                        )
                    else:
                        return self.helper.connector_logger.info(
                            "[ENABLE] Successful reactivated of existing observable",
                            {
                                "pattern_type": pattern_type,
                                "observable_id": observable_id,
                            },
                        )
            else:
                self.helper.connector_logger.error(
                    "[ERROR] The request failed because the indicator id in the comment of the observable is different",
                    {
                        "pattern_type": pattern_type,
                        "indicator_id": observable_matched_comment_id,
                        "observable_id": observable_comment_id,
                    },
                )
        else:
            response = self._query("post", f"/{uri}/", data)

            if response is None:
                return self.helper.connector_logger.error(
                    "[ERROR] Failure observable created", {"pattern_type": pattern_type}
                )
            elif response["status_code"] == 201:
                return self.helper.connector_logger.info(
                    "[CREATE] Successful observable created",
                    {
                        "pattern_type": pattern_type,
                        "response_id": response["response"]["id"],
                    },
                )

    def delete_observable(self, data, pattern_type, uri, source_list_id):
        entity = self.helper.api.indicator.read(
            id=OpenCTIConnectorHelper.get_attribute_in_extension("source_ref", data)
        )
        config_remove_indicator = (
            "[DELETE]" if self.harfanglab_remove_indicator else "[DISABLE]"
        )
        self.log_info_process(data, config_remove_indicator)

        observable = self.build_stix_observable_object(data, entity, True)
        if observable is not None:
            observable_value = observable["value"]
            observable_matched = self.get_and_match_element(
                data, uri, observable_value, source_list_id
            )
            self.process_delete_observable(
                data,
                entity,
                uri,
                pattern_type,
                config_remove_indicator,
                observable_matched,
            )

    def process_delete_observable(
        self,
        data,
        entity,
        uri,
        pattern_type,
        config_remove_indicator,
        observable_matched,
    ):
        if observable_matched is None:
            return self.helper.connector_logger.info(
                "[INFO] The searched for observable does not exist in HarfangLab",
                {"process": config_remove_indicator, "pattern_type": pattern_type},
            )
        else:
            observable_id = observable_matched["id"]

            if "comment" in data:
                observable_comment_id = json.loads(data["comment"])["indicator_id"]
            elif "source_ref" in data:
                observable_comment_id = data["source_ref"]
            else:
                observable_comment_id = data["id"]

            observable_matched_comment_id = json.loads(observable_matched["comment"])[
                "indicator_id"
            ]
            if observable_comment_id == observable_matched_comment_id:
                if self.harfanglab_remove_indicator is True:
                    response = self._query("delete", f"/{uri}/{observable_id}/")

                    if response is None:
                        return self.helper.connector_logger.info(
                            "[INFO] Successful observable deleted",
                            {
                                "process": config_remove_indicator,
                                "pattern_type": pattern_type,
                                "observable_id": observable_id,
                            },
                        )
                    else:
                        return self.helper.connector_logger.error(
                            "[ERROR] Failure observable deleted",
                            {
                                "process": config_remove_indicator,
                                "pattern_type": pattern_type,
                                "observable_id": observable_id,
                            },
                        )

                elif self.harfanglab_remove_indicator is False:
                    observable = self.build_stix_observable_object(
                        observable_matched, entity, False, True
                    )
                    response = self._query(
                        "put", f"/{uri}/{observable_id}/", observable
                    )

                    if response is None:
                        return self.helper.connector_logger.error(
                            "[ERROR] Failure observable deactivation",
                            {
                                "process": config_remove_indicator,
                                "pattern_type": pattern_type,
                                "observable_id": observable_id,
                            },
                        )
                    else:
                        return self.helper.connector_logger.info(
                            "[INFO] Successful observable deactivation",
                            {
                                "process": config_remove_indicator,
                                "pattern_type": pattern_type,
                                "observable_id": observable_id,
                            },
                        )
            else:
                self.helper.connector_logger.error(
                    "[ERROR] The request failed because the indicator id in the comment of the observable is different",
                    {
                        "pattern_type": pattern_type,
                        "indicator_id": observable_matched_comment_id,
                        "observable_id": observable_comment_id,
                    },
                )

    @staticmethod
    def truncate_indicator_name(data):
        if len(data["name"]) > 100:
            return data["name"][0:99]
        else:
            return data["name"]

    @staticmethod
    def find_data_name_match(data, name):
        for item in data:
            if "name" in item and item["name"] == name:
                return item
            elif "value" in item and item["value"] == name:
                return item

    def build_stix_indicator_object(
        self, data, entity, enabled, existing_indicator=None
    ):
        new_indicator = {}

        if existing_indicator:
            new_indicator["id"] = json.loads(data["comment"])["indicator_id"]
            new_indicator["entity_type"] = data["type"]
            new_indicator["value"] = data["value"]
        else:
            new_indicator["id"] = data["id"]
            new_indicator["entity_type"] = data["stix_attribute"]
            new_indicator["value"] = data["stix_value"]
            new_indicator["description"] = data.get("description", "No description")

        if entity is None:
            new_indicator["pattern_type"] = "stix"
            new_indicator["comment"] = (
                json.loads(data["comment"]) if "comment" in data else {}
            )
            new_indicator["description"] = data.get("description", "No description")
        else:
            new_indicator["description"] = entity.get("description", "No description")
            if entity["description"] == "":
                new_indicator["description"] = "No description"

            new_indicator["pattern_type"] = entity["pattern_type"]
            indicator_score = entity["x_opencti_score"]
            indicator_platforms = entity["x_mitre_platforms"]

            new_indicator["comment"] = {
                "indicator_id": new_indicator["id"],
                "indicator_score": indicator_score,
                "indicator_platforms": indicator_platforms,
            }

        return self.pattern_payload(new_indicator, enabled)

    def build_yara_sigma_indicator_object(
        self, data, entity, enabled, existing_indicator=None
    ):
        new_indicator = {}
        new_indicator["name"] = data["name"]

        if entity is not None:
            new_indicator["pattern_type"] = entity["pattern_type"]
        else:
            new_indicator["pattern_type"] = data["pattern_type"]

        if existing_indicator:
            new_indicator["content"] = data["content"]
        else:
            new_indicator["content"] = data["pattern"]

        payload = self.pattern_payload(new_indicator, enabled)
        payload["name"] = self.truncate_indicator_name(data)
        return payload

    def build_stix_observable_object(
        self, data, entity, enabled, existing_observable=None
    ):
        new_observable = {}
        new_observable["pattern_type"] = entity["pattern_type"]

        if existing_observable:
            if "entity_type" in data:
                new_observable["value"] = data["observable_value"]
            else:
                data["entity_type"] = data["type"]
                new_observable["value"] = data["value"]
        else:
            data["entity_type"] = OpenCTIConnectorHelper.get_attribute_in_extension(
                "target_type", data
            )
            new_observable["value"] = OpenCTIConnectorHelper.get_attribute_in_extension(
                "target_value", data
            )

        if (
            data["entity_type"] == "StixFile"
            or data["entity_type"] == "Artifact"
            or data["entity_type"] == "hash"
        ):
            new_observable["entity_type"] = "hash"
        elif (
            data["entity_type"] == "Domain-Name"
            or data["entity_type"] == "Hostname"
            or data["entity_type"] == "domain_name"
        ):
            new_observable["entity_type"] = "domain_name"
        elif (
            data["entity_type"] == "IPv4-Addr"
            or data["entity_type"] == "IPv6-Addr"
            or data["entity_type"] == "ip_both"
        ):
            new_observable["entity_type"] = "ip_both"
        elif data["entity_type"] == "Url" or data["entity_type"] == "url":
            new_observable["entity_type"] = "url"
        else:
            return self.helper.connector_logger.error(
                "[ERROR] The observable type is not processed",
                {"entity_type": data["entity_type"]},
            )
        new_observable["id"] = entity["standard_id"]
        new_observable["score"] = entity["x_opencti_score"]
        new_observable["platforms"] = entity["x_mitre_platforms"]

        new_observable["description"] = entity.get("description", "No description")
        new_observable["comment"] = {
            "indicator_id": new_observable["id"],
            "indicator_score": new_observable["score"],
            "indicator_platforms": new_observable["platforms"],
        }

        return self.pattern_payload(new_observable, enabled)

    def stix_translation_parser(self, data, entity):
        translation = stix_translation.StixTranslation()
        parsed = translation.translate("splunk", "parse", "{}", data["pattern"])
        if "parsed_stix" in parsed:
            results = parsed["parsed_stix"]
            results_build = []
            for result in results:
                stix_attribute = result["attribute"]
                stix_value = result["value"]

                if stix_attribute == "domain-name:value":
                    new_stix_attribute = stix_attribute.replace(
                        "domain-name:value", "domain_name"
                    )
                elif stix_attribute == "file:name":
                    new_stix_attribute = stix_attribute.replace("file:name", "filename")
                elif stix_attribute == "hostname:value":
                    new_stix_attribute = stix_attribute.replace(
                        "hostname:value", "domain_name"
                    )
                elif stix_attribute == "ipv4-addr:value":
                    new_stix_attribute = stix_attribute.replace(
                        "ipv4-addr:value", "ip_both"
                    )
                elif stix_attribute == "ipv6-addr:value":
                    new_stix_attribute = stix_attribute.replace(
                        "ipv6-addr:value", "ip_both"
                    )
                elif stix_attribute == "url:value":
                    new_stix_attribute = stix_attribute.replace("url:value", "url")
                elif stix_attribute == "file:hashes.'SHA-256'":
                    new_stix_attribute = stix_attribute.replace(
                        "file:hashes.'SHA-256'", "hash"
                    )
                elif stix_attribute == "file:hashes.MD5":
                    new_stix_attribute = stix_attribute.replace(
                        "file:hashes.MD5", "hash"
                    )
                elif stix_attribute == "file:hashes.'SHA-1'":
                    new_stix_attribute = stix_attribute.replace(
                        "file:hashes.'SHA-1'", "hash"
                    )
                elif stix_attribute == "file:hashes.'SHA-512'":
                    new_stix_attribute = stix_attribute.replace(
                        "file:hashes.'SHA-512'", "hash"
                    )
                else:
                    new_stix_attribute = None

                    self.helper.connector_logger.error(
                        "[ERROR] Stix attribute type is not supported",
                        {"stix_attribute": stix_attribute},
                    )

                data["stix_attribute"] = new_stix_attribute
                data["stix_value"] = stix_value
                results_build.append(
                    self.build_stix_indicator_object(data, entity, True)
                )
            return results_build

    def get_and_match_element(
        self, data, uri, data_search, source_list_id, reverse_patch=None
    ):
        get_indicator = self._query(
            "get", f"/{uri}/?search={data_search}&source_id={source_list_id}"
        )
        if uri == "IOCRule":
            if get_indicator is None or get_indicator["count"] == 0:
                return
            else:
                if "source_ref" in data:
                    data_id = data["source_ref"]
                    data_source_value = (
                        OpenCTIConnectorHelper.get_attribute_in_extension(
                            "source_value", data
                        )
                    )
                    data_target_value = (
                        OpenCTIConnectorHelper.get_attribute_in_extension(
                            "target_value", data
                        )
                    )

                    if data_source_value == data_target_value:
                        return
                else:
                    data_id = data["id"]
                harfanglab_ioc_id = json.loads(get_indicator["results"][0]["comment"])[
                    "indicator_id"
                ]

                if reverse_patch is not None:
                    if len(reverse_patch) > 3:
                        if "value" in reverse_patch[3]:
                            data_previous_id = reverse_patch[3]["value"]
                        else:
                            return
                        if harfanglab_ioc_id != data_previous_id:
                            return
                    else:
                        if data_id != harfanglab_ioc_id:
                            return
                else:
                    if data_id != harfanglab_ioc_id:
                        return

        return self.find_data_name_match(get_indicator["results"], data_search)

    def pattern_payload(self, data, enabled=True):
        if "entity_type" in data:
            if data["entity_type"] == "hash":
                data["pattern_type"] = "stix"

        if data["pattern_type"] == "yara":
            return {
                "content": data["content"],
                "name": data["name"],
                "source_id": self.yara_list_id,
                "enabled": enabled,
                "hl_local_testing_status": "in_progress",
                "hl_status": self.harfanglab_rule_maturity,
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
                "type": data["entity_type"],
                "value": data["value"],
                "source_id": self.stix_list_id,
                "enabled": enabled,
                "comment": json.dumps(data["comment"]),
                "hl_status": self.harfanglab_rule_maturity,
                "description": data["description"],
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
            self.helper.connector_logger.info(
                "[API] Resource created successfully",
                {"status_code": response.status_code},
            )
            return {"response": response.json(), "status_code": response.status_code}
        elif response.status_code == 204:
            return self.helper.connector_logger.info(
                "[API] Resource deleted successfully",
                {"status_code": response.status_code},
            )
        elif response.status_code == 400:
            return self.helper.connector_logger.error(
                "[API] Bad Request",
                {
                    "status_code": response.status_code,
                    "message": json.loads(response.content),
                },
            )
        elif response.status_code == 401:
            return self.helper.connector_logger.error(
                "[API] Query failed, permission denied",
                {"status_code": response.status_code},
            )
        elif response.status_code == 500:
            return self.helper.connector_logger.error(
                "[API] Internal Server Error", {"status_code": response.status_code}
            )
        else:
            return self.helper.connector_logger.info(
                "[API]", {"status_code": response.status_code, "message": response.text}
            )

    def start(self):
        self.sightings = Sightings(
            self.helper,
            self.harfanglab_ssl_verify,
            self.harfanglab_url,
            self.headers,
            self.harfanglab_source_list_name,
            self.harfanglab_import_security_events_as_incidents,
            self.harfanglab_import_security_events_filters_by_status,
            self.harfanglab_import_filters_by_alert_type,
            self.harfanglab_import_threats_as_case_incidents,
            self.harfanglab_default_markings,
            self.harfanglab_rule_maturity,
            self.default_score,
        )
        self.sightings.start()
        self.helper.listen_stream(self._process_message)


if __name__ == "__main__":
    try:
        HarfangLabInstance = HarfangLabConnector()
        HarfangLabInstance.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
