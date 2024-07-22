import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta

import requests
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable
from sightings import Sightings
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


class SentinelConnector:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        # Get Enviornment Variables
        self.helper = OpenCTIConnectorHelper(config)
        self.tenant_id = get_config_variable(
            "TENANT_ID", ["sentinel", "tenant_id"], config
        )
        self.client_id = get_config_variable(
            "CLIENT_ID", ["sentinel", "client_id"], config
        )
        self.client_secret = get_config_variable(
            "CLIENT_SECRET", ["sentinel", "client_secret"], config
        )
        self.login_url = get_config_variable(
            "LOGIN_URL", ["sentinel", "login_url"], config
        )
        self.resource_url = get_config_variable(
            "RESOURCE_URL", ["sentinel", "resource_url"], config
        )
        self.request_url = get_config_variable(
            "REQUEST_URL", ["sentinel", "request_url"], config
        )
        self.incident_url = get_config_variable(
            "INCIDENT_URL", ["sentinel", "incident_url"], config
        )
        self.sentinel_url = get_config_variable(
            "SENTINEL_URL", ["sentinel", "sentinel_url"], config
        )
        self.confidence_level = get_config_variable(
            "CONFIDENCE_LEVEL", ["sentinel", "confidence_level"], config
        )
        self.expire_time = get_config_variable(
            "EXPIRE_TIME", ["sentinel", "expire_time"], config
        )
        self.target_product = get_config_variable(
            "TARGET_PRODUCT", ["sentinel", "target_product"], config
        )
        self.action = get_config_variable("ACTION", ["sentinel", "action"], config)
        self.tlp_level = get_config_variable(
            "TLP_LEVEL", ["sentinel", "tlp_level"], config
        )
        self.passive_only = get_config_variable(
            "PASSIVE_ONLY", ["sentinel", "passive_only"], config
        )
        self.import_incidents = get_config_variable(
            "IMPORT_INCIDENTS", ["sentinel", "import_incidents"], config
        )
        self.header = None

    def _graph_api_authorization(self):
        try:
            url = (
                f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
            )
            oauth_data = {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "grant_type": "client_credentials",
                "scope": "https://graph.microsoft.com/.default",
            }
            response = requests.post(url, data=oauth_data)
            response_json = json.loads(response.text)
            oauth_token = response_json["access_token"]
            self.headers = {"Authorization": oauth_token}
        except Exception as e:
            raise ValueError("[ERROR] Failed generating oauth token {" + str(e) + "}")

    def _extract_action(self, data):
        # Action condition based on confidence score if action is not set
        if self.action:
            action = self.action
        else:
            score = OpenCTIConnectorHelper.get_attribute_in_extension("score", data)
            if score is None:
                action = "unknown"
            elif score >= self.confidence_level:
                action = "block"
            elif score < self.confidence_level and score != 0:
                action = "alert"
            elif score == 0:
                action = "allow"
            else:
                action = "unknown"
        return action

    def _search_ti_indicator(self, external_id):
        param = f"$filter=externalId eq '{external_id}'"
        uri = self.resource_url + self.request_url + "?" + param
        response = requests.get(uri, headers=self.headers)
        if response.status_code == 206:
            if len(response.json()["value"]) == 1:
                return response.json()["value"][0]["id"]

    def _create_indicator(self, data, method):
        internal_id = OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
        try:
            translation = stix_translation.StixTranslation()
            parsed = translation.translate("splunk", "parse", "{}", data["pattern"])
            if "parsed_stix" in parsed:
                results = parsed["parsed_stix"]
                for result in results:
                    stix_value = result["value"]
                    if result["attribute"] in [
                        "domain-name:value",
                        "hostname:value",
                        "ipv4-addr:value",
                        "ipv6-addr:value",
                        "url:value",
                    ]:
                        stix_type = result["attribute"].replace(":value", "")
                        data["type"] = stix_type
                        data["value"] = stix_value
                        self._create_observable(data, method)
                    elif result["attribute"] == "file:hashes.'SHA-256'":
                        data["type"] = "file"
                        data["hashes"] = {"SHA-256": stix_value}
                        self._create_observable(data, method)
        except:
            self.helper.connector_logger.warning(
                "[CREATE] Cannot convert STIX indicator { " + internal_id + "}"
            )

    def _create_observable(self, data, method):
        self._graph_api_authorization()
        internal_id = OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
        ioc_type = None
        match data["type"]:
            case "ipv4-addr":
                ioc_type = "networkIPv4"
            case "url":
                ioc_type = "url"
            case "domain-name":
                ioc_type = "domainName"
            case "ipv6-addr":
                ioc_type = "networkIPv6"
            case "email-addr":
                ioc_type = "email"
            case "file":
                ioc_type = "file"
        action = self._extract_action(data)
        stix_description = OpenCTIConnectorHelper.get_attribute_in_extension(
            "description", data
        )
        description = (
            stix_description[0:99] if stix_description is not None else "No description"
        )
        updated_at = OpenCTIConnectorHelper.get_attribute_in_extension(
            "updated_at", data
        )
        datetime_object = datetime.strptime(updated_at, "%Y-%m-%dT%H:%M:%S.%fZ")
        days = int(self.expire_time)
        age = timedelta(days)
        expire_datetime = datetime_object + age
        expiration_datetime = str(expire_datetime.strftime("%Y-%m-%dT%H:%M:%SZ"))
        labels = OpenCTIConnectorHelper.get_attribute_in_extension("labels", data)
        tags = labels + ["opencti"] if labels is not None else ["opencti"]
        # Threat Type - Defaults to WatchList but checks for other tags. Will only use one tag
        # https://learn.microsoft.com/en-us/graph/api/resources/tiindicator?view=graph-rest-beta#threat_type-values
        threat_type = "WatchList"
        if labels is not None:
            for label in labels:
                if label.upper() == "BOTNET":
                    threat_type = "Botnet"
                elif label.upper() == "C2":
                    threat_type = "C2"
                elif label.upper() == "CRYPTOMINING":
                    threat_type = "CryptoMining"
                elif label.upper() == "DARKNET":
                    threat_type = "Darknet"
                elif label.upper() == "DDOS":
                    threat_type = "DDoS"
                elif label.upper() == "MALICIOUSURL":
                    threat_type = "MaliciousUrl"
                elif label.upper() == "MALWARE":
                    threat_type = "Malware"
                elif label.upper() == "PHISHING":
                    threat_type = "Phishing"
                elif label.upper() == "PROXY":
                    threat_type = "Proxy"
                elif label.upper() == "PUA":
                    threat_type = "PUA"
        # TLP
        # https://learn.microsoft.com/en-us/graph/api/resources/tiindicator?view=graph-rest-beta#tlplevel-values
        if self.tlp_level:
            tlpLevel = self.tlp_level
        elif "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed" in str(data):
            tlpLevel = "red"
        elif "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37" in str(
            data
        ) or "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82" in str(data):
            tlpLevel = "amber"
        elif "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da" in str(data):
            tlpLevel = "green"
        elif "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9" in str(data):
            tlpLevel = "white"
        else:
            tlpLevel = "unknown"
        # File
        file_name = data.get("name", None)
        file_size = data.get("size", 0)
        # Confidence
        confidence = data.get("confidence", 50)
        # Passive only
        if self.passive_only:
            passive_only = "true"
        else:
            passive_only = "false"

        self.helper.connector_logger.info(
            "[" + method.upper() + "] Processing data {" + internal_id + "}"
        )
        # Do any processing needed
        data["_key"] = internal_id

        # Check for IOC type and send request
        # This is for network based IOCs
        body = {}
        if (
            ioc_type == "networkIPv4"
            or ioc_type == "url"
            or ioc_type == "domainName"
            or ioc_type == "networkIPv6"
        ):
            body = {
                ioc_type: data["value"],
                "action": action,
                "description": description,
                "expirationDateTime": expiration_datetime,
                "targetProduct": self.target_product,
                "threatType": threat_type,
                "tlpLevel": tlpLevel,
                "externalId": internal_id,
                "lastReportedDateTime": str(updated_at),
                "passiveOnly": passive_only,
                "tags": tags,
                "confidence": confidence,
            }
        # This is for email based IOCs
        elif ioc_type == "email":
            body = {
                "emailSenderAddress": data["value"],
                "emailSenderName": data["display_name"],
                "action": action,
                "description": description,
                "expirationDateTime": expiration_datetime,
                "targetProduct": self.target_product,
                "threatType": threat_type,
                "tlpLevel": tlpLevel,
                "externalId": internal_id,
                "lastReportedDateTime": str(updated_at),
                "passiveOnly": passive_only,
                "tags": tags,
                "confidence": confidence,
            }
        # This is for file types. Does a check for MD5, SHA1, and SHA256 being present. Must contain at least one hash value
        elif ioc_type == "file":
            created_date = self.helper.get_attribute_in_extension("created_at", data)
            if "MD5" in data["hashes"]:
                body = {
                    "fileCreatedDateTime": created_date,
                    "fileHashType": "md5",
                    "fileHashValue": data["hashes"]["MD5"],
                    "fileName": file_name,
                    "fileSize": file_size,
                    "action": action,
                    "description": description,
                    "expirationDateTime": expiration_datetime,
                    "targetProduct": self.target_product,
                    "threatType": threat_type,
                    "tlpLevel": tlpLevel,
                    "externalId": internal_id,
                    "lastReportedDateTime": str(updated_at),
                    "passiveOnly": passive_only,
                    "tags": tags,
                }
            if "SHA-1" in data["hashes"]:
                body = {
                    "fileCreatedDateTime": created_date,
                    "fileHashType": "sha1",
                    "fileHashValue": data["hashes"]["SHA-1"],
                    "fileName": file_name,
                    "fileSize": file_size,
                    "action": action,
                    "description": description,
                    "expirationDateTime": expiration_datetime,
                    "targetProduct": self.target_product,
                    "threatType": threat_type,
                    "tlpLevel": tlpLevel,
                    "externalId": internal_id,
                    "lastReportedDateTime": str(updated_at),
                    "passiveOnly": passive_only,
                    "tags": tags,
                    "confidence": confidence,
                }
            if "SHA-256" in data["hashes"]:
                body = {
                    "fileCreatedDateTime": created_date,
                    "fileHashType": "sha256",
                    "fileHashValue": data["hashes"]["SHA-256"],
                    "fileName": file_name,
                    "fileSize": file_size,
                    "action": action,
                    "description": description,
                    "expirationDateTime": expiration_datetime,
                    "targetProduct": self.target_product,
                    "threatType": threat_type,
                    "tlpLevel": tlpLevel,
                    "externalId": internal_id,
                    "lastReportedDateTime": str(updated_at),
                    "passiveOnly": passive_only,
                    "tags": tags,
                    "confidence": confidence,
                }
        if body:
            response = None
            if method == "create":
                response = requests.post(
                    self.resource_url + self.request_url,
                    json=body,
                    headers=self.headers,
                )
            elif method == "update":
                ti_indicator_id = self._search_ti_indicator(body["externalId"])
                if ti_indicator_id:
                    response = requests.patch(
                        self.resource_url + self.request_url + "/" + ti_indicator_id,
                        json=body,
                        headers=self.headers,
                    )
                else:
                    self.helper.connector_logger.error(
                        "[UPDATE] ID "
                        + internal_id
                        + " failed. "
                        + "Unable to find an existing tiIndicator "
                        + "with external_id:"
                        + body["externalId"]
                    )
                    return

            # Log if the creation was successful or not
            if response is not None:
                if "201" in str(response):
                    self.helper.connector_logger.info(
                        "[CREATE] ID {" + internal_id + " Success }"
                    )
                    result = response.json()
                    external_reference = self.helper.api.external_reference.create(
                        source_name=self.target_product.replace("Azure", "Microsoft"),
                        external_id=result["id"],
                        description="Intel within the Microsoft platform.",
                    )
                    if "pattern" in data:
                        self.helper.api.stix_domain_object.add_external_reference(
                            id=internal_id,
                            external_reference_id=external_reference["id"],
                        )
                    else:
                        self.helper.api.stix_cyber_observable.add_external_reference(
                            id=internal_id,
                            external_reference_id=external_reference["id"],
                        )
                elif "204" in str(response):
                    self.helper.connector_logger.info(
                        "[UPDATE] ID {" + internal_id + " Success }"
                    )
                else:
                    self.helper.connector_logger.error(
                        "[CREATE/UPDATE] ID {"
                        + internal_id
                        + " Failed and got }"
                        + str(response)
                        + " status code."
                    )

    def _delete_object(self, data):
        self._graph_api_authorization()
        internal_id = OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
        self.helper.connector_logger.info(
            "[DELETE] Processing data {" + internal_id + "}"
        )
        # Gets a list of all IOC in Microsoft Platform and looks for externalID which is for OpenCTI reference
        response = requests.get(
            self.resource_url + self.request_url, headers=self.headers
        )
        getIOC = response.json()
        did_delete = 0
        # Loop through all Microsoft IOCs to see if the external ID matches the OpenCTI Object id
        for i in range(len(getIOC["value"])):
            if getIOC["value"][i]["externalId"] == internal_id:
                ioc_id = getIOC["value"][i]["id"]
                requests.delete(
                    self.resource_url + self.request_url + "/" + ioc_id,
                    headers=self.headers,
                )
                self.helper.connector_logger.info(
                    "[DELETE] ID {" + internal_id + "} Success"
                )
                if data["type"] == "indicator":
                    entity = self.helper.api.indicator.read(id=internal_id)
                else:
                    entity = self.helper.api.stix_cyber_observable.read(id=internal_id)
                if (
                    entity
                    and "externalReferences" in entity
                    and len(entity["externalReferences"]) > 0
                ):
                    for external_reference in entity["externalReferences"]:
                        if external_reference[
                            "source_name"
                        ] == self.target_product.replace("Azure", "Microsoft"):
                            self.helper.api.external_reference.delete(
                                external_reference["id"]
                            )
                did_delete = 1
        # Logs not found if no IOCs were deleted
        if did_delete == 0:
            self.helper.connector_logger.info(
                "[DELETE] ID {"
                + internal_id
                + "} Not found on "
                + self.target_product.replace("Azure", "Microsoft")
            )

    def _process_message(self, msg):
        try:
            data = json.loads(msg.data)["data"]
            if msg.event == "create" or msg.event == "update":
                if data["type"] == "indicator" and data["pattern_type"].startswith(
                    "stix"
                ):
                    self._create_indicator(data, msg.event)
                elif data["type"] in [
                    "ipv4-addr",
                    "ipv6-addr",
                    "domain-name",
                    "hostname",
                    "url",
                    "email-addr",
                    "file",
                ]:
                    self._create_observable(data, msg.event)
            elif msg.event == "delete":
                self._delete_object(data)
        except Exception as ex:
            self.helper.connector_logger.error(
                "[ERROR] Failed processing data {" + str(ex) + "}"
            )
            self.helper.connector_logger.error(
                "[ERROR] Message data {" + str(msg) + "}"
            )
            return None

    # Listen to OpenCTI stream and calls the _process_message function
    def start(self):
        if self.import_incidents:
            self.sightings = Sightings(
                self.helper,
                self.tenant_id,
                self.client_id,
                self.client_secret,
                self.resource_url,
                self.incident_url,
                self.target_product,
            )
            self.sightings.start()
        self.helper.listen_stream(self._process_message)


if __name__ == "__main__":
    fix_loggers()
    try:
        connector = SentinelConnector()
        connector.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
