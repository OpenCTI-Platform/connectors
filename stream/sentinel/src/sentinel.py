import json
import os
import sys
import time
from datetime import datetime, timedelta

import requests
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable


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

    # Read from OpenCTI then push new, update, or delete to Sentinel
    def _process_message(self, msg):
        data = json.loads(msg.data)["data"]
        # Generate oAuth token on create events for specific IOC type.
        if ((msg.event == "create") and (data["type"] == "ipv4-addr" or data["type"] == "url" or data["type"] == "domain-name" or data["type"] == "ipv6-addr" or data["type"] == "email-addr" or data["type"] == "file")) or (msg.event == "delete"):
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
                headers = {"Authorization": oauth_token}

            # Check for oAuth Token failures
            except Exception as e:
                self.helper.log_error(
                    "[ERROR] Failed generating oauth token {" + str(e) + "}"
                )
                return None

            try:
                # Check on type of IOC for Creation events
                # Update events is a future plan msg.event == 'update'
                # https://learn.microsoft.com/en-us/graph/api/resources/tiindicator?view=graph-rest-beta#indicator-observables
                if (msg.event == "create"):
                    if data["type"] == "ipv4-addr":
                        ioc_type = "networkIPv4"
                    elif data["type"] == "url":
                        ioc_type = "url"
                    elif data["type"] == "domain-name":
                        ioc_type = "domainName"
                    elif data["type"] == "ipv6-addr":
                        ioc_type = "networkIPv6"
                    elif data["type"] == "email-addr":
                        ioc_type = "email"
                    elif data["type"] == "file":
                        ioc_type = "file"

                    # Action condition based on confidence score if action is not set
                    if self.action:
                        action = self.action
                    elif (
                        OpenCTIConnectorHelper.get_attribute_in_extension("score", data)
                        >= self.confidence_level
                    ):
                        action = "block"
                    elif (
                        OpenCTIConnectorHelper.get_attribute_in_extension("score", data)
                        < self.confidence_level
                        and OpenCTIConnectorHelper.get_attribute_in_extension("score", data)
                        != 0
                    ):
                        action = "alert"
                    elif (
                        OpenCTIConnectorHelper.get_attribute_in_extension("score", data)
                        == 0
                    ):
                        action = "allow"
                    else:
                        action = "unknown"

                    # Description - Limited to 100 characters
                    if (
                        OpenCTIConnectorHelper.get_attribute_in_extension(
                            "description", data
                        )
                        is not None
                    ):
                        description = OpenCTIConnectorHelper.get_attribute_in_extension(
                            "description", data
                        )[0:99]
                    else:
                        description = "No description"

                    # Timestamps
                    updated_at = OpenCTIConnectorHelper.get_attribute_in_extension(
                        "updated_at", data
                    )
                    datetime_object = datetime.strptime(updated_at, "%Y-%m-%dT%H:%M:%S.%fZ")
                    days=int(self.expire_time)
                    age = timedelta(days)
                    expire_datetime = datetime_object + age
                    expirationDateTime = str(expire_datetime.strftime("%Y-%m-%dT%H:%M:%SZ"))

                    # Tags - applies all tags
                    tags = []
                    if (
                        OpenCTIConnectorHelper.get_attribute_in_extension("labels", data)
                        is not None
                    ):
                        for i in range(
                            len(
                                OpenCTIConnectorHelper.get_attribute_in_extension(
                                    "labels", data
                                )
                            )
                        ):
                            tags.append(
                                OpenCTIConnectorHelper.get_attribute_in_extension(
                                    "labels", data
                                )[i]
                            )

                    # Threat Type - Defaults to WatchList but checks for other tags. Will only use one tag
                    # https://learn.microsoft.com/en-us/graph/api/resources/tiindicator?view=graph-rest-beta#threattype-values
                    threatType = "WatchList"
                    if (
                        OpenCTIConnectorHelper.get_attribute_in_extension("labels", data)
                        is not None
                    ):
                        for i in range(
                            len(
                                OpenCTIConnectorHelper.get_attribute_in_extension(
                                    "labels", data
                                )
                            )
                        ):
                            if (
                                OpenCTIConnectorHelper.get_attribute_in_extension(
                                    "labels", data
                                )[i].upper()
                                == "BOTNET"
                            ):
                                threatType = "Botnet"
                            elif (
                                OpenCTIConnectorHelper.get_attribute_in_extension(
                                    "labels", data
                                )[i].upper()
                                == "C2"
                            ):
                                threatType = "C2"
                            elif (
                                OpenCTIConnectorHelper.get_attribute_in_extension(
                                    "labels", data
                                )[i].upper()
                                == "CRYPTOMINING"
                            ):
                                threatType = "CryptoMining"
                            elif (
                                OpenCTIConnectorHelper.get_attribute_in_extension(
                                    "labels", data
                                )[i].upper()
                                == "DARKNET"
                            ):
                                threatType = "Darknet"
                            elif (
                                OpenCTIConnectorHelper.get_attribute_in_extension(
                                    "labels", data
                                )[i].upper()
                                == "DDOS"
                            ):
                                threatType = "DDoS"
                            elif (
                                OpenCTIConnectorHelper.get_attribute_in_extension(
                                    "labels", data
                                )[i].upper()
                                == "MALICIOUSURL"
                            ):
                                threatType = "MaliciousUrl"
                            elif (
                                OpenCTIConnectorHelper.get_attribute_in_extension(
                                    "labels", data
                                )[i].upper()
                                == "MALWARE"
                            ):
                                threatType = "Malware"
                            elif (
                                OpenCTIConnectorHelper.get_attribute_in_extension(
                                    "labels", data
                                )[i].upper()
                                == "PHISHING"
                            ):
                                threatType = "Phishing"
                            elif (
                                OpenCTIConnectorHelper.get_attribute_in_extension(
                                    "labels", data
                                )[i].upper()
                                == "PROXY"
                            ):
                                threatType = "Proxy"
                            elif (
                                OpenCTIConnectorHelper.get_attribute_in_extension(
                                    "labels", data
                                )[i].upper()
                                == "PUA"
                            ):
                                threatType = "PUA"
                            elif (
                                OpenCTIConnectorHelper.get_attribute_in_extension(
                                    "labels", data
                                )[i].upper()
                                == "WATCHLIST"
                            ):
                                threatType = "WatchList"

                    # TLP
                    # https://learn.microsoft.com/en-us/graph/api/resources/tiindicator?view=graph-rest-beta#tlplevel-values
                    if self.tlp_level:
                        tlpLevel = self.tlp_level
                    elif "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed" in str(
                        data
                    ):
                        tlpLevel = "red"
                    elif "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37" in str(
                        data
                    ) or "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82" in str(
                        data
                    ):
                        tlpLevel = "amber"
                    elif "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da" in str(
                        data
                    ):
                        tlpLevel = "green"
                    elif "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9" in str(
                        data
                    ):
                        tlpLevel = "white"
                    else:
                        tlpLevel = "unknown"

                    # Passive Mode Check
                    if self.passive_only == "True":
                        passiveOnly = "true"
                    else:
                        passiveOnly = "false"

                    # File Name
                    try:
                        if data["name"] is not None:
                            file_name = data["name"]
                    except:
                        file_name = "Not Provided"

                    # File Size
                    try:
                        if data["size"] is not None:
                            file_size = data["size"]
                    except:
                        file_size = "0"

                    # Handles creation events
                    # https://learn.microsoft.com/en-us/graph/api/tiindicators-post?view=graph-rest-beta&tabs=http
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

                        headers = {"Authorization": oauth_token}

                        # Check for IOC type and send request
                        # This is for network based IOCS
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
                                "expirationDateTime": expirationDateTime,
                                "targetProduct": self.target_product,
                                "threatType": threatType,
                                "tlpLevel": tlpLevel,
                                "externalId": OpenCTIConnectorHelper.get_attribute_in_extension(
                                    "id", data
                                ),
                                "lastReportedDateTime": str(updated_at),
                                "passiveOnly": passiveOnly,
                                "tags": tags,
                            }
                            response = requests.post(
                                self.resource_url + self.request_url,
                                json=body,
                                headers=headers,
                            )
                        # This is for email based IOCs
                        elif ioc_type == "email":
                            body = {
                                "emailSenderAddress": data["value"],
                                "emailSenderName": data["display_name"],
                                "action": action,
                                "description": description,
                                "expirationDateTime": expirationDateTime,
                                "targetProduct": self.target_product,
                                "threatType": threatType,
                                "tlpLevel": tlpLevel,
                                "externalId": OpenCTIConnectorHelper.get_attribute_in_extension(
                                    "id", data
                                ),
                                "lastReportedDateTime": str(updated_at),
                                "passiveOnly": passiveOnly,
                                "tags": tags,
                            }
                            response = requests.post(
                                self.resource_url + self.request_url,
                                json=body,
                                headers=headers,
                            )
                        # This is for file types. Does a check for MD5, SHA1, and SHA256 being present. Must contain at least one hash value
                        elif ioc_type == "file":
                            if "MD5" in data["hashes"]:
                                body = {
                                    "fileCreatedDateTime": data["ctime"],
                                    "fileHashType": "md5",
                                    "fileHashValue": data["hashes"]["MD5"],
                                    "fileName": file_name,
                                    "fileSize": file_size,
                                    "action": action,
                                    "description": description,
                                    "expirationDateTime": expirationDateTime,
                                    "targetProduct": self.target_product,
                                    "threatType": threatType,
                                    "tlpLevel": tlpLevel,
                                    "externalId": OpenCTIConnectorHelper.get_attribute_in_extension(
                                        "id", data
                                    ),
                                    "lastReportedDateTime": str(updated_at),
                                    "passiveOnly": passiveOnly,
                                    "tags": tags,
                                }
                                response = requests.post(
                                    self.resource_url + self.request_url,
                                    json=body,
                                    headers=headers,
                                )
                            if "SHA-1" in data["hashes"]:
                                body = {
                                    "fileCreatedDateTime": data["ctime"],
                                    "fileHashType": "sha1",
                                    "fileHashValue": data["hashes"]["SHA-1"],
                                    "fileName": file_name,
                                    "fileSize": file_size,
                                    "action": action,
                                    "description": description,
                                    "expirationDateTime": expirationDateTime,
                                    "targetProduct": self.target_product,
                                    "threatType": threatType,
                                    "tlpLevel": tlpLevel,
                                    "externalId": OpenCTIConnectorHelper.get_attribute_in_extension(
                                        "id", data
                                    ),
                                    "lastReportedDateTime": str(updated_at),
                                    "passiveOnly": passiveOnly,
                                    "tags": tags,
                                }
                                response = requests.post(
                                    self.resource_url + self.request_url,
                                    json=body,
                                    headers=headers,
                                )
                            if "SHA-256" in data["hashes"]:
                                body = {
                                    "fileCreatedDateTime": data["ctime"],
                                    "fileHashType": "sha256",
                                    "fileHashValue": data["hashes"]["SHA-256"],
                                    "fileName": file_name,
                                    "fileSize": file_size,
                                    "action": action,
                                    "description": description,
                                    "expirationDateTime": expirationDateTime,
                                    "targetProduct": self.target_product,
                                    "threatType": threatType,
                                    "tlpLevel": tlpLevel,
                                    "externalId": OpenCTIConnectorHelper.get_attribute_in_extension(
                                        "id", data
                                    ),
                                    "lastReportedDateTime": str(updated_at),
                                    "passiveOnly": passiveOnly,
                                    "tags": tags,
                                }
                                response = requests.post(
                                    self.resource_url + self.request_url,
                                    json=body,
                                    headers=headers,
                                )

                        # Log if the creation was successful or not
                        if "201" in str(response):
                            self.helper.log_info(
                                "[CREATE] ID {"
                                + OpenCTIConnectorHelper.get_attribute_in_extension(
                                    "id", data
                                )
                                + " Success }"
                            )
                        else:
                            self.helper.log_info(
                                "[CREATE] ID {"
                                + OpenCTIConnectorHelper.get_attribute_in_extension(
                                    "id", data
                                )
                                + " Failed and got }"
                                + response
                                + " status code."
                            )

                    # Handles update events - This section is not yet fully developed and is commented out
                    # Only allows the updating of these OpenCTI related fields action, confidence, description, expirationDateTime, externalId, tags, and tlpLevel
                    # https://learn.microsoft.com/en-us/graph/api/tiindicator-update?view=graph-rest-beta&tabs=http
                    # if msg.event == "update":
                    #     self.helper.log_info(
                    #         "[UPDATE] Processing data {"
                    #         + OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
                    #         + "}"
                    #     )
                    #     data["_key"] = OpenCTIConnectorHelper.get_attribute_in_extension(
                    #         "id", data
                    #     )

                    #     # Gets a list of all IOC in Microsoft Platform and looks for externalID which is for OpenCTI reference
                    #     response = requests.get(self.resource_url + self.request_url, headers=headers)
                    #     getIOC = response.json()
                    #     for i in range(len(getIOC['value'])):
                    #         if getIOC['value'][i]['externalId'] == OpenCTIConnectorHelper.get_attribute_in_extension("id", data):
                    #             ioc_id = getIOC['value'][i]['id']
                    #             break
                    #         else:
                    #             ioc_id = None

                    #     if ioc_id is not None:
                    #         response = requests.patch(self.resource_url + self.request_url + '/' + ioc_id, json=body, headers=headers)
                    #         self.helper.log_info(
                    #         "[UPDATE] ID {"
                    #         + OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
                    #         + " Success }" +  self.target_product
                    #     )
                    #     else:
                    #         self.helper.log_info(
                    #         "[UPDATE] ID {"
                    #         + OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
                    #         + " Not found on }" +  self.target_product
                    #     )

                # Handles delete events
                # https://learn.microsoft.com/en-us/graph/api/tiindicator-delete?view=graph-rest-beta&tabs=http
                elif msg.event == "delete":
                    self.helper.log_info(
                        "[DELETE] Processing data {"
                        + OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
                        + "}"
                    )

                    # Gets a list of all IOC in Microsoft Platform and looks for externalID which is for OpenCTI reference
                    response = requests.get(
                        self.resource_url + self.request_url, headers=headers
                    )
                    getIOC = response.json()
                    did_delete = 0

                    # Loop through all Microsoft IOCs to see if the external ID matches the OpenCTI Object id
                    for i in range(len(getIOC["value"])):
                        if getIOC["value"][i][
                            "externalId"
                        ] == OpenCTIConnectorHelper.get_attribute_in_extension("id", data):
                            ioc_id = getIOC["value"][i]["id"]
                            response = requests.delete(
                                self.resource_url + self.request_url + "/" + ioc_id,
                                headers=headers,
                            )
                            self.helper.log_info(
                                "[DELETE] ID {"
                                + OpenCTIConnectorHelper.get_attribute_in_extension(
                                    "id", data
                                )
                                + "} Success"
                            )
                            did_delete = 1

                    # Logs not found if no IOCs were deleted
                    if did_delete == 0:
                        self.helper.log_info(
                            "[DELETE] ID {"
                            + OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
                            + "} Not found on "
                            + self.target_product
                        )
                return None

            # Error exception for failure
            except Exception as e:
                self.helper.log_error("[ERROR] Failed processing data {" + str(e) + "}")
                self.helper.log_error("[ERROR] Message data {" + str(msg) + "}")
                return None

    # Listen to OpenCTI stream and calls the _process_message function
    def start(self):
        self.helper.listen_stream(self._process_message)


if __name__ == "__main__":
    try:
        connector = SentinelConnector()
        connector.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
