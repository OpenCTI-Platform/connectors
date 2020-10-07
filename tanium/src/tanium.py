################################
# Tanium Connector for OpenCTI #
################################

import os
import yaml
import json
import re
import requests
import threading
import time

from dateutil.parser import parse
from stix2slider import slide_string
from stix2slider.options import initialize_options
from pycti import OpenCTIConnectorHelper, get_config_variable, StixCyberObservableTypes


class TaniumConnectorAlertsGatherer(threading.Thread):
    def __init__(self, helper, tanium_url, tanium_login, tanium_password):
        threading.Thread.__init__(self)
        self.helper = helper
        self.tanium_url = tanium_url
        self.tanium_login = tanium_login
        self.tanium_password = tanium_password

        # Variables
        self.session = None
        # Open a session
        self._get_session()

        # Identity
        self.identity = self.helper.api.identity.create(
            type="Organization",
            name=self.helper.get_name(),
            description=self.helper.get_name(),
        )

    def _get_session(self):
        payload = {
            "username": self.tanium_login,
            "password": self.tanium_password,
        }
        r = requests.post(self.tanium_url + "/api/v2/session/login", json=payload)
        if r.status_code == 200:
            result = r.json()
            self.session = result["data"]["session"]
        else:
            raise ValueError("Cannot login to the Tanium API")

    def _query(
        self,
        method,
        uri,
        payload=None,
        content_type="application/json",
        type=None,
        retry=False,
    ):
        headers = {"session": self.session, "content-type": content_type, "type": type}
        if content_type == "application/octet-stream":
            headers["content-disposition"] = (
                "attachment; filename=" + payload["filename"]
            )
            headers["name"] = payload["name"]
            headers["description"] = payload["description"]
        if method == "get":
            r = requests.get(self.tanium_url + uri, headers=headers, params=payload)
        elif method == "post":
            if content_type == "application/octet-stream":
                r = requests.post(
                    self.tanium_url + uri,
                    headers=headers,
                    data=payload["document"],
                )
            elif type is not None:
                r = requests.post(
                    self.tanium_url + uri, headers=headers, data=payload["intelDoc"]
                )
            else:
                r = requests.post(self.tanium_url + uri, headers=headers, json=payload)
        elif method == "put":
            r = requests.put(self.tanium_url + uri, headers=headers, json=payload)
        elif method == "patch":
            r = requests.patch(self.tanium_url + uri, headers=headers, json=payload)
        elif method == "delete":
            r = requests.delete(self.tanium_url + uri, headers=headers)
        else:
            raise ValueError("Unspported method")
        if r.status_code == 200:
            try:
                return r.json()
            except:
                return r.text
        elif r.status_code == 401 and not retry:
            self._get_session()
            self._query(method, uri, payload, content_type, type, True)
        elif r.status_code == 401:
            raise ValueError("Query failed, permission denied")
        else:
            pass

    def run(self):
        while True:
            alerts = self._query(
                "get", "/plugin/products/detect3/api/v1/alerts", {"sort": "-createdAt"}
            )
            state = self.helper.get_state()
            if "lastAlertTimestamp" in state:
                last_timestamp = state["lastAlertTimestamp"]
            else:
                last_timestamp = 0
            alerts = reversed(alerts)
            for alert in alerts:
                alert_timestamp = parse(alert["createdAt"]).timestamp()
                if int(alert_timestamp) > int(last_timestamp):
                    # Mark as processed
                    if state is not None:
                        state["lastAlertTimestamp"] = parse(
                            alert["createdAt"]
                        ).timestamp()
                        self.helper.set_state(state)
                    else:
                        self.helper.set_state(
                            {
                                "lastAlertTimestamp": parse(
                                    alert["createdAt"]
                                ).timestamp()
                            }
                        )
                    # Check if the intel is in OpenCTI
                    external_reference = self.helper.api.external_reference.read(
                        filters=[
                            {"key": "source_name", "values": ["Tanium"]},
                            {
                                "key": "external_id",
                                "values": [str(alert["intelDocId"])],
                            },
                        ]
                    )
                    if external_reference is not None:
                        entity = self.helper.api.stix_domain_object.read(
                            filters=[
                                {
                                    "key": "hasExternalReference",
                                    "values": [external_reference["id"]],
                                }
                            ]
                        )
                        if entity is None:
                            entity = self.helper.api.stix_cyber_observable.read(
                                filters=[
                                    {
                                        "key": "hasExternalReference",
                                        "values": [external_reference["id"]],
                                    }
                                ]
                            )
                        if entity is not None:
                            self.helper.api.stix_sighting_relationship.create(
                                fromId=entity["id"],
                                toId=self.identity["id"],
                                first_seen=parse(alert["createdAt"]).strftime(
                                    "%Y-%m-%dT%H:%M:%SZ"
                                ),
                                last_seen=parse(alert["createdAt"]).strftime(
                                    "%Y-%m-%dT%H:%M:%SZ"
                                ),
                                count=1,
                                confidence=90,
                            )
            time.sleep(5)


class TaniumConnector:
    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
        self.tanium_url = get_config_variable("TANIUM_URL", ["tanium", "url"], config)
        self.tanium_login = get_config_variable(
            "TANIUM_LOGIN", ["tanium", "login"], config
        )
        self.tanium_password = get_config_variable(
            "TANIUM_PASSWORD", ["tanium", "password"], config
        )
        self.tanium_indicator_types = get_config_variable(
            "TANIUM_INDICATOR_TYPES", ["tanium", "indicator_types"], config
        ).split(",")
        self.tanium_observable_types = get_config_variable(
            "TANIUM_OBSERVABLE_TYPES", ["tanium", "observable_types"], config
        ).split(",")
        self.tanium_import_label = get_config_variable(
            "TANIUM_IMPORT_LABEL",
            ["tanium", "import_label"],
            config,
        )
        self.tanium_auto_quickscan = get_config_variable(
            "TANIUM_AUTO_QUICKSCAN", ["tanium", "auto_quickscan"], config, False, False
        )
        self.tanium_computer_groups = get_config_variable(
            "TANIUM_COMPUTER_GROUPS", ["tanium", "computer_groups"], config, False, ""
        ).split(",")

        # Variables
        self.session = None

        # Open a session
        self._get_session()

        # Create the source if not exist
        self.source_id = None
        sources = self._query("get", "/plugin/products/detect3/api/v1/sources")
        for source in sources:
            if source["name"] == "OpenCTI":
                self.source_id = source["id"]
        if self.source_id is None:
            source = self._query(
                "post",
                "/plugin/products/detect3/api/v1/sources",
                {
                    "type": "api-client",
                    "name": "OpenCTI",
                    "description": "Cyber Threat Intelligence knowledge imported from OpenCTI.",
                    "canAutoQuickScan": True,
                },
            )
            self.source_id = source["id"]

    def _get_session(self):
        payload = {
            "username": self.tanium_login,
            "password": self.tanium_password,
        }
        r = requests.post(self.tanium_url + "/api/v2/session/login", json=payload)
        if r.status_code == 200:
            result = r.json()
            self.session = result["data"]["session"]
        else:
            raise ValueError("Cannot login to the Tanium API")

    def _query(
        self,
        method,
        uri,
        payload=None,
        content_type="application/json",
        type=None,
        retry=False,
    ):
        self.helper.log_info("Query " + method + " on " + uri)
        headers = {"session": self.session, "content-type": content_type, "type": type}
        if content_type == "application/octet-stream":
            headers["content-disposition"] = (
                "attachment; filename=" + payload["filename"]
            )
            headers["name"] = payload["name"]
            headers["description"] = payload["description"]
        if method == "get":
            r = requests.get(self.tanium_url + uri, headers=headers, params=payload)
        elif method == "post":
            if content_type == "application/octet-stream":
                r = requests.post(
                    self.tanium_url + uri,
                    headers=headers,
                    data=payload["document"],
                )
            elif type is not None:
                r = requests.post(
                    self.tanium_url + uri, headers=headers, data=payload["intelDoc"]
                )
            else:
                r = requests.post(self.tanium_url + uri, headers=headers, json=payload)
        elif method == "put":
            if content_type == "application/xml":
                print(headers)
                print(payload)
                r = requests.put(self.tanium_url + uri, headers=headers, data=payload)
            else:
                r = requests.put(self.tanium_url + uri, headers=headers, json=payload)
        elif method == "patch":
            r = requests.patch(self.tanium_url + uri, headers=headers, json=payload)
        elif method == "delete":
            r = requests.delete(self.tanium_url + uri, headers=headers)
        else:
            raise ValueError("Unspported method")
        if r.status_code == 200:
            try:
                return r.json()
            except:
                return r.text
        elif r.status_code == 401 and not retry:
            self._get_session()
            return self._query(method, uri, payload, content_type, type, True)
        elif r.status_code == 401:
            raise ValueError("Query failed, permission denied")
        else:
            self.helper.log_info(r.text)

    def _get_labels(self, labels):
        # List labels
        tanium_labels = self._query(
            "get", "/plugin/products/detect3/api/v1/labels", {"limit": 500}
        )
        tanium_labels_dict = {}
        for tanium_label in tanium_labels:
            tanium_labels_dict[tanium_label["name"].lower()] = tanium_label
        final_labels = []
        for label in labels:
            # Label already exists
            if label["value"] in tanium_labels_dict:
                final_labels.append(tanium_labels_dict[label["value"]])
            # Create the label
            else:
                created_label = self._query(
                    "post",
                    "/plugin/products/detect3/api/v1/labels",
                    {
                        "name": label["value"],
                        "description": "Label imported from OpenCTI",
                    },
                )
                final_labels.append(created_label)
        return final_labels

    def _get_by_id(self, internal_id, yara=False):
        if yara:
            response = self._query(
                "get",
                "/plugin/products/detect3/api/v1/intels",
                {"name": internal_id + ".yara"},
            )
        else:
            response = self._query(
                "get",
                "/plugin/products/detect3/api/v1/intels",
                {"description": internal_id},
            )
        if response and len(response) > 0:
            return response[0]
        else:
            return None

    def _create_indicator_stix(self, entity, original_intel_document=None):
        print(original_intel_document)
        if original_intel_document is None:
            intel_document = self._get_by_id(entity["id"])
            if intel_document is not None:
                return intel_document

        stix2_bundle = self.helper.api.stix2.export_entity(
            entity["entity_type"],
            entity["id"],
            "simple",
            None,
            True,
            True,
        )
        initialize_options()
        stix_indicator = slide_string(stix2_bundle)
        stix_indicator = re.sub(
            r"<indicator:Description>(.*?)<\/indicator:Description>",
            r"<indicator:Description>" + entity["id"] + "</indicator:Description>",
            stix_indicator,
        )
        stix_indicator = re.sub(
            r"<indicator:Description ordinality=\"1\">(.*?)<\/indicator:Description>",
            r'<indicator:Description ordinality="1">'
            + entity["id"]
            + "</indicator:Description>",
            stix_indicator,
        )
        payload = {"intelDoc": stix_indicator}
        if original_intel_document is not None:
            intel_document = self._query(
                "put",
                "/plugin/products/detect3/api/v1/intels/"
                + str(original_intel_document["id"]),
                stix_indicator,
                "application/xml",
                "stix",
            )
        else:
            intel_document = self._query(
                "post",
                "/plugin/products/detect3/api/v1/sources/"
                + str(self.source_id)
                + "/intels",
                payload,
                "application/xml",
                "stix",
            )
        return intel_document

    def _create_indicator_yara(self, entity, original_intel_document=None):
        if original_intel_document is None:
            intel_document = self._get_by_id(entity["id"], True)
            if intel_document is not None:
                return intel_document

        filename = entity["id"] + ".yara"
        if original_intel_document is not None:
            intel_document = self._query(
                "put",
                "/plugin/products/detect3/api/v1/intels/"
                + str(original_intel_document["id"]),
                {
                    "filename": filename,
                    "document": entity["pattern"],
                    "name": entity["name"],
                    "description": entity["id"],
                },
                "application/octet-stream",
                "yara",
            )
        else:
            intel_document = self._query(
                "post",
                "/plugin/products/detect3/api/v1/sources/"
                + str(self.source_id)
                + "/intels",
                {
                    "filename": filename,
                    "document": entity["pattern"],
                    "name": entity["name"],
                    "description": entity["id"],
                },
                "application/octet-stream",
                "yara",
            )
        return intel_document

    def _create_tanium_signal(self, entity, original_intel_document=None):
        if original_intel_document is None:
            intel_document = self._get_by_id(entity["id"])
            if intel_document is not None:
                return intel_document

        platforms = []
        if "x_mitre_platforms" in entity and len(entity["x_mitre_platforms"]) > 0:
            for x_mitre_platform in entity["x_mitre_platforms"]:
                if x_mitre_platform in ["Linux", "Windows", "macOS"]:
                    platforms.append(
                        x_mitre_platform.lower()
                        if x_mitre_platform != "macOS"
                        else "mac"
                    )
        if original_intel_document is not None:
            intel_document = self._query(
                "put",
                "/plugin/products/detect3/api/v1/intels/"
                + str(original_intel_document["id"]),
                {
                    "name": entity["name"],
                    "description": entity["id"],
                    "platforms": platforms,
                    "contents": entity["pattern"],
                },
            )
        else:
            intel_document = self._query(
                "post",
                "/plugin/products/detect3/api/v1/sources/"
                + str(self.source_id)
                + "/intels",
                {
                    "name": entity["name"],
                    "description": entity["id"],
                    "platforms": platforms,
                    "contents": entity["pattern"],
                },
            )
        return intel_document

    def _create_observable(self, entity, original_intel_document=None):
        if original_intel_document is None:
            intel_document = self._get_by_id(entity["id"])
            if intel_document is not None:
                return intel_document

        intel_type = None
        value = None
        name = None
        if entity["entity_type"] == "StixFile":
            intel_type = "file_hash"
            if "hashes" in entity:
                for hash in entity["hashes"]:
                    value = (
                        value + hash["hash"] + "\n"
                        if value is not None
                        else hash["hash"] + "\n"
                    )
                    name = hash["hash"]

        elif entity["entity_type"] in [
            "IPv4-Addr",
            "IPv6-Addr",
            "Domain-Name",
            "X-OpenCTI-Hostname",
        ]:
            intel_type = "ip_or_host"
            value = entity["value"]
            name = entity["value"]
        if intel_type is None or value is None:
            return None

        openioc = self._query(
            "post",
            "/plugin/products/detect3/api/v1/intels/quick-add",
            {
                "exact": True,
                "name": name,
                "description": entity["id"],
                "type": intel_type,
                "text": value,
            },
        )
        openioc = re.sub(
            r"<description>(.*?)<\/description>",
            r"<description>" + entity["id"] + "</description>",
            openioc,
        )
        payload = {"intelDoc": openioc}
        if original_intel_document is not None:
            intel_document = self._query(
                "put",
                "/plugin/products/detect3/api/v1/intels/"
                + str(original_intel_document["id"]),
                payload,
                "application/xml",
                "openioc",
            )
        else:
            intel_document = self._query(
                "post",
                "/plugin/products/detect3/api/v1/sources/"
                + str(self.source_id)
                + "/intels",
                payload,
                "application/xml",
                "openioc",
            )

        return intel_document

    def _post_operations(self, entity, intel_document):
        if intel_document is not None and entity is not None:
            if self.tanium_auto_quickscan:
                for computer_group in self.tanium_computer_groups:
                    self._query(
                        "post",
                        "/plugin/products/detect3/api/v1/quick-scans",
                        {
                            "computerGroupId": int(computer_group),
                            "intelDocId": intel_document["id"],
                        },
                    )

            external_reference = self.helper.api.external_reference.create(
                source_name="Tanium",
                url=self.tanium_url
                + "/#/thr_workbench/intel/"
                + str(intel_document["id"]),
                external_id=str(intel_document["id"]),
                description="Intel document within the Tanium platform.",
            )
            if entity["entity_type"] == "Indicator":
                self.helper.api.stix_domain_object.add_external_reference(
                    id=entity["id"], external_reference_id=external_reference["id"]
                )
            else:
                self.helper.api.stix_cyber_observable.add_external_reference(
                    id=entity["id"], external_reference_id=external_reference["id"]
                )
            if len(entity["objectLabel"]) > 0:
                labels = self._get_labels(entity["objectLabel"])
                for label in labels:
                    if label is not None:
                        self._query(
                            "put",
                            "/plugin/products/detect3/api/v1/intels/"
                            + str(intel_document["id"])
                            + "/labels",
                            {"id": label["id"]},
                        )

    def _process_intel(self, entity_type, data, original_intel_document=None):
        entity = None
        intel_document = None
        if entity_type == "indicator":
            entity = self.helper.api.indicator.read(id=data["data"]["x_opencti_id"])
            if entity is None:
                return {"entity": entity, "intel_document": intel_document}
            if entity["pattern_type"] == "stix":
                intel_document = self._create_indicator_stix(
                    entity, original_intel_document
                )
            elif entity["pattern_type"] == "yara":
                intel_document = self._create_indicator_yara(
                    entity, original_intel_document
                )
            elif entity["pattern_type"] == "tanium-signal":
                intel_document = self._create_tanium_signal(
                    entity, original_intel_document
                )
        elif (
            StixCyberObservableTypes.has_value(entity_type)
            and entity_type.lower() in self.tanium_observable_types
        ):
            entity = self.helper.api.stix_cyber_observable.read(
                id=data["data"]["x_opencti_id"]
            )
            intel_document = self._create_observable(entity, original_intel_document)
        return {"entity": entity, "intel_document": intel_document}

    def _process_message(self, msg):
        data = json.loads(msg.data)
        entity_type = data["data"]["type"]
        if (
            entity_type != "indicator"
            and entity_type not in self.tanium_observable_types
        ):
            return
        # Handle creation
        if msg.event == "create":
            if (
                self.tanium_import_label == "*"
                or "labels" not in data["data"]
                or not self.tanium_import_label
                or self.tanium_import_label not in data["data"]["labels"]
            ):
                return
            # Process intel
            processed_intel = self._process_intel(entity_type, data)
            intel_document = processed_intel["intel_document"]
            entity = processed_intel["entity"]
            # Create external reference and add object labels
            self._post_operations(entity, intel_document)

        elif msg.event == "update":
            if (
                "x_data_update" in data["data"]
                and "add" in data["data"]["x_data_update"]
                and "labels" in data["data"]["x_data_update"]["add"]
            ):
                if (
                    self.tanium_import_label
                    in data["data"]["x_data_update"]["add"]["labels"]
                ):
                    # Process intel
                    processed_intel = self._process_intel(entity_type, data)
                    intel_document = processed_intel["intel_document"]
                    entity = processed_intel["entity"]
                    # Create external reference and add object labels
                    self._post_operations(entity, intel_document)
                else:
                    entity = self.helper.api.indicator.read(
                        id=data["data"]["x_opencti_id"],
                        customAttributes="""
                        pattern_type
                    """,
                    )
                    intel_document = self._get_by_id(
                        data["data"]["x_opencti_id"],
                        yara=True
                        if entity is not None and entity["pattern_type"] == "yara"
                        else False,
                    )
                    if intel_document:
                        new_labels = []
                        for label in data["data"]["x_data_update"]["add"]["labels"]:
                            new_labels.append({"value": label})
                        labels = self._get_labels(new_labels)
                        for label in labels:
                            self._query(
                                "put",
                                "/plugin/products/detect3/api/v1/intels/"
                                + str(intel_document["id"])
                                + "/labels",
                                {"id": label["id"]},
                            )
            elif (
                "x_data_update" in data["data"]
                and "remove" in data["data"]["x_data_update"]
                and "labels" in data["data"]["x_data_update"]["remove"]
            ):
                if (
                    self.tanium_import_label
                    in data["data"]["x_data_update"]["remove"]["labels"]
                ):
                    # Import label has been removed
                    intel_document = self._get_by_id(data["data"]["x_opencti_id"])
                    if intel_document is not None:
                        self._query(
                            "delete",
                            "/plugin/products/detect3/api/v1/intels/"
                            + str(intel_document["id"]),
                        )
                    # Remove external references
                    if entity_type == "indicator":
                        entity = self.helper.api.indicator.read(
                            id=data["data"]["x_opencti_id"]
                        )
                    else:
                        entity = self.helper.api.stix_cyber_observable.read(
                            id=data["data"]["x_opencti_id"]
                        )
                    if (
                        entity
                        and "externalReferences" in entity
                        and len(entity["externalReferences"]) > 0
                    ):
                        for external_reference in entity["externalReferences"]:
                            if external_reference["source_name"] == "Tanium":
                                self.helper.api.external_reference.delete(
                                    external_reference["id"]
                                )
                else:
                    intel_document = self._get_by_id(data["data"]["x_opencti_id"])
                    if intel_document:
                        new_labels = []
                        for label in data["data"]["x_data_update"]["remove"]["labels"]:
                            new_labels.append({"value": label})
                        labels = self._get_labels(new_labels)
                        for label in labels:
                            self._query(
                                "delete",
                                "/plugin/products/detect3/api/v1/intels/"
                                + str(intel_document["id"])
                                + "/labels/"
                                + str(label["id"]),
                            )
            elif (
                "x_data_update" in data["data"]
                and "replace" in data["data"]["x_data_update"]
            ):
                if entity_type == "indicator":
                    if "pattern" in data["data"]["x_data_update"]["replace"]:
                        intel_document = self._get_by_id(data["data"]["x_opencti_id"])
                        if intel_document is not None:
                            self._process_intel(entity_type, data, intel_document)
                    elif (
                        "value" in data["data"]["x_data_update"]["replace"]
                        or "hashes" in data["data"]["x_data_update"]["replace"]
                    ):
                        intel_document = self._get_by_id(data["data"]["x_opencti_id"])
                        if intel_document is not None:
                            self._process_intel(entity_type, data, intel_document)

        elif msg.event == "delete":
            intel_document = self._get_by_id(data["data"]["x_opencti_id"])
            if intel_document is not None:
                self._query(
                    "delete",
                    "/plugin/products/detect3/api/v1/intels/"
                    + str(intel_document["id"]),
                )

    def start(self):
        self.alerts_gatherer = TaniumConnectorAlertsGatherer(
            self.helper, self.tanium_url, self.tanium_login, self.tanium_password
        )
        self.alerts_gatherer.start()
        self.helper.listen_stream(self._process_message)


if __name__ == "__main__":
    TaniumInstance = TaniumConnector()
    TaniumInstance.start()
