import base64
import datetime
import json
import os
import sys
import time
import uuid
from urllib import request

import html2text
import requests
import stix2
import yaml
from bs4 import BeautifulSoup
from datalake import Datalake, Output
from dateutil.parser import parse
from pycti import OpenCTIConnectorHelper, Report, get_config_variable


class OrangeCyberDefense:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.ocd_worldwatch_api_url = "https://api-tdc.cert.orangecyberdefense.com/v1"
        self.ocd_vulnerabilities_api_url = ""
        self.ocd_datalake_api_url = (
            "https://datalake.cert.orangecyberdefense.com/api/v2"
        )

        self.ocd_worldwatch_api_login = get_config_variable(
            "OCD_WORLDWATCH_API_LOGIN", ["ocd", "worldwatch_api_login"], config
        )
        self.ocd_worldwatch_api_key = get_config_variable(
            "OCD_WORLDWATCH_API_KEY", ["ocd", "worldwatch_api_key"], config
        )
        self.ocd_datalake_login = get_config_variable(
            "OCD_DATALAKE_LOGIN", ["ocd", "datalake_login"], config
        )
        self.ocd_datalake_password = get_config_variable(
            "OCD_DATALAKE_PASSWORD", ["ocd", "datalake_password"], config
        )
        self.ocd_import_worldwatch = get_config_variable(
            "OCD_IMPORT_WORLDWATCH", ["ocd", "import_worldwatch"], config, False, True
        )
        self.ocd_import_worldwatch_start_date = get_config_variable(
            "OCD_IMPORT_WORLDWATCH_START_DATE",
            ["ocd", "import_worldwatch_start_date"],
            config,
        )
        self.ocd_import_vulnerabilities = get_config_variable(
            "OCD_IMPORT_VULNERABILITIES",
            ["ocd", "import_vulnerabilities"],
            config,
            False,
            True,
        )
        self.ocd_import_vulnerabilities_start_date = get_config_variable(
            "OCD_IMPORT_VULNERABILITIES_START_DATE",
            ["ocd", "import_vulnerabilities_start_date"],
            config,
        )
        self.ocd_import_datalake = get_config_variable(
            "OCD_IMPORT_DATALAKE", ["ocd", "import_datalake"], config, False, True
        )
        self.ocd_import_datalake_atom_types = get_config_variable(
            "OCD_IMPORT_DATALAKE_ATOM_TYPES",
            ["ocd", "import_datalake_atom_types"],
            config,
        ).split(",")
        self.ocd_import_datalake_threat_types = get_config_variable(
            "OCD_IMPORT_DATALAKE_THREAT_TYPES",
            ["ocd", "import_datalake_threat_types"],
            config,
        ).split(",")
        self.ocd_import_datalake_minimum_risk_score = get_config_variable(
            "OCD_IMPORT_DATALAKE_MINIMUM_RISK_SCORE",
            ["ocd", "import_datalake_minimum_risk_score"],
            config,
            True,
            0,
        )
        self.ocd_import_datalake_start_date = get_config_variable(
            "OCD_IMPORT_DATALAKE_START_DATE",
            ["ocd", "import_datalake_start_date"],
            config,
        )
        self.ocd_create_observables = get_config_variable(
            "OCD_CREATE_OBSERVABLES", ["ocd", "create_observables"], config, False, True
        )
        self.ocd_curate_labels = get_config_variable(
            "OCD_CURATE_LABELS", ["ocd", "curate_labels"], config, False, True
        )
        self.ocd_interval = get_config_variable(
            "OCD_INTERVAL", ["ocd", "interval"], config, True
        )
        self.ocd_threat_actor_as_intrusion_set = get_config_variable(
            "OCD_THREAT_ACTOR_AS_INTRUSION_SET",
            ["ocd", "threat_actor_as_intrusion_set"],
            config,
            False,
            True,
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )

        # Init variables
        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="Orange Cyberdefense",
            description="Orange Cyberdefense is the expert cybersecurity business unit of the Orange Group, providing consulting, solutions and services to organizations around the globe.",
        )
        self.marking = self.helper.api.marking_definition.create(
            definition_type="COMMERCIAL",
            definition="ORANGE CYBERDEFENSE",
            x_opencti_order=99,
            x_opencti_color="#ff7900",
        )
        self.worldwatch_auth_token = None
        self.datalake_instance = Datalake(
            username=self.ocd_datalake_login, password=self.ocd_datalake_password
        )
        self.cache = {}

    def get_interval(self):
        return int(self.ocd_interval) * 60

    def _get_worldwatch_token(self):
        data = str.encode(
            '{"username": "'
            + self.ocd_worldwatch_api_login
            + '", "password": "'
            + self.ocd_worldwatch_api_key
            + '"}',
            "utf-8",
        )
        query = request.Request(
            self.ocd_worldwatch_api_url + "/auth/",
            method="POST",
            data=data,
            headers={"Content-Type": "application/json"},
        )
        with request.urlopen(query) as response:
            content = json.loads(response.read().decode("utf-8"))
        self.worldwatch_auth_token = content["token"]

    def _curate_labels(self, labels):
        curated_labels = []
        for label in labels:
            if "tlp:" in label:
                continue
            label_value = label
            if '="' in label:
                label_value_split = label.split('="')
                label_value = label_value_split[1][:-1].strip()
            elif ":" in label:
                label_value_split = label.split(":")
                label_value = label_value_split[1].strip()
            if label_value.isdigit():
                if ":" in label:
                    label_value_split = label.split(":")
                    label_value = label_value_split[1].strip()
                else:
                    label_value = label
            if '="' in label_value:
                label_value = label_value.replace('="', "-")[:-1]
            curated_labels.append(label_value)
        return curated_labels

    def _get_alert_entities(self, id):
        self.helper.log_info("Getting datalake entries for worldwatch " + str(id))
        # Query params
        query_body = {
            "AND": [
                {
                    "AND": [
                        {
                            "field": "tags",
                            "multi_values": ["world_watch-" + str(id)],
                            "type": "filter",
                        },
                    ]
                }
            ]
        }
        limit = 1000
        offset = 0
        objects = []
        while True:
            self.helper.log_info(
                "Iterating, limit=" + str(limit) + ", offset=" + str(offset)
            )
            try:
                data = self.datalake_instance.AdvancedSearch.advanced_search_from_query_body(
                    query_body,
                    limit=limit,
                    offset=offset,
                    ordering=["last_updated"],
                    output=Output.STIX,
                )
            except Exception as e:
                self.helper.log_error(str(e))
                break
            if offset + limit >= 10000 or "objects" not in data:
                break
            # Parse the result
            for object in data["objects"]:
                if "labels" in object:
                    for label in object["labels"]:
                        if label == "tlp:white":
                            object["object_marking_refs"] = [stix2.TLP_WHITE.get("id")]
                        if label == "tlp:green":
                            object["object_marking_refs"] = [stix2.TLP_GREEN.get("id")]
                        if label == "tlp:amber":
                            object["object_marking_refs"] = [
                                stix2.TLP_AMBER.get("id"),
                                self.marking["standard_id"],
                            ]
                        if label == "tlp:red":
                            object["object_marking_refs"] = [
                                stix2.TLP_RED.get("id"),
                                self.marking["standard_id"],
                            ]
                if "labels" in object and self.ocd_curate_labels:
                    object["labels"] = self._curate_labels(object["labels"])
                if "confidence" not in object:
                    object["confidence"] = self.helper.connect_confidence_level
                if "created_by_ref" not in object:
                    object["created_by_ref"] = self.identity["standard_id"]
                if object["type"] == "indicator" and self.ocd_create_observables:
                    object["x_opencti_create_observables"] = True
                if (
                    object["type"] == "threat-actor"
                    and self.ocd_threat_actor_as_intrusion_set
                ):
                    object["type"] = "intrusion-set"
                    object["id"] = object["id"].replace("threat-actor", "intrusion-set")
                if object["type"] == "sector":
                    object["type"] = "identity"
                    object["identity_class"] = "class"
                    object["id"] = object["id"].replace("sector", "identity")
                if object["type"] == "relationship":
                    object["source_ref"] = object["source_ref"].replace(
                        "sector", "identity"
                    )
                    object["target_ref"] = object["target_ref"].replace(
                        "sector", "identity"
                    )
                    if self.ocd_threat_actor_as_intrusion_set:
                        object["source_ref"] = object["source_ref"].replace(
                            "threat-actor", "intrusion-set"
                        )
                        object["target_ref"] = object["target_ref"].replace(
                            "threat-actor", "intrusion-set"
                        )
                objects.append(object)
            offset = offset + limit
        return objects

    def _generate_report(self, report):
        objects = []
        curated_title = report["title"].replace("Updated - ", "")
        self.helper.log_info(
            'Genearing report "'
            + curated_title
            + '" ('
            + report["timestamp_updated"]
            + ")"
        )
        external_references = []
        if report["url"] is not None:
            external_reference = stix2.ExternalReference(
                source_name=report["source_name"], url=report["url"]
            )
            external_references.append(external_reference)
        report_objects = self._get_alert_entities(report["id"])
        if report_objects is None or len(report_objects) == 0:
            report_objects = [self.identity["standard_id"]]
        analysis_blocks = [
            x for x in report["incident_blocks"] if x["type"] == "analysis"
        ][::-1]
        technical_blocks = [
            x for x in report["incident_blocks"] if x["type"] == "technical_information"
        ][::-1]
        if len(analysis_blocks) == 0:
            return []
        analysis_html = ""
        for block in analysis_blocks:
            analysis_html = analysis_html + block["content"]
        technical_html = ""
        for block in technical_blocks:
            technical_html = technical_html + block["content"]
        text_maker = html2text.HTML2Text()
        text_maker.body_width = 0
        text_maker.ignore_links = False
        text_maker.ignore_images = False
        text_maker.ignore_tables = False
        text_maker.ignore_emphasis = False
        text_maker.skip_internal_links = False
        text_maker.inline_links = True
        text_maker.protect_links = True
        text_maker.mark_code = True
        analysis_md = text_maker.handle(analysis_html)
        analysis_md = analysis_md.replace("](//", "](https://")
        soup = BeautifulSoup(technical_html, features="lxml")
        links = soup.find_all("a")
        for tag in links:
            link = tag.get("href", None)
            if link is not None and "orangecyberdefense.com" not in link:
                external_reference = stix2.ExternalReference(
                    source_name=report["source_name"], url=link
                )
                external_references.append(external_reference)
        file_analysis = {
            "name": "analysis.html",
            "mime_type": "text/html",
            "data": base64.b64encode(analysis_html.encode("utf-8")).decode("utf-8"),
        }
        file_technical = {
            "name": "technical_appendix.html",
            "mime_type": "text/html",
            "data": base64.b64encode(technical_html.encode("utf-8")).decode("utf-8"),
        }
        report_stix = stix2.Report(
            id=Report.generate_id(curated_title, report["timestamp_detected"]),
            name=curated_title,
            description=analysis_md,
            report_types=["threat-report"],
            created_by_ref=self.identity["standard_id"],
            confidence=self.helper.connect_confidence_level,
            external_references=external_references,
            created=parse(report["timestamp_detected"]),
            published=parse(report["timestamp_detected"]),
            modified=parse(report["timestamp_updated"]),
            object_refs=[x["id"] for x in report_objects],
            labels=["severity-" + str(report["severity"]), report["source_name"]],
            allow_custom=True,
            object_marking_refs=[
                stix2.TLP_GREEN.get("id"),
                self.marking["standard_id"],
            ],
            x_opencti_files=[file_analysis, file_technical],
        )
        objects.append(report_stix)
        objects = objects + report_objects
        return objects

    def _import_worldwatch(self, work_id, current_state):
        # Get the token
        self._get_worldwatch_token()
        # Query params
        url = self.ocd_worldwatch_api_url + "/cybalerts/"
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Token " + self.worldwatch_auth_token,
        }
        params = (
            ("timestamp_updated_since", current_state["worldwatch"]),
            ("ordering", "timestamp_updated"),
        )
        self.helper.log_info("Iterating " + url)
        response = requests.get(url, headers=headers, params=params)
        data = json.loads(response.content)
        while data["next"] is not None:
            self.helper.log_info("Iterating " + data["next"])
            for report in data["results"]:
                date = parse(report["timestamp_updated"]).date()
                last_report_time = report["timestamp_updated"]
                if date > datetime.datetime.now().date():
                    continue
                try:
                    report_objects = self._generate_report(report)
                    self.helper.send_stix2_bundle(
                        stix2.Bundle(
                            objects=report_objects,
                            allow_custom=True,
                        ).serialize(),
                        update=self.update_existing_data,
                        work_id=work_id,
                    )
                except Exception as e:
                    self.helper.log_error(str(e))
                current_state["worldwatch"] = last_report_time
                self.helper.set_state(current_state)
            url = str(data["next"])
            response = requests.get(url, headers=headers, params=params)
            data = json.loads(response.content)
        for report in data["results"]:
            last_report_time = report["timestamp_updated"]
            date = parse(report["timestamp_updated"]).date()
            if date > datetime.datetime.now().date():
                continue
            try:
                report_objects = self._generate_report(report)
                self.helper.send_stix2_bundle(
                    stix2.Bundle(
                        objects=report_objects,
                        allow_custom=True,
                    ).serialize(),
                    update=self.update_existing_data,
                    work_id=work_id,
                )
            except Exception as e:
                self.helper.log_error(str(e))
            current_state["worldwatch"] = last_report_time
            self.helper.set_state(current_state)
        return current_state

    def _import_datalake(self, work_id, current_state):
        # Query params
        query_body = {
            "AND": [
                {
                    "AND": [
                        {
                            "field": "atom_type",
                            "multi_values": self.ocd_import_datalake_atom_types,
                            "type": "filter",
                        },
                        {
                            "field": "last_updated",
                            "range": {"gte": current_state["datalake"]},
                            "type": "filter",
                        },
                        {
                            "field": "risk",
                            "range": {
                                "gt": self.ocd_import_datalake_minimum_risk_score
                            },
                            "type": "filter",
                        },
                        {
                            "field": "threat_types",
                            "multi_values": self.ocd_import_datalake_threat_types,
                            "type": "filter",
                        },
                    ]
                }
            ]
        }
        limit = 500
        offset = 0
        last_entity_timestamp = current_state["datalake"]
        while True:
            self.helper.log_info(
                "Iterating, limit=" + str(limit) + ", offset=" + str(offset)
            )
            objects = []
            try:
                data = self.datalake_instance.AdvancedSearch.advanced_search_from_query_body(
                    query_body,
                    limit=limit,
                    offset=offset,
                    ordering=["last_updated"],
                    output=Output.STIX,
                )
            except Exception as e:
                self.helper.log_error(str(e))
                break
            if offset + limit >= 10000 or "objects" not in data:
                break
            # Parse the result
            for object in data["objects"]:
                if "labels" in object:
                    for label in object["labels"]:
                        if label == "tlp:white":
                            object["object_marking_refs"] = [stix2.TLP_WHITE.get("id")]
                        if label == "tlp:green":
                            object["object_marking_refs"] = [stix2.TLP_GREEN.get("id")]
                        if label == "tlp:amber":
                            object["object_marking_refs"] = [
                                stix2.TLP_AMBER.get("id"),
                                self.marking["standard_id"],
                            ]
                        if label == "tlp:red":
                            object["object_marking_refs"] = [
                                stix2.TLP_RED.get("id"),
                                self.marking["standard_id"],
                            ]
                if "labels" in object and self.ocd_curate_labels:
                    object["labels"] = self._curate_labels(object["labels"])
                if "confidence" not in object:
                    object["confidence"] = self.helper.connect_confidence_level
                if "created_by_ref" not in object:
                    object["created_by_ref"] = self.identity["standard_id"]
                if object["type"] == "indicator" and self.ocd_create_observables:
                    object["x_opencti_create_observables"] = True
                if (
                    object["type"] == "threat-actor"
                    and self.ocd_threat_actor_as_intrusion_set
                ):
                    object["type"] = "intrusion-set"
                    object["id"] = object["id"].replace("threat-actor", "intrusion-set")
                if object["type"] == "sector":
                    object["type"] = "identity"
                    object["identity_class"] = "class"
                    object["id"] = object["id"].replace("sector", "identity")
                if object["type"] == "relationship":
                    object["source_ref"] = object["source_ref"].replace(
                        "sector", "identity"
                    )
                    object["target_ref"] = object["target_ref"].replace(
                        "sector", "identity"
                    )
                    if self.ocd_threat_actor_as_intrusion_set:
                        object["source_ref"] = object["source_ref"].replace(
                            "threat-actor", "intrusion-set"
                        )
                        object["target_ref"] = object["target_ref"].replace(
                            "threat-actor", "intrusion-set"
                        )
                if "modified" in object:
                    last_entity_timestamp = object["modified"]
                objects.append(object)
            bundle = {
                "id": f"bundle--{uuid.uuid4()}",
                "type": "bundle",
                "objects": objects,
            }
            self.helper.send_stix2_bundle(
                json.dumps(bundle),
                update=self.update_existing_data,
                work_id=work_id,
            )
            current_state["datalake"] = last_entity_timestamp
            self.helper.set_state(current_state)
            offset = offset + limit
        return current_state

    def run(self):
        while True:
            try:
                self.helper.log_info("Synchronizing with Orange Cyberdefense APIs...")
                timestamp = int(time.time())
                now = datetime.datetime.utcfromtimestamp(timestamp)
                friendly_name = "Orange Cyberdefense run @ " + now.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                current_state = self.helper.get_state()
                if current_state is None:
                    self.helper.set_state(
                        {
                            "worldwatch": parse(
                                self.ocd_import_worldwatch_start_date
                            ).isoformat(),
                            "datalake": parse(
                                self.ocd_import_datalake_start_date
                            ).isoformat(),
                            "vulnerabilities": parse(
                                self.ocd_import_vulnerabilities_start_date
                            ).isoformat(),
                        }
                    )
                current_state = self.helper.get_state()
                if self.ocd_import_worldwatch:
                    self.helper.log_info(
                        "Get World Watch alerts since "
                        + str(current_state["worldwatch"])
                    )
                    new_state = self._import_worldwatch(work_id, current_state)
                    self.helper.log_info("Setting new state " + str(new_state))
                    self.helper.set_state(new_state)
                if self.ocd_import_datalake:
                    self.helper.log_info(
                        "Get Datalake Data since " + str(current_state["datalake"])
                    )
                    new_state = self._import_datalake(work_id, current_state)
                    self.helper.log_info("Setting new state " + str(new_state))
                    self.helper.set_state(new_state)
                message = "End of synchronization"
                self.helper.api.work.to_processed(work_id, message)
                self.helper.log_info(message)
                time.sleep(self.get_interval())
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
                time.sleep(60)


if __name__ == "__main__":
    try:
        ocdConnector = OrangeCyberDefense()
        ocdConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
