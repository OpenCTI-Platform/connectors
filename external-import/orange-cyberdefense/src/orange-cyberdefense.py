import base64
import datetime
import json
import os
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from urllib import request

import html2text
import requests
import stix2
import yaml
from bs4 import BeautifulSoup
from datalake import Datalake, Output
from dateutil.parser import parse
from pycti import (OpenCTIConnectorHelper, Report, StixCoreRelationship,
                   Vulnerability, get_config_variable)

atom_types_mapping = {
    "apk": "Unknown",
    "as": "Autonomous-System",
    "cc": "Payment-Card",
    "crypto": "Cryptocurrency-Wallet",
    "cve": "Unknown",
    "domain": "Domain-Name",
    "email": "Email-Addr",
    "file": "StixFile",
    "fqdn": "Hostname",
    "iban": "Bank-Account",
    "ip": "IPv4-Addr",
    "ip_range": "IPv4-Addr",
    "paste": "Text",
    "phone_number": "Phone-Number",
    "regkey": "Windows-Registry-Key",
    "ssl": "X509-Certificate",
    "url": "Url",
}


def keep_first(iterable, key=None):
    if key is None:
        key = lambda x: x
    seen = set()
    for elem in iterable:
        k = key(elem)
        if k in seen:
            continue
        yield elem
        seen.add(k)


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
        self.ocd_vulnerabilities_login = get_config_variable(
            "OCD_VULNERABILITIES_LOGIN", ["ocd", "vulnerabilities_login"], config
        )
        self.ocd_vulnerabilities_password = get_config_variable(
            "OCD_VULNERABILITIES_PASSWORD", ["ocd", "vulnerabilities_password"], config
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
            "escape",
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
        curated_labels = [
            label for label in curated_labels if label is not None and len(label) > 0
        ]
        return curated_labels

    def _process_object(self, object):
        if "labels" in object:
            for label in object["labels"]:
                if label == "tlp:clear":
                    object["object_marking_refs"] = [stix2.TLP_WHITE.get("id")]
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
        if "x_datalake_score" in object:
            scores = list(object["x_datalake_score"].values())
            if len(scores) > 0:
                object["x_opencti_score"] = max(scores)
        if (
            "x_datalake_atom_type" in object
            and object["x_datalake_atom_type"] in atom_types_mapping
        ):
            object["x_opencti_main_observable_type"] = atom_types_mapping[
                object["x_datalake_atom_type"]
            ]
        if "created_by_ref" not in object:
            object["created_by_ref"] = self.identity["standard_id"]
        if "external_references" in object:
            external_references = []
            for external_reference in object["external_references"]:
                if "url" in external_reference:
                    external_reference["url"] = external_reference["url"].replace(
                        "api/v2/mrti/threats", "gui/threat"
                    )
                    external_references.append(external_reference)
                else:
                    external_references.append(external_reference)
            object["external_references"] = external_references
        if object["type"] == "indicator" and self.ocd_create_observables:
            object["x_opencti_create_observables"] = True
        if object["type"] == "threat-actor" and self.ocd_threat_actor_as_intrusion_set:
            object["type"] = "intrusion-set"
            object["id"] = object["id"].replace("threat-actor", "intrusion-set")
        if object["type"] == "sector":
            object["type"] = "identity"
            object["identity_class"] = "class"
            object["id"] = object["id"].replace("sector", "identity")
        if object["type"] == "relationship":
            object["source_ref"] = object["source_ref"].replace("sector", "identity")
            object["target_ref"] = object["target_ref"].replace("sector", "identity")
            if self.ocd_threat_actor_as_intrusion_set:
                object["source_ref"] = object["source_ref"].replace(
                    "threat-actor", "intrusion-set"
                )
                object["target_ref"] = object["target_ref"].replace(
                    "threat-actor", "intrusion-set"
                )
        return object

    def _create_magic_bundle(self, objects, date, markings):
        attackers = [
            o
            for o in objects
            if o["type"] in ["threat-actor", "intrusion-set", "malware", "campaign"]
        ]
        victims = [o for o in objects if o["type"] in ["identity", "location"]]
        threats = [
            o
            for o in objects
            if o["type"] in ["threat-actor", "intrusion-set", "campaign"]
        ]
        arsenals = [
            o for o in objects if o["type"] in ["malware", "tool", "attack-pattern"]
        ]
        relationships = []
        if len(attackers) <= 5:
            # Magic targets
            for attacker in attackers:
                for victim in victims:
                    relationships.append(
                        json.loads(
                            stix2.Relationship(
                                id=StixCoreRelationship.generate_id(
                                    "targets", attacker["id"], victim["id"]
                                ),
                                relationship_type="targets",
                                created_by_ref=self.identity["standard_id"],
                                confidence=self.helper.connect_confidence_level,
                                source_ref=attacker["id"],
                                target_ref=victim["id"],
                                object_marking_refs=markings,
                                start_time=date,
                                created=date,
                                modified=date,
                                allow_custom=True,
                            ).serialize()
                        )
                    )
        else:
            self.helper.log_info(
                "Too many attackers ("
                + str(len(attackers))
                + "), not creating relationships..."
            )
        if len(threats) <= 5:
            # Magic uses
            for threat in threats:
                for arsenal in arsenals:
                    relationships.append(
                        json.loads(
                            stix2.Relationship(
                                id=StixCoreRelationship.generate_id(
                                    "uses", threat["id"], arsenal["id"]
                                ),
                                relationship_type="uses",
                                created_by_ref=self.identity["standard_id"],
                                confidence=self.helper.connect_confidence_level,
                                source_ref=threat["id"],
                                target_ref=arsenal["id"],
                                object_marking_refs=markings,
                                start_time=date,
                                created=date,
                                modified=date,
                                allow_custom=True,
                            ).serialize()
                        )
                    )
        else:
            self.helper.log_info(
                "Too many threats ("
                + str(len(threats))
                + "), not creating relationships..."
            )
        return relationships

    def _get_alert_entities(self, id, date, markings):
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
                        {
                            "field": "atom_type",
                            "multi_values": self.ocd_import_datalake_atom_types,
                            "type": "filter",
                        },
                    ]
                }
            ]
        }
        limit = 50
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
                processed_object = self._process_object(object)
                objects.append(processed_object)
            magic_relationships = self._create_magic_bundle(
                data["objects"], date, markings
            )
            objects = objects + magic_relationships
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
        if "url" in report and report["url"] is not None:
            external_reference = stix2.ExternalReference(
                source_name=report["source_name"], url=report["url"]
            )
            external_references.append(external_reference)
            if "portal.cert.orangecyberdefense.com" not in report["url"]:
                external_reference = stix2.ExternalReference(
                    source_name="Orange Cyberdefense",
                    url="https://portal.cert.orangecyberdefense.com/worldwatch/"
                    + str(report["id"]),
                )
                external_references.append(external_reference)
        else:
            external_reference = stix2.ExternalReference(
                source_name="Orange Cyberdefense",
                url="https://portal.cert.orangecyberdefense.com/worldwatch/"
                + str(report["id"]),
            )
            external_references.append(external_reference)
        report_objects = self._get_alert_entities(
            report["id"],
            parse(report["timestamp_detected"]),
            [
                stix2.TLP_GREEN.get("id"),
                self.marking["standard_id"],
            ],
        )
        if report_objects is None:
            report_objects = []
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
            object_refs=[x["id"] for x in report_objects]
            if len(report_objects) > 0
            else [self.identity["standard_id"]],
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
            if "next" not in data:
                data["next"] = None
        for report in data["results"]:
            last_report_time = report["timestamp_updated"]
            date = parse(report["timestamp_updated"]).date()
            if date > datetime.datetime.now().date():
                continue
            try:
                report_objects = self._generate_report(report)
                keep_first(report_objects, "id")
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
            last_report_timestamp = parse(last_report_time).timestamp() + 1
            current_state["worldwatch"] = (
                datetime.datetime.fromtimestamp(last_report_timestamp)
                .astimezone()
                .isoformat()
            )
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
                processed_object = self._process_object(object)
                objects.append(processed_object)
                if "modified" in object:
                    last_entity_timestamp = object["modified"]
                objects.append(object)
            keep_first(objects, "id")
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
            current_state["datalake"] = (
                parse(last_entity_timestamp).astimezone().isoformat()
            )
            self.helper.set_state(current_state)
            offset = offset + limit
        return current_state

    def import_vulnerabilities(self, work_id):
        try:
            url = (
                "https://portal.cert.orangecyberdefense.com/api/csi/xml/vulns/login/"
                + self.ocd_vulnerabilities_login
                + "/password/"
                + self.ocd_vulnerabilities_password
            )
            xml_data = request.urlopen(url).read().decode("utf-8")
            root = ET.fromstring(xml_data)
            agent = root.find("./agent")
            objects = []
            for vuln in agent.findall("vuln"):
                vulnerability = {
                    "title": vuln.findtext("titre", None),
                    "date": vuln.findtext("date", None),
                    "cve": vuln.findtext("cve", None),
                    "description": vuln.find("description").findtext("contenu"),
                    "base_score": vuln.find("cvss").findtext("base_score"),
                }
                objects.append(
                    stix2.Vulnerability(
                        id=Vulnerability.generate_id(vulnerability["title"]),
                        name=vulnerability["title"],
                        description=vulnerability["description"],
                        created=parse(vulnerability["date"]),
                        modified=parse(vulnerability["date"]),
                        allow_custom=True,
                        created_by_ref=self.identity["standard_id"],
                        confidence=self.helper.connect_confidence_level,
                        object_marking_refs=[
                            stix2.TLP_GREEN.get("id"),
                            self.marking["standard_id"],
                        ],
                        custom_properties={
                            "x_opencti_aliases": [vulnerability["cve"]]
                            if vulnerability["cve"] is not None
                            else None,
                            "x_opencti_base_score": float(vulnerability["base_score"]),
                        },
                    )
                )
            self.helper.send_stix2_bundle(
                stix2.Bundle(
                    objects=objects,
                    allow_custom=True,
                ).serialize(),
                update=self.update_existing_data,
                work_id=work_id,
            )
        except Exception as e:
            self.helper.log_error(str(e))
            pass

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
                            "worldwatch": parse(self.ocd_import_worldwatch_start_date)
                            .astimezone()
                            .isoformat(),
                            "datalake": parse(self.ocd_import_datalake_start_date)
                            .astimezone()
                            .isoformat(),
                            "vulnerabilities": (
                                datetime.datetime.today() - datetime.timedelta(days=30)
                            )
                            .astimezone()
                            .isoformat(),
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
                if self.ocd_import_vulnerabilities:
                    now_timestamp = datetime.datetime.today().timestamp()
                    state_timestamp = parse(
                        current_state["vulnerabilities"]
                    ).timestamp()
                    if (now_timestamp - state_timestamp) > 3600 * 24 * 30:
                        self.helper.log_info(
                            "Get Vulnerabilities Data since "
                            + str(current_state["vulnerabilities"])
                        )
                        self.import_vulnerabilities(work_id)
                        current_state[
                            "vulnerabilities"
                        ] = datetime.datetime.utcfromtimestamp(
                            now_timestamp
                        ).isoformat()
                        self.helper.log_info("Setting new state " + str(current_state))
                        self.helper.set_state(current_state)
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
