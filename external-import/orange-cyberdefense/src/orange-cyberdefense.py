import base64
import datetime
import json
import logging
import os
import re
import sys
import time
import zipfile
from html.parser import HTMLParser
from io import StringIO
from urllib import request

import html2text
import requests
import stix2
import yaml
from bs4 import BeautifulSoup
from datalake import Datalake, Output
from dateutil.parser import parse
from pycti import (
    Incident,
    Note,
    OpenCTIConnectorHelper,
    Report,
    StixCoreRelationship,
    Vulnerability,
    get_config_variable,
)


class MLStripper(HTMLParser):
    def __init__(self):
        super().__init__()
        self.reset()
        self.strict = False
        self.convert_charrefs = True
        self.text = StringIO()

    def handle_data(self, d):
        self.text.write(d)

    def get_data(self):
        return self.text.getvalue()


def strip_tags(html):
    s = MLStripper()
    s.feed(html)
    return s.get_data()


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


def _parse_date(date):
    return parse(date).astimezone().isoformat()


def extract_and_read_zip_file(filepath, extract_path):
    if not os.path.exists(filepath):
        logging.warning(f"File path {filepath} does not exist. Exiting...")
        return []

    json_files_content = []

    with zipfile.ZipFile(filepath, "r") as zip_ref:
        zip_ref.extractall(extract_path)
        logging.debug(f"Extracted zip file to {extract_path}")

    for root, dirs, files in os.walk(extract_path):
        for file in files:
            if file.endswith(".json"):
                with open(os.path.join(root, file), "r") as json_file:
                    logging.debug(f"Reading file {file}")
                    data = json.load(json_file)
                    json_files_content.append(data)
                    json_file.close()
    logging.debug(f"Returning stix content from {len(json_files_content)} files")
    return json_files_content


def generate_markdown_table(data):
    markdown_str = "## Threat scores\n"
    markdown_str += (
        "| DDoS | Fraud | Hack | Leak | Malware | Phishing | Scam | Scan | Spam |\n"
    )
    markdown_str += (
        "|------|-------|------|------|---------|----------|------|------|------|\n"
    )

    threat_scores = data.get("x_datalake_score", {})
    ddos = threat_scores.get("ddos", "-")
    fraud = threat_scores.get("fraud", "-")
    hack = threat_scores.get("hack", "-")
    leak = threat_scores.get("leak", "-")
    malware = threat_scores.get("malware", "-")
    phishing = threat_scores.get("phishing", "-")
    scam = threat_scores.get("scam", "-")
    scan = threat_scores.get("scan", "-")
    spam = threat_scores.get("spam", "-")

    markdown_str += f"| {ddos} | {fraud} | {hack} | {leak} | {malware} | {phishing} | {scam} | {scan} | {spam} |\n"
    markdown_str += "## Threat intelligence sources\n"
    markdown_str += (
        "| source_id | count | first_seen | last_updated | min_depth | max_depth |\n"
    )
    markdown_str += (
        "|-----------|-------|------------|--------------|-----------|-----------|\n"
    )

    threat_sources = data.get("x_datalake_sources", [])

    # Sort the threat_sources by 'last_updated' in descending order
    threat_sources.sort(key=lambda x: x.get("last_updated", ""), reverse=True)

    for source in threat_sources:
        source_id = source.get("source_id", "-")
        count = source.get("count", "-")
        first_seen = source.get("first_seen", "-")
        if first_seen != "-":
            # Format 'first_seen' to 'YYYY-MM-DD'
            first_seen = datetime.datetime.fromisoformat(
                first_seen.rstrip("Z")
            ).strftime("%Y-%m-%d %H:%M")
        last_updated = source.get("last_updated", "-")
        if last_updated != "-":
            # Format 'last_updated' to 'YYYY-MM-DD'
            last_updated = datetime.datetime.fromisoformat(
                last_updated.rstrip("Z")
            ).strftime("%Y-%m-%d %H:%M")
        min_depth = source.get("min_depth", "-")
        max_depth = source.get("max_depth", "-")

        markdown_str += f"| {source_id} | {count} | {first_seen} | {last_updated} | {min_depth} | {max_depth} |\n"

    return markdown_str


class OrangeCyberDefense:
    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path, encoding="utf8"), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.ocd_portal_api_url = "https://api-tdc.cert.orangecyberdefense.com/v1"
        self.ocd_vulnerabilities_api_url = ""
        self.ocd_datalake_api_url = (
            "https://datalake.cert.orangecyberdefense.com/api/v2"
        )
        self.ocd_portal_api_login = get_config_variable(
            "OCD_PORTAL_API_LOGIN", ["ocd", "portal_api_login"], config
        )
        self.ocd_portal_api_key = get_config_variable(
            "OCD_PORTAL_API_KEY", ["ocd", "portal_api_key"], config
        )
        self.ocd_datalake_login = get_config_variable(
            "OCD_DATALAKE_LOGIN", ["ocd", "datalake_login"], config
        )
        self.ocd_datalake_password = get_config_variable(
            "OCD_DATALAKE_PASSWORD", ["ocd", "datalake_password"], config
        )
        self.ocd_datalake_zip_file_path = get_config_variable(
            "OCD_DATALAKE_ZIP_FILE_PATH",
            ["ocd", "datalake_zip_file_path"],
            config,
            default="/opt/opencti-connector-orange-cyberdefense",
        )
        self.ocd_vulnerabilities_login = get_config_variable(
            "OCD_VULNERABILITIES_LOGIN", ["ocd", "vulnerabilities_login"], config
        )
        self.ocd_vulnerabilities_password = get_config_variable(
            "OCD_VULNERABILITIES_PASSWORD", ["ocd", "vulnerabilities_password"], config
        )
        self.ocd_import_worldwatch = get_config_variable(
            "OCD_IMPORT_WORLDWATCH", ["ocd", "import_worldwatch"], config, default=True
        )
        self.ocd_import_worldwatch_start_date = get_config_variable(
            "OCD_IMPORT_WORLDWATCH_START_DATE",
            ["ocd", "import_worldwatch_start_date"],
            config,
        )
        self.ocd_import_cybercrime = get_config_variable(
            "OCD_IMPORT_CYBERCRIME", ["ocd", "import_cybercrime"], config, default=True
        )
        self.ocd_import_cybercrime_start_date = get_config_variable(
            "OCD_IMPORT_CYBERCRIME_START_DATE",
            ["ocd", "import_cybercrime_start_date"],
            config,
        )
        self.ocd_import_vulnerabilities = get_config_variable(
            "OCD_IMPORT_VULNERABILITIES",
            ["ocd", "import_vulnerabilities"],
            config,
            default=True,
        )
        self.ocd_import_datalake = get_config_variable(
            "OCD_IMPORT_DATALAKE", ["ocd", "import_datalake"], config, default=True
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
            isNumber=True,
            default=80,
        )
        self.ocd_create_observables = get_config_variable(
            "OCD_CREATE_OBSERVABLES",
            ["ocd", "create_observables"],
            config,
            default=True,
        )
        self.ocd_curate_labels = get_config_variable(
            "OCD_CURATE_LABELS", ["ocd", "curate_labels"], config, default=True
        )
        self.ocd_interval = get_config_variable(
            "OCD_INTERVAL", ["ocd", "interval"], config, isNumber=True, default=5
        )
        self.ocd_threat_actor_as_intrusion_set = get_config_variable(
            "OCD_THREAT_ACTOR_AS_INTRUSION_SET",
            ["ocd", "threat_actor_as_intrusion_set"],
            config,
            default=True,
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
        self.portal_auth_token = None
        self.datalake_instance = Datalake(
            username=self.ocd_datalake_login, password=self.ocd_datalake_password
        )
        self.cache = {}

    def _get_portal_token(self):
        data = str.encode(
            '{"username": "'
            + self.ocd_portal_api_login
            + '", "password": "'
            + self.ocd_portal_api_key
            + '"}',
            "utf-8",
            "escape",
        )
        query = request.Request(
            self.ocd_portal_api_url + "/auth/",
            method="POST",
            data=data,
            headers={"Content-Type": "application/json"},
        )
        with request.urlopen(query) as response:
            content = json.loads(response.read().decode("utf-8"))
        self.portal_auth_token = content["token"]

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
        if object["type"] == "indicator":
            threat_scores = object.get("x_datalake_score", {})
            for threat_type, score in threat_scores.items():
                if (
                    threat_type in self.ocd_import_datalake_threat_types
                    and score >= self.ocd_import_datalake_minimum_risk_score
                ):
                    new_label = f"dtl_{threat_type}_{self.ocd_import_datalake_minimum_risk_score}"
                    if "labels" in object:
                        object["labels"].append(new_label)
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
        curated_title = strip_tags(
            report["title"].replace("Updated - ", "").replace("MAJ - ", "")
        )
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
            [stix2.TLP_GREEN.get("id"), self.marking["standard_id"]],
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
            object_refs=(
                [x["id"] for x in report_objects]
                if len(report_objects) > 0
                else [self.identity["standard_id"]]
            ),
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

    def _import_worldwatch(self, current_state):
        # Get the token
        self._get_portal_token()
        # Query params
        url = self.ocd_portal_api_url + "/cybalerts/"
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Token " + self.portal_auth_token,
        }
        params = (
            ("offer_name", "World Watch"),
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
                    if report_objects:
                        self._log_and_initiate_work("Worldwatch")
                        self.helper.send_stix2_bundle(
                            stix2.Bundle(
                                objects=report_objects, allow_custom=True
                            ).serialize(),
                            update=self.update_existing_data,
                            work_id=self.work_id,
                        )
                        self._log_and_terminate_work()
                except Exception as e:
                    self.helper.log_error(str(e))
                current_state["worldwatch"] = last_report_time
                self.helper.set_state(current_state)
            url = str(data["next"])
            response = requests.get(url, headers=headers)
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
                if report_objects:
                    self._log_and_initiate_work("Worldwatch")
                    self.helper.send_stix2_bundle(
                        stix2.Bundle(
                            objects=report_objects, allow_custom=True
                        ).serialize(),
                        update=self.update_existing_data,
                        work_id=self.work_id,
                    )
                    self._log_and_terminate_work()
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

    def _gen_severity(self, severity):
        if severity == 1:
            return "low"
        if severity == 2:
            return "medium"
        if severity == 3:
            return "medium"
        if severity == 4:
            return "high"
        if severity == 4:
            return "critical"

    def _generate_incident(self, incident):
        objects = []
        curated_title = strip_tags(
            incident["title"].replace("Updated - ", "").replace("MAJ - ", "")
        )
        self.helper.log_info(
            'Genearing incident "'
            + curated_title
            + '" ('
            + incident["timestamp_updated"]
            + ")"
        )
        external_references = []
        external_reference = stix2.ExternalReference(
            source_name="Orange Cyberdefense",
            url="https://portal.cert.orangecyberdefense.com/cybercrime/"
            + str(incident["id"]),
        )
        external_references.append(external_reference)
        analysis_blocks = [
            x for x in incident["incident_blocks"] if x["type"] == "analysis"
        ][::-1]
        technical_blocks = [
            x
            for x in incident["incident_blocks"]
            if x["type"] == "technical_information"
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
        technical_md = text_maker.handle(technical_html)
        technical_md = technical_md.replace("](//", "](https://")
        soup = BeautifulSoup(technical_html, features="lxml")
        links = soup.find_all("a")
        for tag in links:
            link = tag.get("href", None)
            if link is not None and "orangecyberdefense.com" not in link:
                external_reference = stix2.ExternalReference(
                    source_name=incident["source_name"], url=link
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
        labels = [incident["services"][0]["name"], incident["risk"]]
        incident_stix = stix2.Incident(
            id=Incident.generate_id(
                curated_title, parse(incident["timestamp_detected"])
            ),
            name=curated_title,
            incident_type=incident["services"][0]["offer_name"],
            description=analysis_md,
            created_by_ref=self.identity["standard_id"],
            confidence=self.helper.connect_confidence_level,
            external_references=external_references,
            created=parse(incident["timestamp_detected"]),
            modified=parse(incident["timestamp_updated"]),
            first_seen=parse(incident["timestamp_detected"]),
            last_seen=parse(incident["timestamp_updated"]),
            source=incident["source_name"],
            severity=self._gen_severity(incident["severity"]),
            labels=labels,
            allow_custom=True,
            object_marking_refs=[
                stix2.TLP_GREEN.get("id"),
                self.marking["standard_id"],
            ],
            x_opencti_files=[file_analysis, file_technical],
        )
        objects.append(incident_stix)
        custom_properties = {
            "description": "Observable related to an incident.",
            "x_opencti_score": incident["severity"] * 20,
            "labels": labels,
            "created_by_ref": self.identity["standard_id"],
            "external_references": external_references,
        }
        url_stix = None
        if (
            "url" in incident
            and incident["url"] is not None
            and len(incident["url"]) > 0
        ):
            url_stix = stix2.URL(
                value=incident["url"],
                object_marking_refs=[
                    stix2.TLP_GREEN.get("id"),
                    self.marking["standard_id"],
                ],
                custom_properties=custom_properties,
            )
            objects.append(url_stix)
        if url_stix is not None:
            incident_url_relation = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "related-to", url_stix.get("id"), incident_stix.get("id")
                ),
                relationship_type="related-to",
                created_by_ref=self.identity["standard_id"],
                confidence=self.helper.connect_confidence_level,
                source_ref=url_stix.get("id"),
                target_ref=incident_stix.get("id"),
                object_marking_refs=[
                    stix2.TLP_GREEN.get("id"),
                    self.marking["standard_id"],
                ],
                allow_custom=True,
            )
            objects.append(incident_url_relation)

        detection_date = parse(incident["timestamp_detected"])
        detection_date = detection_date.replace(
            hour=0, minute=0, second=0, microsecond=0
        ) - datetime.timedelta(days=detection_date.weekday())
        report_stix = stix2.Report(
            id=Report.generate_id(curated_title, detection_date),
            name="Weekly cybercrime alerts and incidents ("
            + detection_date.strftime("%Y-%m-%d")
            + ")",
            report_types=["threat-report"],
            created_by_ref=self.identity["standard_id"],
            confidence=self.helper.connect_confidence_level,
            created=detection_date,
            published=detection_date,
            modified=detection_date,
            object_refs=[x["id"] for x in objects],
            labels=["cybercrime", "ocd"],
            allow_custom=True,
            object_marking_refs=[
                stix2.TLP_GREEN.get("id"),
                self.marking["standard_id"],
            ],
        )
        objects.append(report_stix)
        if len(technical_md) > 2:
            note_stix = stix2.Note(
                id=Note.generate_id(detection_date, technical_md),
                abstract="Technical information about this alert.",
                content=technical_md,
                created=detection_date,
                modified=detection_date,
                created_by_ref=self.identity["standard_id"],
                object_marking_refs=[
                    stix2.TLP_GREEN.get("id"),
                    self.marking["standard_id"],
                ],
                object_refs=[incident_stix.get("id")],
            )
            objects.append(note_stix)
        return objects

    def _import_cybercrime(self, current_state):
        # Get the token
        self._get_portal_token()
        # Query params
        url = self.ocd_portal_api_url + "/cybalerts/"
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Token " + self.portal_auth_token,
        }
        params = (
            ("timestamp_updated_since", current_state["cybercrime"]),
            ("ordering", "timestamp_updated"),
        )
        self.helper.log_info("Iterating " + url)
        self.helper.log_info(str(params))
        response = requests.get(url, headers=headers, params=params)
        data = json.loads(response.content)
        while data["next"] is not None:
            self.helper.log_info("Iterating " + data["next"])
            for report in data["results"]:
                service = report["services"][0]["name"]
                date = parse(report["timestamp_updated"]).date()
                last_report_time = report["timestamp_updated"]
                if date > datetime.datetime.now().date() or service == "World Watch":
                    continue
                try:
                    incident_objects = self._generate_incident(report)
                    if incident_objects:
                        self._log_and_initiate_work("Cybercrime")
                        self.helper.send_stix2_bundle(
                            stix2.Bundle(
                                objects=incident_objects, allow_custom=True
                            ).serialize(),
                            update=self.update_existing_data,
                            work_id=self.work_id,
                        )
                        self._log_and_terminate_work()
                except Exception as e:
                    self.helper.log_error(str(e))
                current_state["cybercrime"] = last_report_time
                self.helper.set_state(current_state)
            url = str(data["next"])
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = json.loads(response.content)
            if "next" not in data:
                data["next"] = None
        for report in data["results"]:
            service = report["services"][0]["name"]
            last_report_time = report["timestamp_updated"]
            date = parse(report["timestamp_updated"]).date()
            if date > datetime.datetime.now().date() or service == "World Watch":
                continue
            try:
                incident_objects = self._generate_incident(report)
                if incident_objects:
                    self._log_and_initiate_work("Cybercrime")
                    self.helper.send_stix2_bundle(
                        stix2.Bundle(
                            objects=incident_objects, allow_custom=True
                        ).serialize(),
                        update=self.update_existing_data,
                        work_id=self.work_id,
                    )
                    self._log_and_terminate_work()
            except Exception as e:
                self.helper.log_error(str(e))
            last_report_timestamp = parse(last_report_time).timestamp() + 1
            current_state["cybercrime"] = (
                datetime.datetime.fromtimestamp(last_report_timestamp)
                .astimezone()
                .isoformat()
            )
            self.helper.set_state(current_state)
        return current_state

    def _import_datalake(self, current_state):
        # Define query parameters
        last_entity_timestamp = None
        calculated_interval = (int(self.ocd_interval) + 15) * 60
        query_body = {
            "AND": [
                {
                    "AND": [
                        # Filter by atom type
                        {
                            "field": "atom_type",
                            "multi_values": self.ocd_import_datalake_atom_types,
                            "type": "filter",
                        },
                        # Filter by last updated date
                        {
                            "field": "system_last_updated",
                            "type": "filter",
                            "value": calculated_interval,
                        },
                        # Filter by threats types & risk score
                        {
                            "field": "risk",
                            "inner_params": {
                                "threat_types": self.ocd_import_datalake_threat_types
                            },
                            "range": {
                                "gt": self.ocd_import_datalake_minimum_risk_score
                            },
                            "type": "filter",
                        },
                    ]
                }
            ]
        }
        logging.info(query_body)
        # Create the bulk search task
        datalake_instance = Datalake(
            username=self.ocd_datalake_login, password=self.ocd_datalake_password
        )
        task = datalake_instance.BulkSearch.create_task(
            for_stix_export=True, query_body=query_body
        )
        # Download the data as STIX_ZIP
        zip_file_path = self.ocd_datalake_zip_file_path + "/data.zip"
        task.download_sync_stream_to_file(
            output=Output.STIX_ZIP, timeout=15 * 200, output_path=zip_file_path
        )
        extract_and_read_zip_file(
            filepath=zip_file_path, extract_path=self.ocd_datalake_zip_file_path
        )

        # Loop over the extracted files and process them
        objects = []
        for filename in os.listdir(self.ocd_datalake_zip_file_path):
            if filename.endswith(".json"):
                with open(
                    os.path.join(self.ocd_datalake_zip_file_path + "/", filename)
                ) as f:
                    data = json.load(f)
                    if "objects" in data:
                        for object in data["objects"]:
                            processed_object = self._process_object(object)
                            if processed_object["type"] == "indicator":
                                creation_date = processed_object.get("created", {})
                                technical_md = generate_markdown_table(processed_object)
                                note_stix = stix2.Note(
                                    id=Note.generate_id(creation_date, technical_md),
                                    confidence=self.helper.connect_confidence_level,
                                    abstract="OCD-CERT Datalake additional informations",
                                    content=technical_md,
                                    created=creation_date,
                                    modified=processed_object["modified"],
                                    created_by_ref=self.identity["standard_id"],
                                    object_marking_refs=[self.marking["standard_id"]],
                                    object_refs=[processed_object.get("id")],
                                )
                                objects.append(note_stix)
                            objects.append(processed_object)
                            if "modified" in object:
                                last_entity_timestamp = object.get("modified")

                    else:
                        logging.warning("'objects' key is not in data")

        # Cleanup the temporary files
        if os.path.exists(zip_file_path):
            try:
                os.remove(zip_file_path)
            except OSError as e:
                logging.error(f"Error removing {zip_file_path}: {e}")
        for filename in os.listdir(self.ocd_datalake_zip_file_path):
            # Avoid directory traversal attacks (exemple : a file containing ../ or /)
            safe_filename = os.path.basename(filename)
            if safe_filename.endswith(".json"):
                try:
                    os.remove(os.path.join(self.ocd_datalake_zip_file_path, filename))
                except OSError as e:
                    logging.error(
                        f"Error removing {os.path.join(self.ocd_datalake_zip_file_path, filename)}: {e}"
                    )

        # Remove duplicates
        keep_first(objects, "id")

        # Create a bundle of the processed objects
        if len(objects):
            self._log_and_initiate_work("Datalake")
            # Send the created bundle
            self.helper.send_stix2_bundle(
                stix2.Bundle(objects=objects, allow_custom=True).serialize(),
                update=self.update_existing_data,
                work_id=self.work_id,
            )
            self._log_and_terminate_work()

        # Update the state if 'modified' field is present
        if last_entity_timestamp:
            current_state["datalake"] = (
                parse(last_entity_timestamp).astimezone().isoformat()
            )
            self.helper.set_state(current_state)

        # Return the updated state
        return current_state

    def _import_vulnerabilities(self, current_state):
        last_entity_timestamp = None
        dtl = Datalake(
            username=self.ocd_datalake_login, password=self.ocd_datalake_password
        )
        tag_subcategory_list = dtl.FilteredTagSubcategory.get_filtered_and_sorted_list(
            category_name="Vulnerability", limit=50, ordering="-updated_at"
        )
        objects = []
        pattern = r"CVSS Score: (\d+\.\d+)"
        if tag_subcategory_list is not None:
            for vuln in tag_subcategory_list["results"]:
                match = re.search(pattern, vuln["description"])
                cvss_score = match.group(1) if match else None
                external_references = []
                if "external_references" in vuln:
                    for ref in vuln["external_references"]:
                        source_name = ref.get("source_name", "Orange Cyberdefense")
                        description = ref.get("description", "No description provided")
                        external_reference = stix2.ExternalReference(
                            source_name=source_name,
                            description=description,
                            url=ref["url"],
                        )
                        external_references.append(external_reference)
                objects.append(
                    stix2.Vulnerability(
                        id=Vulnerability.generate_id(vuln["stix_uuid"].split("--")[1]),
                        name=vuln["name"],
                        description=vuln["description"],
                        created=parse(vuln["created_at"]),
                        modified=parse(vuln["updated_at"]),
                        allow_custom=True,
                        created_by_ref=self.identity["standard_id"],
                        confidence=self.helper.connect_confidence_level,
                        object_marking_refs=[
                            stix2.TLP_GREEN.get("id"),
                            self.marking["standard_id"],
                        ],
                        custom_properties={
                            "x_opencti_aliases": (
                                vuln["tags"] if vuln["tags"] is not None else None
                            ),
                            "x_opencti_base_score": (
                                float(cvss_score) if cvss_score is not None else None
                            ),
                        },
                        external_references=external_references,
                        labels=vuln["tags"],
                    )
                )
                if "updated_at" in vuln:
                    last_entity_timestamp = vuln.get("updated_at")

            if objects:
                self._log_and_initiate_work("Vulnerabilities")
                self.helper.send_stix2_bundle(
                    stix2.Bundle(objects=objects, allow_custom=True).serialize(),
                    update=self.update_existing_data,
                    work_id=self.work_id,
                )
                self._log_and_terminate_work()
        else:
            logging.warning("New vulnerabilites not found")

        if last_entity_timestamp:
            current_state["vulnerabilities"] = (
                parse(last_entity_timestamp).astimezone().isoformat()
            )
        self.helper.set_state(current_state)
        return current_state

    def _set_initial_state(self):
        initial_state = {
            "worldwatch": _parse_date(
                self.ocd_import_worldwatch_start_date
                or datetime.datetime.today().isoformat()
            ),
            "cybercrime": _parse_date(
                self.ocd_import_cybercrime_start_date
                or datetime.datetime.today().isoformat()
            ),
            "datalake": _parse_date(datetime.datetime.today().isoformat()),
            "vulnerabilities": _parse_date(datetime.datetime.today().isoformat()),
        }
        self.helper.set_state(initial_state)
        return initial_state

    def _log_and_initiate_work(self, name):
        self.helper.log_info("Synchronizing with Orange Cyberdefense APIs...")
        timestamp = int(time.time())
        now = datetime.datetime.utcfromtimestamp(timestamp)
        friendly_name = f"Orange Cyberdefense {name} service run @ {now.strftime('%Y-%m-%d %H:%M:%S')}"
        self.work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )

    def _log_and_terminate_work(self):
        self.helper.api.work.to_processed(self.work_id, "End of synchronization")
        self.helper.log_info("End of synchronization")

    def process_and_update_state(self, current_state, key):
        update_methods = {
            "worldwatch": self._import_worldwatch,
            "cybercrime": self._import_cybercrime,
            "datalake": self._import_datalake,
            "vulnerabilities": self._import_vulnerabilities,
        }

        if key not in update_methods:
            return

        if not getattr(self, f"ocd_import_{key}", None):
            return

        log_message = f"Get {key} alerts since {current_state[key]}"
        if key == "datalake":
            log_message += f" with the interval of {self.ocd_interval} minutes"

        self.helper.log_info(log_message)
        new_state = update_methods[key](current_state)
        self.helper.log_info(f"Setting new state {new_state}")
        self.helper.set_state(new_state)

    def run(self):
        current_state = None
        while True:
            try:
                current_state = self.helper.get_state() or self._set_initial_state()
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                exit(0)
            except Exception as e:  # Consider catching more specific exceptions
                self.helper.log_error(str(e))
                time.sleep(60)
            if current_state:
                for key in ["worldwatch", "cybercrime", "datalake", "vulnerabilities"]:
                    try:
                        self.process_and_update_state(current_state, key)
                    except Exception as ex:
                        self.helper.log_error(str(ex))
                        time.sleep(60)

            time.sleep(int(self.ocd_interval) * 60)


if __name__ == "__main__":
    try:
        ocdConnector = OrangeCyberDefense()
        ocdConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
