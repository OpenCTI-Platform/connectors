import datetime
import json
import logging
import os
import sys
import time
import zipfile
from html.parser import HTMLParser
from io import StringIO
from typing import Iterable, TypeVar

import html2text
import requests
import stix2
import yaml
from datalake import Datalake, Output
from dateutil.parser import parse
from pycti import (
    Note,
    OpenCTIConnectorHelper,
    Report,
    StixCoreRelationship,
    get_config_variable,
)

T = TypeVar("T")


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


def strip_tags(html: str):
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


def keep_first(iterable: Iterable[T], key=None):
    """
    Generator that yields once per unique element from the provided iterable.
    If key is provided, it is used to determine uniqueness.
    If it is string, it must be a valid key of all elements of the iterable.
    Else, key must be a callable returning a hashable value, it will be called on all elements.

    """
    if key is None:

        def func(x):
            return x

    elif isinstance(key, str):

        def func(x):
            return x[key]

    elif callable(key):
        func = key
    else:
        raise ValueError("key must either be None, a str, or a callable")
    seen = set()
    for elem in iterable:
        k = func(elem)
        if k in seen:
            continue
        seen.add(k)
        yield elem


def iter_stix_bs_results(zip_file_path):
    """
    iterates on all stix objects of a stix bulk search result which is a zip file of multiple stix bundle json files
    """
    with zipfile.ZipFile(zip_file_path, "r") as zip:
        for filename in zip.namelist():
            with zip.open(filename) as file:
                bundle = json.load(file)
                if "objects" in bundle:
                    yield from bundle["objects"]


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


def extract_datalake_query_hash(url: str):
    logging.info("Extracting query hash from URL: %s", url)
    # Find the starting position of 'query_hash='
    start_pos = url.find("query_hash=")
    if start_pos == -1:
        return ""
    start_pos += len("query_hash=")
    # Find the ending position of the hash (either end of string or next parameter)
    end_pos = url.find("&", start_pos)
    if end_pos == -1:
        end_pos = len(url)
    # Extract the query hash
    query_hash = url[start_pos:end_pos]
    return query_hash


def _curate_labels(labels):
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


class OrangeCyberDefense:
    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path, encoding="utf8"), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.ocd_datalake_api_url = (
            "https://datalake.cert.orangecyberdefense.com/api/v2"
        )
        self.ocd_datalake_token = get_config_variable(
            "OCD_DATALAKE_TOKEN", ["ocd", "datalake_token"], config
        )
        self.ocd_datalake_zip_file_path = get_config_variable(
            "OCD_DATALAKE_ZIP_FILE_PATH",
            ["ocd", "datalake_zip_file_path"],
            config,
            default="/opt/opencti-connector-orange-cyberdefense",
        )
        self.ocd_import_worldwatch_api_key = get_config_variable(
            "OCD_IMPORT_WORLDWATCH_API_KEY",
            ["ocd", "import_worldwatch_api_key"],
            config,
        )
        self.ocd_import_worldwatch = get_config_variable(
            "OCD_IMPORT_WORLDWATCH", ["ocd", "import_worldwatch"], config, default=True
        )
        self.ocd_import_worldwatch_start_date = get_config_variable(
            "OCD_IMPORT_WORLDWATCH_START_DATE",
            ["ocd", "import_worldwatch_start_date"],
            config,
        )
        self.ocd_import_threat_library = get_config_variable(
            "OCD_IMPORT_THREAT_LIBRARY",
            ["ocd", "import_threat_library"],
            config,
            default=True,
        )
        self.ocd_import_datalake = get_config_variable(
            "OCD_IMPORT_DATALAKE", ["ocd", "import_datalake"], config, default=True
        )
        self.ocd_datalake_queries = json.loads(
            get_config_variable(
                "OCD_DATALAKE_QUERIES",
                ["ocd", "datalake_queries"],
                config,
            )
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
            "OCD_INTERVAL", ["ocd", "interval"], config, isNumber=True, default=15
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
        self.ocd_reset_state = get_config_variable(
            "OCD_RESET_STATE",
            ["ocd", "reset_state"],
            config,
            default=False,
        )

        # Init variables
        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="Orange Cyberdefense",
            description="""Orange Cyberdefense is the expert cybersecurity business unit of the Orange Group,
            providing consulting, solutions and services to organizations around the globe.""",
        )
        self.marking = self.helper.api.marking_definition.create(
            definition_type="COMMERCIAL",
            definition="ORANGE CYBERDEFENSE",
            x_opencti_order=99,
            x_opencti_color="#ff7900",
        )
        if self.ocd_import_datalake or self.ocd_import_threat_library:
            self.datalake_instance = Datalake(longterm_token=self.ocd_datalake_token)
        self.cache = {}

    def _generate_indicator_note(self, indicator_object):
        creation_date = indicator_object.get("created", {})
        technical_md = generate_markdown_table(indicator_object)
        note_stix = stix2.Note(
            id=Note.generate_id(creation_date, technical_md),
            abstract="OCD-CERT Datalake additional informations",
            content=technical_md,
            created=creation_date,
            modified=indicator_object["modified"],
            created_by_ref=self.identity["standard_id"],
            object_marking_refs=[self.marking["standard_id"]],
            object_refs=[indicator_object.get("id")],
        )
        return note_stix

    def _get_ranged_scored(self, score: int):
        if score == 100:
            return 90
        return (score // 10) * 10

    def _process_object(self, object):

        dict_label_to_object_marking_refs = {
            "tlp:clear": [stix2.TLP_WHITE.get("id")],
            "tlp:white": [stix2.TLP_WHITE.get("id")],
            "tlp:green": [stix2.TLP_GREEN.get("id")],
            "tlp:amber": [stix2.TLP_AMBER.get("id"), self.marking["standard_id"]],
            "tlp:red": [stix2.TLP_RED.get("id"), self.marking["standard_id"]],
        }
        if "labels" in object:
            for label in object["labels"]:
                if label in dict_label_to_object_marking_refs.keys():
                    object["object_marking_refs"] = dict_label_to_object_marking_refs[
                        label
                    ]
        if "labels" in object and self.ocd_curate_labels:
            object["labels"] = _curate_labels(object["labels"])
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

        # Type specific operations
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
            if self.ocd_create_observables:
                object["x_opencti_create_observables"] = True
            threat_scores = object.get("x_datalake_score", {})
            for threat_type, score in threat_scores.items():
                ranged_score = self._get_ranged_scored(score)
                new_label = f"dtl_{threat_type}_{ranged_score}"
                if not "labels" in object:
                    object["labels"] = []
                object["labels"].append(new_label)
        return object

    def _get_report_iocs(self, datalake_query_hash: str):
        """
        Fetch the stix objects from Datalake that are found with the provided query_hash
        This export is very demanding for the Datalake API, so it must be done in small
        batches to limit Gateway Timeouts
        """
        objects = []
        self.helper.log_info(
            "Extracting stix objects from Datalake query hash: " + datalake_query_hash
        )

        limit = 25
        offset = 0
        objects = []
        while True:
            self.helper.log_info(
                "Iterating, limit=" + str(limit) + ", offset=" + str(offset)
            )
            try:
                data = self.datalake_instance.AdvancedSearch.advanced_search_from_query_hash(
                    query_hash=datalake_query_hash,
                    limit=limit,
                    offset=offset,
                    ordering=["last_updated"],
                    output=Output.STIX,
                )
            except Exception as e:
                self.helper.log_error(
                    f"ERROR: unable to get offset={str(offset)} with limit={str(limit)} for query_hash={datalake_query_hash}. "
                    f"Error message: {str(e)}"
                )
                break
            if offset + limit >= 10000 or "objects" not in data:
                break
            # Parse the result
            for object in data["objects"]:
                processed_object = self._process_object(object)
                objects.append(processed_object)
                if processed_object["type"] == "indicator":
                    stix2_note = self._generate_indicator_note(processed_object)
                    objects.append(stix2_note)
            offset += limit

        # we remove duplicates, after processing because processing may affect id
        objects = list(keep_first(objects, "id"))
        return objects

    def _get_report_entities(self, tags: Iterable[str]):
        """
        Fetch the threat entities from Datalake that have some of the provided tags (as stix label)
        """
        objects = []
        self.helper.log_info(
            "Getting datalake report entities for WorldWatch with tags " + str(tags)
        )

        for tag in tags:
            try:
                url = "https://datalake.cert.orangecyberdefense.com/api/v2/mrti/tag-subcategory/filtered/"
                payload = json.dumps(
                    {
                        "limit": "5000",
                        "offset": "0",
                        "tag": tag,
                    }
                )
                headers = {
                    "Accept": "application/stix+json",
                    "Content-Type": "application/json",
                    "Authorization": "Token " + self.ocd_datalake_token,
                }
                response = requests.post(url, headers=headers, data=payload)
                data = response.json()
            except Exception as e:
                self.helper.log_error(
                    "This tag cannot be found in Datalake: " + tag + "\n" + str(e)
                )
                continue
            if "objects" in data:
                for stix_object in data["objects"]:
                    label: str
                    for label in stix_object["labels"]:
                        if tag.lower() == label.lower():
                            processed_object = self._process_object(stix_object)
                            objects.append(processed_object)
                            break
            else:
                self.helper.log_info("No objects found for tag " + tag)
        return objects

    def get_html_content_block(self, content_block_id):
        url = (
            "https://api-ww.cert.orangecyberdefense.com/api/content_block/"
            + str(content_block_id)
            + "/html"
        )
        headers = {
            "Content-Type": "application/json",
            "Authorization": self.ocd_import_worldwatch_api_key,
        }
        response = requests.get(url, headers=headers)
        return response.json().get("html")

    def _create_report_relationships(self, objects, date, markings):
        """
        Generates stix relationship objects for the given objects.
        Objects are sorted into categories: attackers, victims, threats, arsenals.
        - "targets" relations are created between attackers and victims.
        - "uses" relations are created between threats and arsenals.
        """
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
        return relationships

    def _generate_report(self, report: dict):
        self.helper.log_info(
            'Generating report "'
            + report["title"]
            + '" ('
            + report["timestamp_updated"]
            + ")"
        )

        # Managing external references
        self.helper.log_info("Processing external references...")
        external_references = []
        # Add external reference to advisory on CERT Portal
        external_reference = stix2.ExternalReference(
            source_name="Orange Cyberdefense WorldWatch advisory",
            url=f"https://portal.cert.orangecyberdefense.com/worldwatch/advisory/{report['advisory']}",
            description=report["title"],
        )
        external_references.append(external_reference)

        if report.get("sources") is not None:
            for source in report["sources"]:
                external_reference = stix2.ExternalReference(
                    source_name=source["title"] or "Orange Cyberdefense",
                    url=source["url"],
                    description=source["description"],
                )
                external_references.append(external_reference)
        if report.get("datalake_url") is not None:
            external_reference = stix2.ExternalReference(
                source_name=report["datalake_url"]["title"] or "Datalake Search",
                url=report["datalake_url"]["url"],
                description=report["datalake_url"]["description"],
            )
            external_references.append(external_reference)
        self.helper.log_info(f"Got {len(external_references)} external_references.")

        # Getting the iocs object from the report
        self.helper.log_info("Getting iocs from Datalake...")
        if report["datalake_url"]:
            if self.ocd_import_datalake or self.ocd_import_threat_library:
                hashkey = extract_datalake_query_hash(report["datalake_url"]["url"])
                if hashkey:
                    report_iocs = self._get_report_iocs(
                        datalake_query_hash=hashkey,
                    )
                else:
                    self.helper.log_info(
                        f"No hashkey found in datalake url: {report['datalake_url']['url']}"
                    )
                    report_iocs = []
            else:
                self.helper.log_info("Skipping because datalake is not configured")
                report_iocs = []
        else:
            self.helper.log_info("No datalake url found")
            report_iocs = []
        self.helper.log_info(f"Got {len(report_iocs)} stix objects from datalake.")

        # Getting the report entities
        self.helper.log_info("Getting report entities...")
        tags = set(report["tags"]) | set(report["advisory_tags"])
        if (self.ocd_import_datalake or self.ocd_import_threat_library) and tags:
            report_entities = self._get_report_entities(tags)
        else:
            report_entities = []
        self.helper.log_info(f"Got {len(report_entities)} threat entities.")

        report_object_marking_refs = [
            stix2.TLP_GREEN.get("id"),
            self.marking["standard_id"],
        ]

        # Generate relationships (stix objects) between threat entities
        self.helper.log_info("Generating relationships for threat entities...")
        report_relationships = self._create_report_relationships(
            report_entities,
            parse(report["timestamp_updated"]),
            report_object_marking_refs,
        )
        self.helper.log_info(f"Generated {len(report_relationships)} relations.")

        # Processing the report
        self.helper.log_info("Processing the report description...")
        html_content = self.get_html_content_block(report["id"]) or ""
        # Convert HTML to Markdown
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
        # Generate the report
        report_md = text_maker.handle(html_content)

        report_object_refs = (
            [
                x["id"] for x in report_iocs if x["type"] == "indicator"
            ]  # ids from "indicator" iocs
            + [x["id"] for x in report_entities]  # ids from threat entities
            + [  # ids from threat entities relations
                x["id"] for x in report_relationships
            ]
        )

        report_stix = stix2.Report(
            id=Report.generate_id(
                f"{report['advisory']}-{report['id']}", report["timestamp_created"]
            ),
            name=report["title"],
            description=report_md,
            report_types=["threat-report"],
            created_by_ref=self.identity["standard_id"],
            external_references=external_references,
            created=parse(report["timestamp_created"]),
            published=parse(report["timestamp_updated"]),
            modified=parse(report["timestamp_updated"]),
            object_refs=(
                report_object_refs
                if report_object_refs
                else [self.identity["standard_id"]]
            ),
            labels=["severity-" + str(report["severity"])],
            allow_custom=True,
            object_marking_refs=report_object_marking_refs,
        )
        objects = [report_stix] + report_iocs + report_entities + report_relationships
        return objects

    def get_content_block_list(self, start_date: datetime.datetime):
        url = (
            "https://api-ww.cert.orangecyberdefense.com/api/content_block/"
            "?sort_by=timestamp_updated&sort_order=asc&limit=5000"
            "&updated_after=" + start_date.strftime("%Y-%m-%dT%H:%M:%S")
        )
        headers = {
            "Content-Type": "application/json",
            "Authorization": self.ocd_import_worldwatch_api_key,
        }
        response = requests.get(url, headers=headers)
        return response.json()["items"]

    def _import_worldwatch(self):
        current_state = self.helper.get_state()

        content_block_list = self.get_content_block_list(
            datetime.datetime.fromisoformat(current_state["worldwatch"])
        )

        for content_block in content_block_list:
            try:
                self.helper.log_info(
                    f"---------------------------------- WorldWatch -> {content_block['id']}-------------------------------------------"
                )
                content_block_objects = self._generate_report(content_block)
                if content_block_objects:
                    self.helper.log_info("Sending stix bundle to OpenCTI")
                    self._log_and_initiate_work("World Watch")
                    self.helper.send_stix2_bundle(
                        stix2.Bundle(
                            objects=content_block_objects, allow_custom=True
                        ).serialize(),
                        update=self.update_existing_data,
                        work_id=self.work_id,
                    )
                    self._log_and_terminate_work()
                # Update state timestamp if content block is newer than the current state and not in future
                if (
                    parse(content_block["timestamp_updated"])
                    <= datetime.datetime.now(tz=datetime.timezone.utc)
                ) and (
                    parse(content_block["timestamp_updated"])
                    >= parse(current_state["worldwatch"])
                ):
                    current_state["worldwatch"] = (
                        parse(content_block["timestamp_updated"])
                        .astimezone()
                        .isoformat()
                    )
                    self.helper.set_state(current_state)
            except Exception as e:
                self.helper.log_error(
                    f"Error while importing WorldWatch advisory {content_block['id']}: {str(e)} "
                )
                continue

    def _import_datalake(self):
        current_state = self.helper.get_state()
        # Define query parameters
        calculated_interval = (int(self.ocd_interval) + 15) * 60

        # Filter by last updated date query body object
        filter_by_last_updated_date_query_body = {
            "AND": [
                {
                    "field": "system_last_updated",
                    "type": "filter",
                    "value": calculated_interval,
                }
            ]
        }

        for query in self.ocd_datalake_queries:

            try:
                adv_search = self.datalake_instance.AdvancedSearch.advanced_search_from_query_hash(
                    query["query_hash"], limit=0
                )
                query_body = adv_search["query_body"]
            except Exception as e:
                self.helper.log_error(
                    f"Could not extract query_body for the following Bulk search : '{query['label']}', error : '{str(e)}'"
                )
                continue

            if len(query_body.keys()) > 0 and list(query_body.keys())[0] == "AND":
                query_body["AND"].append(filter_by_last_updated_date_query_body)
            else:
                self.helper.log_info(
                    f"""Bulk search {query['label']} doesn't use a main 'AND' operator
                      -> unable to filter on last {self.ocd_interval} minutes data."""
                )

            self.helper.log_info(
                f"Creating Bulk Search with label '{query['label']}' in Datalake with the following query hash '{query['query_hash']}'"
            )

            # Create the bulk search task
            task = self.datalake_instance.BulkSearch.create_task(
                for_stix_export=True, query_body=query_body
            )

            self.helper.log_info(f"Waiting for Bulk Search {task.uuid}...")
            # Download the data as STIX_ZIP
            zip_file_path = self.ocd_datalake_zip_file_path + "/data.zip"
            task.download_sync_stream_to_file(
                output=Output.STIX_ZIP, timeout=60 * 60, output_path=zip_file_path
            )

            self.helper.log_info("Processing Bulk Search results...")
            objects = []
            for object in iter_stix_bs_results(zip_file_path):
                processed_object = self._process_object(object)
                if processed_object["type"] == "indicator":
                    if not "labels" in processed_object:
                        processed_object["labels"] = []
                    processed_object["labels"].append(f"dtl_{query['label']}")
                    note_stix = self._generate_indicator_note(processed_object)
                    objects.append(note_stix)
                objects.append(processed_object)

            # Cleanup the temporary files
            if os.path.exists(zip_file_path):
                try:
                    os.remove(zip_file_path)
                except OSError as e:
                    logging.error(f"Error removing {zip_file_path}: {e}")

            # we remove duplicates, after processing because processing may affect id
            objects = list(keep_first(objects, "id"))

            # Create a bundle of the processed objects
            if objects:
                self.helper.log_info(
                    f"Got {len(objects)} stix objects from query \"{query['label']}\"."
                )
                self._log_and_initiate_work(f"Datalake query {query['label']}")
                # Send the created bundle
                self.helper.send_stix2_bundle(
                    stix2.Bundle(objects=objects, allow_custom=True).serialize(),
                    update=self.update_existing_data,
                    work_id=self.work_id,
                )
                self._log_and_terminate_work()

        # Update the state if 'modified' field is present
        current_state["datalake"] = (
            datetime.datetime.now(tz=datetime.timezone.utc).astimezone().isoformat()
        )
        self.helper.set_state(current_state)

    def _import_threat_library(self):
        current_state = self.helper.get_state()

        url = "https://datalake.cert.orangecyberdefense.com/api/v2/mrti/tag-subcategory/filtered/"
        payload = json.dumps({"limit": "500", "offset": "0", "ordering": "-updated_at"})
        headers = {
            "Accept": "application/stix+json",
            "Content-Type": "application/json",
            "Authorization": "Token " + self.ocd_datalake_token,
        }
        threat_stix_bundle = requests.request(
            "POST", url, headers=headers, data=payload
        ).json()
        if threat_stix_bundle["objects"]:
            self._log_and_initiate_work("Threat Library")
            threat_stix_bundle["objects"] = [
                self._process_object(obj) for obj in threat_stix_bundle["objects"]
            ]
            self.helper.send_stix2_bundle(
                stix2.Bundle(
                    objects=threat_stix_bundle["objects"], allow_custom=True
                ).serialize(),
                update=self.update_existing_data,
                work_id=self.work_id,
            )
            self._log_and_terminate_work()
            current_state["threat_library"] = (
                datetime.datetime.now(tz=datetime.timezone.utc).astimezone().isoformat()
            )
            self.helper.set_state(current_state)
            return True

        return False

    def _log_and_initiate_work(self, name):
        self.helper.log_info("Pushing data to OpenCTI APIs...")
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        friendly_name = f"Orange Cyberdefense \"{name}\" service run @ {now.strftime('%Y-%m-%d %H:%M:%S')}"
        self.work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )

    def _log_and_terminate_work(self):
        self.helper.api.work.to_processed(self.work_id, "End of synchronization")
        self.helper.log_info("End of synchronization")

    def _set_initial_state(self):
        logging.info("Setting initial state")
        initial_state = {
            "worldwatch": parse(self.ocd_import_worldwatch_start_date)
            .astimezone()
            .isoformat(),
            "datalake": "",
            "threat_library": "",
        }
        self.helper.set_state(initial_state)
        logging.info(f"Initial state set: {initial_state}")
        return initial_state

    def _validate_state(self, state):
        """
        returns True if the state is correct for the current version of the connector
        this function must be updated if the state format change
        """
        if state is None:
            return False

        return all(
            key in state.keys() for key in ["worldwatch", "datalake", "threat_library"]
        )

    def run(self):
        if self.ocd_reset_state:
            current_state = self._set_initial_state()
        else:
            # connector initialization: it tries to fetch state from the opencti instance
            # if no valid state is found, then state is reset using the provided config
            current_state = self.helper.get_state()
            if self._validate_state(current_state):
                self.helper.log_info(
                    "State initialized using state from opencti instance"
                )
            else:
                self.helper.log_info(
                    "State from opencti is absent or invalid, resetting state..."
                )
                current_state = self._set_initial_state()

        while True:
            try:
                if self.ocd_import_worldwatch:
                    try:
                        self._import_worldwatch()
                    except Exception as ex:
                        self.helper.log_error(
                            f"Encountered an error while ingesting WorldWatch: {str(ex)}"
                        )
                if self.ocd_import_threat_library:
                    try:
                        if self._import_threat_library():
                            self.helper.log_info("Threat Library successfully updated")
                        else:
                            self.helper.log_info(
                                "No updates available for Threat Library"
                            )
                    except Exception as ex:
                        self.helper.log_error(
                            f"Encountered an error while updating ThreatLibrary: {str(ex)}"
                        )
                if self.ocd_import_datalake:
                    try:
                        self._import_datalake()
                    except Exception as ex:
                        self.helper.log_error(
                            f"Encountered an error while ingesting Datalake: {str(ex)}"
                        )

                logging.info(f"Sleeping for {self.ocd_interval} minutes")
                time.sleep(int(self.ocd_interval) * 60)
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                exit(0)


if __name__ == "__main__":
    try:
        ocdConnector = OrangeCyberDefense()
        ocdConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
