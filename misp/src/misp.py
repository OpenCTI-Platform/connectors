import os
import yaml
import time
import json

from datetime import datetime
from dateutil.parser import parse
from pymisp import ExpandedPyMISP
from stix2 import (
    Bundle,
    Identity,
    IntrusionSet,
    Malware,
    Tool,
    AttackPattern,
    Report,
    Indicator,
    Relationship,
    ExternalReference,
    TLP_WHITE,
    TLP_GREEN,
    TLP_AMBER,
    TLP_RED,
    ObjectPath,
    EqualityComparisonExpression,
    ObservationExpression,
)

from pycti import OpenCTIConnectorHelper, get_config_variable

PATTERNTYPES = ["yara", "sigma", "pcre", "snort", "suricata"]
OPENCTISTIX2 = {
    "autonomous-system": {
        "type": "autonomous-system",
        "path": ["number"],
        "transform": {"operation": "remove_string", "value": "AS"},
    },
    "mac-addr": {"type": "mac-addr", "path": ["value"]},
    "domain": {"type": "domain-name", "path": ["value"]},
    "ipv4-addr": {"type": "ipv4-addr", "path": ["value"]},
    "ipv6-addr": {"type": "ipv6-addr", "path": ["value"]},
    "url": {"type": "url", "path": ["value"]},
    "email-address": {"type": "email-addr", "path": ["value"]},
    "email-subject": {"type": "email-message", "path": ["subject"]},
    "mutex": {"type": "mutex", "path": ["name"]},
    "file-name": {"type": "file", "path": ["name"]},
    "file-path": {"type": "file", "path": ["name"]},
    "file-md5": {"type": "file", "path": ["hashes", "MD5"]},
    "file-sha1": {"type": "file", "path": ["hashes", "SHA1"]},
    "file-sha256": {"type": "file", "path": ["hashes", "SHA256"]},
    "directory": {"type": "directory", "path": ["path"]},
    "registry-key": {"type": "windows-registry-key", "path": ["key"]},
    "registry-key-value": {"type": "windows-registry-value-type", "path": ["data"]},
    "pdb-path": {"type": "file", "path": ["name"]},
    "windows-service-name": {"type": "windows-service-ext", "path": ["service_name"]},
    "windows-service-display-name": {
        "type": "windows-service-ext",
        "path": ["display_name"],
    },
    "x509-certificate-issuer": {"type": "x509-certificate", "path": ["issuer"]},
    "x509-certificate-serial-number": {
        "type": "x509-certificate",
        "path": ["serial_number"],
    },
}
FILETYPES = ["file-name", "file-md5", "file-sha1", "file-sha256"]

class Misp:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
        self.misp_url = get_config_variable("MISP_URL", ["misp", "url"], config)
        self.misp_key = get_config_variable("MISP_KEY", ["misp", "key"], config)
        self.misp_ssl_verify = get_config_variable(
            "MISP_SSL_VERIFY", ["misp", "ssl_verify"], config
        )
        self.misp_create_report = get_config_variable(
            "MISP_CREATE_REPORTS", ["misp", "create_reports"], config
        )
        self.misp_report_class = (
            get_config_variable("MISP_REPORT_CLASS", ["misp", "report_class"], config)
            or "MISP Event"
        )
        self.misp_import_from_date = get_config_variable(
            "MISP_IMPORT_FROM_DATE", ["misp", "import_from_date"], config
        )
        self.misp_import_tags = get_config_variable(
            "MISP_IMPORT_TAGS", ["misp", "import_tags"], config
        )
        self.misp_interval = get_config_variable(
            "MISP_INTERVAL", ["misp", "interval"], config, True
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )

        # Initialize MISP
        self.misp = ExpandedPyMISP(
            url=self.misp_url, key=self.misp_key, ssl=self.misp_ssl_verify, debug=False
        )

    def get_interval(self):
        return int(self.misp_interval) * 60

    def run(self):
        while True:
            timestamp = int(time.time())
            # Get the last_run datetime
            current_state = self.helper.get_state()
            if current_state is not None and "last_run" in current_state:
                last_run = datetime.utcfromtimestamp(
                    current_state["last_run"]
                ).strftime("%Y-%m-%d %H:%M:%S")
                self.helper.log_info("Connector last run: " + last_run)
            else:
                last_run = None
                self.helper.log_info("Connector has never run")

            # If import with tags
            complex_query_tag = None
            if self.misp_import_tags is not None:
                or_parameters = []
                for tag in self.misp_import_tags.split(","):
                    or_parameters.append(tag.strip())
                    complex_query_tag = self.misp.build_complex_query(
                        or_parameters=or_parameters
                    )

            # If import from a specific date
            import_from_date = None
            if self.misp_import_from_date is not None:
                import_from_date = parse(self.misp_import_from_date).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

            # Prepare the query
            kwargs = dict()
            if complex_query_tag is not None:
                kwargs["tags"] = complex_query_tag
            if last_run is not None:
                kwargs["timestamp"] = last_run
            elif import_from_date is not None:
                kwargs["date_from"] = import_from_date

            # Query with pagination of 100
            current_page = 1
            while True:
                kwargs["limit"] = 50
                kwargs["page"] = current_page
                self.helper.log_info(
                    "Fetching MISP events with args: " + json.dumps(kwargs)
                )
                events = []
                try:
                    events = self.misp.search("events", **kwargs)
                except Exception as e:
                    self.helper.log_error(str(e))
                    try:
                        events = self.misp.search("events", **kwargs)
                    except Exception as e:
                        self.helper.log_error(str(e))

                self.helper.log_info("MISP returned " + str(len(events)) + " events.")
                # Break if no more result
                if len(events) == 0:
                    break
                try:
                    self.process_events(events)
                except Exception as e:
                    self.helper.log_error(str(e))
                current_page += 1
            self.helper.set_state({"last_run": timestamp})
            time.sleep(self.get_interval())

    def process_events(self, events):
        for event in events:
            self.helper.log_info("Processing event " + event["Event"]["uuid"])
            ### Default variables
            added_markings = []
            added_entities = []
            added_object_refs = []

            ### Pre-process
            # Author
            author = Identity(
                name=event["Event"]["Orgc"]["name"], identity_class="organization"
            )
            # Elements
            event_elements = self.prepare_elements(event["Event"]["Galaxy"], author)
            # Markings
            if "Tag" in event["Event"]:
                event_markings = self.resolve_markings(event["Event"]["Tag"])
            else:
                event_markings = [TLP_WHITE]
            # Tags
            event_tags = []
            if "Tag" in event["Event"]:
                event_tags = self.resolve_tags(event["Event"]["Tag"])
            # ExternalReference
            event_external_reference = ExternalReference(
                source_name=self.helper.connect_name,
                external_id=event["Event"]["uuid"],
                url=self.misp_url + "/events/view/" + event["Event"]["uuid"],
            )

            ### Get indicators
            event_external_references = [event_external_reference]
            indicators = []
            # Get attributes
            for attribute in event["Event"]["Attribute"]:
                indicator = self.process_attribute(
                    author, event_elements, event_markings, [], attribute
                )
                if attribute["type"] == "link":
                    event_external_references.append(
                        ExternalReference(
                            source_name=attribute["category"],
                            external_id=attribute["uuid"],
                            url=attribute["value"],
                        )
                    )
                if indicator is not None:
                    indicators.append(indicator)
            # Get attributes of objects
            objects_relationships = []
            for object in event["Event"]["Object"]:
                attribute_external_references = []
                for attribute in object["Attribute"]:
                    if attribute["type"] == "link":
                        attribute_external_references.append(
                            ExternalReference(
                                source_name=attribute["category"],
                                external_id=attribute["uuid"],
                                url=attribute["value"],
                            )
                        )
                object_attributes = []
                for attribute in object["Attribute"]:
                    indicator = self.process_attribute(
                        author, event_elements, event_markings, attribute_external_references, attribute
                    )
                    if indicator is not None:
                        indicators.append(indicator)
                        if (
                            object["meta-category"] == "file"
                            and indicator["indicator"].x_opencti_observable_type
                            in FILETYPES
                        ):
                            object_attributes.append(indicator)
                objects_relationships.extend(
                    self.process_observable_relations(object_attributes, [])
                )

            ### Prepare the bundle
            bundle_objects = [author]
            object_refs = []
            # Add event markings
            for event_marking in event_markings:
                if event_marking["id"] not in added_markings:
                    bundle_objects.append(event_marking)
                    added_markings.append(event_marking["id"])
            # Add event elements
            all_event_elements = (
                event_elements["intrusion_sets"]
                + event_elements["malwares"]
                + event_elements["tools"]
                + event_elements["attack_patterns"]
            )
            for event_element in all_event_elements:
                if event_element["name"] not in added_object_refs:
                    object_refs.append(event_element)
                    added_object_refs.append(event_element["name"])
                if event_element["name"] not in added_entities:
                    bundle_objects.append(event_element)
                    added_entities.append(event_element["name"])
            # Add indicators
            for indicator in indicators:
                if indicator["indicator"]["id"] not in added_object_refs:
                    object_refs.append(indicator["indicator"])
                    added_object_refs.append(indicator["indicator"]["id"])
                if indicator["indicator"]["id"] not in added_entities:
                    bundle_objects.append(indicator["indicator"])
                    added_entities.append(indicator["indicator"]["id"])
                # Add attribute markings
                for attribute_marking in indicator["markings"]:
                    if attribute_marking["id"] not in added_markings:
                        bundle_objects.append(attribute_marking)
                        added_markings.append(attribute_marking["id"])
                # Add attribute elements
                all_attribute_elements = (
                    indicator["attribute_elements"]["intrusion_sets"]
                    + indicator["attribute_elements"]["malwares"]
                    + indicator["attribute_elements"]["tools"]
                    + indicator["attribute_elements"]["attack_patterns"]
                )
                for attribute_element in all_attribute_elements:
                    if attribute_element["name"] not in added_object_refs:
                        object_refs.append(attribute_element)
                        added_object_refs.append(attribute_element["name"])
                    if attribute_element["name"] not in added_entities:
                        bundle_objects.append(attribute_element)
                        added_entities.append(attribute_element["name"])
                # Add attribute relationships
                for relationship in indicator["relationships"]:
                    object_refs.append(relationship)
                    bundle_objects.append(relationship)
            # Add object_relationships
            for object_relationship in objects_relationships:
                bundle_objects.append(object_relationship)

            ### Create the report if needed
            if self.misp_create_report and len(object_refs) > 0:
                report = Report(
                    name=event["Event"]["info"],
                    description=event["Event"]["info"],
                    published=parse(event["Event"]["date"]),
                    created_by_ref=author,
                    object_marking_refs=event_markings,
                    labels=["threat-report"],
                    object_refs=object_refs,
                    external_references=event_external_references,
                    custom_properties={
                        "x_opencti_report_class": self.misp_report_class,
                        "x_opencti_object_status": 2,
                        "x_opencti_tags": event_tags,
                    },
                )
                bundle_objects.append(report)
            bundle = Bundle(objects=bundle_objects).serialize()
            self.helper.log_info("Sending event STIX2 bundle")
            self.helper.send_stix2_bundle(
                bundle, None, self.update_existing_data, False
            )

    def process_attribute(self, author, event_elements, event_markings, attribute_external_references, attribute):
        try:
            resolved_attributes = self.resolve_type(
                attribute["type"], attribute["value"]
            )
            if resolved_attributes is None:
                return None

            for resolved_attribute in resolved_attributes:
                ### Pre-process
                # Elements
                attribute_elements = self.prepare_elements(attribute["Galaxy"], author)
                # Markings & Tags
                attribute_tags = []
                if "Tag" in attribute:
                    attribute_markings = self.resolve_markings(
                        attribute["Tag"], with_default=False
                    )
                    attribute_tags = self.resolve_tags(attribute["Tag"])
                    if len(attribute_markings) == 0:
                        attribute_markings = event_markings
                else:
                    attribute_markings = event_markings

                ### Create the indicator
                observable_type = resolved_attribute["type"]
                observable_value = resolved_attribute["value"]
                name = resolved_attribute["value"]
                pattern_type = "stix"
                # observable type is yara for instance
                if observable_type in PATTERNTYPES:
                    pattern_type = observable_type
                    observable_type = "Unknown"
                    genuine_pattern = (
                        "[file:hashes.md5 = 'd41d8cd98f00b204e9800998ecf8427e']"
                    )
                    pattern = observable_value
                    name = (
                        attribute["comment"]
                        if len(attribute["comment"]) > 0
                        else observable_type
                    )
                # observable type is not in stix 2
                elif observable_type not in OPENCTISTIX2:
                    return None
                # observable type is in stix
                else:
                    if "transform" in OPENCTISTIX2[observable_type]:
                        if (
                            OPENCTISTIX2[observable_type]["transform"]["operation"]
                            == "remove_string"
                        ):
                            observable_value = observable_value.replace(
                                OPENCTISTIX2[observable_type]["transform"]["value"], ""
                            )
                    lhs = ObjectPath(
                        OPENCTISTIX2[observable_type]["type"],
                        OPENCTISTIX2[observable_type]["path"],
                    )
                    genuine_pattern = str(
                        ObservationExpression(
                            EqualityComparisonExpression(lhs, observable_value)
                        )
                    )
                    pattern = genuine_pattern

                indicator = Indicator(
                    name=name,
                    description=attribute["comment"],
                    pattern=genuine_pattern,
                    valid_from=datetime.utcfromtimestamp(
                        int(attribute["timestamp"])
                    ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    labels=["malicious-activity"],
                    created_by_ref=author,
                    object_marking_refs=attribute_markings,
                    external_references=attribute_external_references,
                    custom_properties={
                        "x_opencti_indicator_pattern": pattern,
                        "x_opencti_observable_type": observable_type,
                        "x_opencti_observable_value": observable_value,
                        "x_opencti_pattern_type": pattern_type,
                        "x_opencti_tags": attribute_tags,
                    },
                )

                ### Create the relationships
                relationships = []
                # Event threats
                for threat in (
                    event_elements["intrusion_sets"]
                    + event_elements["malwares"]
                    + event_elements["tools"]
                ):
                    relationships.append(
                        Relationship(
                            relationship_type="indicates",
                            created_by_ref=author,
                            source_ref=indicator.id,
                            target_ref=threat.id,
                            description=attribute["comment"],
                            object_marking_refs=attribute_markings,
                            custom_properties={
                                "x_opencti_first_seen": datetime.utcfromtimestamp(
                                    int(attribute["timestamp"])
                                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                "x_opencti_last_seen": datetime.utcfromtimestamp(
                                    int(attribute["timestamp"])
                                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                "x_opencti_weight": self.helper.connect_confidence_level,
                            },
                        )
                    )
                # Attribute threats
                for threat in (
                    attribute_elements["intrusion_sets"]
                    + attribute_elements["malwares"]
                    + attribute_elements["tools"]
                ):
                    relationships.append(
                        Relationship(
                            relationship_type="indicates",
                            created_by_ref=author,
                            source_ref=indicator.id,
                            target_ref=threat.id,
                            description=attribute["comment"],
                            object_marking_refs=attribute_markings,
                            custom_properties={
                                "x_opencti_first_seen": datetime.utcfromtimestamp(
                                    int(attribute["timestamp"])
                                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                "x_opencti_last_seen": datetime.utcfromtimestamp(
                                    int(attribute["timestamp"])
                                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                "x_opencti_weight": self.helper.connect_confidence_level,
                            },
                        )
                    )
                # Event Attack Patterns
                for attack_pattern in event_elements["attack_patterns"]:
                    if len(event_elements["malwares"]) > 0:
                        threats = event_elements["malwares"]
                    elif len(event_elements["intrusion_sets"]) > 0:
                        threats = event_elements["intrusion_sets"]
                    else:
                        threats = []
                    for threat in threats:
                        relationship_uses = Relationship(
                            relationship_type="uses",
                            created_by_ref=author,
                            source_ref=threat.id,
                            target_ref=attack_pattern.id,
                            description=attribute["comment"],
                            object_marking_refs=attribute_markings,
                            custom_properties={
                                "x_opencti_first_seen": datetime.utcfromtimestamp(
                                    int(attribute["timestamp"])
                                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                "x_opencti_last_seen": datetime.utcfromtimestamp(
                                    int(attribute["timestamp"])
                                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                "x_opencti_weight": self.helper.connect_confidence_level,
                                "x_opencti_ignore_dates": True,
                            },
                        )
                        relationships.append(relationship_uses)
                        relationship_indicates = Relationship(
                            relationship_type="indicates",
                            created_by_ref=author,
                            source_ref=indicator.id,
                            target_ref="malware--fa42a846-8d90-4e51-bc29-71d5b4802168",  # Fake
                            description=attribute["comment"],
                            object_marking_refs=attribute_markings,
                            custom_properties={
                                "x_opencti_first_seen": datetime.utcfromtimestamp(
                                    int(attribute["timestamp"])
                                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                "x_opencti_last_seen": datetime.utcfromtimestamp(
                                    int(attribute["timestamp"])
                                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                "x_opencti_weight": self.helper.connect_confidence_level,
                                "x_opencti_source_ref": indicator.id,
                                "x_opencti_target_ref": relationship_uses.id,
                            },
                        )
                        relationships.append(relationship_indicates)
                # Attribute Attack Patterns
                for attack_pattern in attribute_elements["attack_patterns"]:
                    if len(attribute_elements["malwares"]) > 0:
                        threats = attribute_elements["malwares"]
                    elif len(attribute_elements["intrusion_sets"]) > 0:
                        threats = attribute_elements["intrusion_sets"]
                    else:
                        threats = []
                    for threat in threats:
                        relationship_uses = Relationship(
                            relationship_type="uses",
                            created_by_ref=author,
                            source_ref=threat.id,
                            target_ref=attack_pattern.id,
                            description=attribute["comment"],
                            object_marking_refs=attribute_markings,
                            custom_properties={
                                "x_opencti_first_seen": datetime.utcfromtimestamp(
                                    int(attribute["timestamp"])
                                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                "x_opencti_last_seen": datetime.utcfromtimestamp(
                                    int(attribute["timestamp"])
                                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                "x_opencti_weight": self.helper.connect_confidence_level,
                                "x_opencti_ignore_dates": True,
                            },
                        )
                        relationships.append(relationship_uses)
                        relationship_indicates = Relationship(
                            relationship_type="indicates",
                            created_by_ref=author,
                            source_ref=indicator.id,
                            target_ref="malware--fa42a846-8d90-4e51-bc29-71d5b4802168",  # Fake
                            description=attribute["comment"],
                            object_marking_refs=attribute_markings,
                            custom_properties={
                                "x_opencti_first_seen": datetime.utcfromtimestamp(
                                    int(attribute["timestamp"])
                                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                "x_opencti_last_seen": datetime.utcfromtimestamp(
                                    int(attribute["timestamp"])
                                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                "x_opencti_weight": self.helper.connect_confidence_level,
                                "x_opencti_source_ref": indicator.id,
                                "x_opencti_target_ref": relationship_uses.id,
                                "x_opencti_ignore_dates": True,
                            },
                        )
                        relationships.append(relationship_indicates)

                return {
                    "indicator": indicator,
                    "relationships": relationships,
                    "attribute_elements": attribute_elements,
                    "markings": attribute_markings,
                }
        except:
            return None

    def process_observable_relations(
        self, object_attributes, result_table, start_element=0
    ):
        if start_element == 0:
            result_table = []
        if len(object_attributes) == 1:
            return []

        for x in range(start_element + 1, len(object_attributes)):
            result_table.append(
                Relationship(
                    relationship_type="corresponds",
                    source_ref=object_attributes[start_element]["indicator"]["id"],
                    target_ref=object_attributes[x]["indicator"]["id"],
                    description="Same file",
                    custom_properties={"x_opencti_ignore_dates": True},
                )
            )
        if start_element != len(object_attributes):
            return self.process_observable_relations(
                object_attributes, result_table, start_element + 1
            )
        else:
            return result_table

    def prepare_elements(self, galaxies, author):
        elements = {
            "intrusion_sets": [],
            "malwares": [],
            "tools": [],
            "attack_patterns": [],
        }
        added_names = []
        for galaxy in galaxies:
            # Get the linked intrusion sets
            if (
                (
                    galaxy["namespace"] == "mitre-attack"
                    and galaxy["name"] == "Intrusion Set"
                )
                or (galaxy["namespace"] == "misp" and galaxy["name"] == "Threat Actor")
                or (
                    galaxy["namespace"] == "misp"
                    and galaxy["name"] == "Microsoft Activity Group actor"
                )
            ):
                for galaxy_entity in galaxy["GalaxyCluster"]:
                    if " - G" in galaxy_entity["value"]:
                        name = galaxy_entity["value"].split(" - G")[0]
                    elif "APT " in galaxy_entity["value"]:
                        name = galaxy_entity["value"].replace("APT ", "APT")
                    else:
                        name = galaxy_entity["value"]
                    if "meta" in galaxy_entity and "synonyms" in galaxy_entity["meta"]:
                        aliases = galaxy_entity["meta"]["synonyms"]
                    else:
                        aliases = [name]
                    if name not in added_names:
                        elements["intrusion_sets"].append(
                            IntrusionSet(
                                name=name,
                                labels=["intrusion-set"],
                                description=galaxy_entity["description"],
                                created_by_ref=author,
                                custom_properties={"x_opencti_aliases": aliases},
                            )
                        )
                        added_names.append(name)
            # Get the linked malwares
            if (
                (galaxy["namespace"] == "mitre-attack" and galaxy["name"] == "Malware")
                or (galaxy["namespace"] == "misp" and galaxy["name"] == "Tool")
                or (galaxy["namespace"] == "misp" and galaxy["name"] == "Ransomware")
                or (galaxy["namespace"] == "misp" and galaxy["name"] == "Android")
                or (galaxy["namespace"] == "misp" and galaxy["name"] == "Malpedia")
            ):
                for galaxy_entity in galaxy["GalaxyCluster"]:
                    if " - S" in galaxy_entity["value"]:
                        name = galaxy_entity["value"].split(" - S")[0]
                    else:
                        name = galaxy_entity["value"]
                    if "meta" in galaxy_entity and "synonyms" in galaxy_entity["meta"]:
                        aliases = galaxy_entity["meta"]["synonyms"]
                    else:
                        aliases = [name]
                    if name not in added_names:
                        elements["malwares"].append(
                            Malware(
                                name=name,
                                labels=["malware"],
                                description=galaxy_entity["description"],
                                created_by_ref=author,
                                custom_properties={"x_opencti_aliases": aliases},
                            )
                        )
                        added_names.append(name)
            # Get the linked tools
            if galaxy["namespace"] == "mitre-attack" and galaxy["name"] == "Tool":
                for galaxy_entity in galaxy["GalaxyCluster"]:
                    if " - S" in galaxy_entity["value"]:
                        name = galaxy_entity["value"].split(" - S")[0]
                    else:
                        name = galaxy_entity["value"]
                    if "meta" in galaxy_entity and "synonyms" in galaxy_entity["meta"]:
                        aliases = galaxy_entity["meta"]["synonyms"]
                    else:
                        aliases = [name]
                    if name not in added_names:
                        elements["tools"].append(
                            Tool(
                                name=name,
                                labels=["tool"],
                                description=galaxy_entity["description"],
                                created_by_ref=author,
                                custom_properties={"x_opencti_aliases": aliases},
                            )
                        )
                        added_names.append(name)
            # Get the linked attack_patterns
            if (
                galaxy["namespace"] == "mitre-attack"
                and galaxy["name"] == "Attack Pattern"
            ):
                for galaxy_entity in galaxy["GalaxyCluster"]:
                    if " - T" in galaxy_entity["value"]:
                        name = galaxy_entity["value"].split(" - T")[0]
                    else:
                        name = galaxy_entity["value"]
                    if "meta" in galaxy_entity and "synonyms" in galaxy_entity["meta"]:
                        aliases = galaxy_entity["meta"]["synonyms"]
                    else:
                        aliases = [name]
                    if name not in added_names:
                        elements["attack_patterns"].append(
                            AttackPattern(
                                name=name,
                                labels=["attack-pattern"],
                                description=galaxy_entity["description"],
                                created_by_ref=author,
                                custom_properties={
                                    "x_opencti_external_id": galaxy_entity["meta"][
                                        "external_id"
                                    ][0],
                                    "x_opencti_aliases": aliases,
                                },
                            )
                        )
                        added_names.append(name)
        return elements

    def resolve_type(self, type, value):
        types = {
            "yara": ["yara"],
            "md5": ["file-md5"],
            "sha1": ["file-sha1"],
            "sha256": ["file-sha256"],
            "filename": ["file-name"],
            "pdb": ["pdb-path"],
            "filename|md5": ["file-name", "file-md5"],
            "filename|sha1": ["file-name", "file-sha1"],
            "filename|sha256": ["file-name", "file-sha256"],
            "ip-src": ["ipv4-addr"],
            "ip-dst": ["ipv4-addr"],
            "hostname": ["domain"],
            "domain": ["domain"],
            "domain|ip": ["domain", "ipv4-addr"],
            "url": ["url"],
            "windows-service-name": ["windows-service-name"],
            "windows-service-displayname": ["windows-service-display-name"],
            "windows-scheduled-task": ["windows-scheduled-task"],
        }
        if type in types:
            resolved_types = types[type]
            if len(resolved_types) == 2:
                values = value.split("|")
                if resolved_types[0] == "ipv4-addr":
                    type_0 = self.detect_ip_version(values[0])
                else:
                    type_0 = resolved_types[0]
                if resolved_types[1] == "ipv4-addr":
                    type_1 = self.detect_ip_version(values[1])
                else:
                    type_1 = resolved_types[1]
                return [
                    {"type": type_0, "value": values[0]},
                    {"type": type_1, "value": values[1]},
                ]
            else:
                if resolved_types[0] == "ipv4-addr":
                    type_0 = self.detect_ip_version(value)
                else:
                    type_0 = resolved_types[0]
                return [{"type": type_0, "value": value}]

    def detect_ip_version(self, value):
        if len(value) > 16:
            return "ipv6-addr"
        else:
            return "ipv4-addr"

    def resolve_markings(self, tags, with_default=True):
        markings = []
        for tag in tags:
            if tag["name"] == "tlp:white":
                markings.append(TLP_WHITE)
            if tag["name"] == "tlp:green":
                markings.append(TLP_GREEN)
            if tag["name"] == "tlp:amber":
                markings.append(TLP_AMBER)
            if tag["name"] == "tlp:red":
                markings.append(TLP_RED)
        if len(markings) == 0 and with_default:
            markings.append(TLP_WHITE)
        return markings

    def resolve_tags(self, tags):
        opencti_tags = []
        for tag in tags:
            if (
                tag["name"] != "tlp:white"
                and tag["name"] != "tlp:green"
                and tag["name"] != "tlp:amber"
                and tag["name"] != "tlp:red"
                and not tag["name"].startswith("misp-galaxy:mitre-threat-actor")
                and not tag["name"].startswith("misp-galaxy:mitre-intrusion-set")
                and not tag["name"].startswith("misp-galaxy:mitre-malware")
                and not tag["name"].startswith("misp-galaxy:mitre-attack-pattern")
                and not tag["name"].startswith("misp-galaxy:mitre-tool")
                and not tag["name"].startswith("misp-galaxy:tool")
                and not tag["name"].startswith("misp-galaxy:ransomware")
                and not tag["name"].startswith("misp-galaxy:malpedia")
            ):
                tag_value = tag["name"]
                if "=\"" in tag["name"]:
                    tag_value_split = tag["name"].split("=\"")
                    tag_value = tag_value_split[1][:-1].strip()
                elif ":" in tag["name"]:
                    tag_value_split = tag["name"].split(":")
                    tag_value = tag_value_split[1].strip()
                if tag_value.isdigit():
                    if ":" in tag["name"]:
                        tag_value_split = tag["name"].split(":")
                        tag_value = tag_value_split[1].strip()
                    else:
                        tag_value = tag["name"]
                opencti_tags.append(
                    {"tag_type": "MISP", "value": tag_value, "color": "#008ac8"}
                )
        return opencti_tags


if __name__ == "__main__":
    try:
        mispConnector = Misp()
        mispConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
