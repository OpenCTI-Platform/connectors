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
    Sighting,
    TLP_WHITE,
    TLP_GREEN,
    TLP_AMBER,
    TLP_RED,
    ObjectPath,
    EqualityComparisonExpression,
    ObservationExpression,
)

from pycti import (
    OpenCTIConnectorHelper,
    get_config_variable,
    SimpleObservable,
    OpenCTIStix2Utils,
)

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
    "file-sha1": {"type": "file", "path": ["hashes", "SHA-1"]},
    "file-sha256": {"type": "file", "path": ["hashes", "SHA-256"]},
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
        self.misp_create_indicators = get_config_variable(
            "MISP_CREATE_INDICATORS", ["misp", "create_indicators"], config
        )
        self.misp_create_observables = get_config_variable(
            "MISP_CREATE_OBSERVABLES", ["misp", "create_observables"], config
        )
        self.misp_report_type = (
            get_config_variable("MISP_REPORT_TYPE", ["misp", "report_type"], config)
            or "MISP Event"
        )
        self.misp_import_from_date = get_config_variable(
            "MISP_IMPORT_FROM_DATE", ["misp", "import_from_date"], config
        )
        self.misp_import_tags = get_config_variable(
            "MISP_IMPORT_TAGS", ["misp", "import_tags"], config
        )
        self.misp_import_tags_not = get_config_variable(
            "MISP_IMPORT_TAGS_NOT", ["misp", "import_tags_not"], config
        )
        self.import_creator_orgs = get_config_variable(
            "MISP_IMPORT_CREATOR_ORGS", ["misp", "import_creator_orgs"], config
        )
        self.import_owner_orgs = get_config_variable(
            "MISP_IMPORT_OWNER_ORGS", ["misp", "import_owner_orgs"], config
        )
        self.import_distribution_levels = get_config_variable(
            "MISP_IMPORT_DISTRIBUTION_LEVELS",
            ["misp", "import_distribution_levels"],
            config,
        )
        self.import_threat_levels = get_config_variable(
            "MISP_IMPORT_THREAT_LEVELS", ["misp", "import_threat_levels"], config
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
                last_run = datetime.utcfromtimestamp(current_state["last_run"])
                self.helper.log_info(
                    "Connector last run: " + last_run.strftime("%Y-%m-%d %H:%M:%S")
                )
            else:
                last_run = None
                self.helper.log_info("Connector has never run")

            # If import with tags
            complex_query_tag = None
            if (self.misp_import_tags is not None) or (
                self.misp_import_tags_not is not None
            ):
                or_parameters = []
                not_parameters = []

                if self.misp_import_tags:
                    for tag in self.misp_import_tags.split(","):
                        or_parameters.append(tag.strip())
                if self.misp_import_tags_not:
                    for ntag in self.misp_import_tags_not.split(","):
                        not_parameters.append(ntag.strip())

                complex_query_tag = self.misp.build_complex_query(
                    or_parameters=or_parameters if len(or_parameters) > 0 else None,
                    not_parameters=not_parameters if len(not_parameters) > 0 else None,
                )

            # If import from a specific date
            import_from_date = None
            if self.misp_import_from_date is not None:
                import_from_date = datetime.fromisoformat(self.misp_import_from_date)

            # Prepare the query
            kwargs = dict()
            if complex_query_tag is not None:
                kwargs["tags"] = complex_query_tag
            if last_run is not None:
                kwargs["timestamp"] = int(last_run.timestamp())
            elif import_from_date is not None:
                kwargs["date_from"] = import_from_date.strftime("%Y-%m-%d")

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

                self.process_events(events)
                current_page += 1
            self.helper.set_state({"last_run": timestamp})
            time.sleep(self.get_interval())

    def process_events(self, events):
        try:
            # Prepare filters
            import_creator_orgs = None
            import_owner_orgs = None
            import_distribution_levels = None
            import_threat_levels = None
            if self.import_creator_orgs is not None:
                import_creator_orgs = self.import_creator_orgs.split(",")
            if self.import_owner_orgs is not None:
                import_owner_orgs = self.import_owner_orgs.split(",")
            if self.import_distribution_levels is not None:
                import_distribution_levels = self.import_distribution_levels.split(",")
            if self.import_threat_levels is not None:
                import_threat_levels = self.import_threat_levels.split(",")

            for event in events:
                self.helper.log_info("Processing event " + event["Event"]["uuid"])

                # Check against filter
                if (
                    import_creator_orgs is not None
                    and event["Event"]["Orgc"]["name"] not in import_creator_orgs
                ):
                    self.helper.log_info(
                        "Event creator organization "
                        + event["Event"]["Orgc"]["name"]
                        + " not in import_creator_orgs, do not import"
                    )
                    continue
                if (
                    import_owner_orgs is not None
                    and event["Event"]["Org"]["name"] not in import_owner_orgs
                ):
                    self.helper.log_info(
                        "Event owner organization "
                        + event["Event"]["Org"]["name"]
                        + " not in import_owner_orgs, do not import"
                    )
                    continue
                if (
                    import_distribution_levels is not None
                    and event["Event"]["distribution"] not in import_distribution_levels
                ):
                    self.helper.log_info(
                        "Event distribution level "
                        + event["Event"]["distribution"]
                        + " not in import_distribution_levels, do not import"
                    )
                    continue
                if (
                    import_threat_levels is not None
                    and event["Event"]["threat_level_id"] not in import_threat_levels
                ):
                    self.helper.log_info(
                        "Event threat level "
                        + event["Event"]["threat_level_id"]
                        + " not in import_threat_levels, do not import"
                    )
                    continue

                ### Default variables
                added_markings = []
                added_entities = []
                added_object_refs = []
                added_sightings = []

                ### Pre-process
                # Author
                author = Identity(
                    name=event["Event"]["Orgc"]["name"], identity_class="organization"
                )
                # Markings
                if "Tag" in event["Event"]:
                    event_markings = self.resolve_markings(event["Event"]["Tag"])
                else:
                    event_markings = [TLP_WHITE]
                # Elements
                event_elements = self.prepare_elements(
                    event["Event"]["Galaxy"],
                    event["Event"]["Tag"],
                    author,
                    event_markings,
                )
                # Tags
                event_tags = []
                if "Tag" in event["Event"]:
                    event_tags = self.resolve_tags(event["Event"]["Tag"])
                # ExternalReference
                event_external_reference = ExternalReference(
                    source_name=self.helper.connect_name,
                    description=event["Event"]["info"],
                    external_id=event["Event"]["uuid"],
                    url=self.misp_url + "/events/view/" + event["Event"]["uuid"],
                )

                ### Get indicators
                event_external_references = [event_external_reference]
                indicators = []
                # Get attributes
                for attribute in event["Event"]["Attribute"]:
                    indicator = self.process_attribute(
                        author,
                        event_elements,
                        event_markings,
                        event_tags,
                        [],
                        attribute,
                        event["Event"]["threat_level_id"],
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
                            author,
                            event_elements,
                            event_markings,
                            event_tags,
                            attribute_external_references,
                            attribute,
                            event["Event"]["threat_level_id"],
                        )
                        if indicator is not None:
                            indicators.append(indicator)
                            if (
                                object["meta-category"] == "file"
                                and indicator[
                                    "indicator"
                                ].x_opencti_main_observable_type
                                in FILETYPES
                            ):
                                object_attributes.append(indicator)
                    # TODO Extend observable

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
                    if indicator["indicator"] is not None:
                        if indicator["indicator"]["id"] not in added_object_refs:
                            object_refs.append(indicator["indicator"])
                            added_object_refs.append(indicator["indicator"]["id"])
                        if indicator["indicator"]["id"] not in added_entities:
                            bundle_objects.append(indicator["indicator"])
                            added_entities.append(indicator["indicator"]["id"])
                    if indicator["observable"] is not None:
                        if indicator["observable"]["id"] not in added_object_refs:
                            object_refs.append(indicator["observable"])
                            added_object_refs.append(indicator["observable"]["id"])
                        if indicator["observable"]["id"] not in added_entities:
                            bundle_objects.append(indicator["observable"])
                            added_entities.append(indicator["observable"]["id"])

                    # Add attribute markings
                    for attribute_marking in indicator["markings"]:
                        if attribute_marking["id"] not in added_markings:
                            bundle_objects.append(attribute_marking)
                            added_markings.append(attribute_marking["id"])
                    # Add attribute sightings identities
                    for attribute_identity in indicator["identities"]:
                        if attribute_identity["id"] not in added_entities:
                            bundle_objects.append(attribute_identity)
                            added_entities.append(attribute_identity["id"])
                    # Add attribute sightings
                    for attribute_sighting in indicator["sightings"]:
                        if attribute_sighting["id"] not in added_sightings:
                            bundle_objects.append(attribute_sighting)
                            added_sightings.append(attribute_sighting["id"])
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
                        id=OpenCTIStix2Utils.generate_random_stix_id("report"),
                        name=event["Event"]["info"],
                        description=event["Event"]["info"],
                        published=parse(event["Event"]["date"]),
                        report_types=[self.misp_report_type],
                        created_by_ref=author,
                        object_marking_refs=event_markings,
                        labels=event_tags,
                        object_refs=object_refs,
                        external_references=event_external_references,
                        custom_properties={
                            "x_opencti_report_status": 2,
                        },
                    )
                    bundle_objects.append(report)
                bundle = Bundle(objects=bundle_objects).serialize()
                self.helper.log_info("Sending event STIX2 bundle")
                self.helper.send_stix2_bundle(
                    bundle, None, self.update_existing_data, True
                )
        except:
            return None

    def process_attribute(
        self,
        author,
        event_elements,
        event_markings,
        event_labels,
        attribute_external_references,
        attribute,
        event_threat_level,
    ):
        resolved_attributes = self.resolve_type(attribute["type"], attribute["value"])
        if resolved_attributes is None:
            return None

        for resolved_attribute in resolved_attributes:
            ### Pre-process
            # Markings & Tags
            attribute_tags = event_labels
            if "Tag" in attribute:
                attribute_markings = self.resolve_markings(
                    attribute["Tag"], with_default=False
                )
                attribute_tags = self.resolve_tags(attribute["Tag"])
                if len(attribute_markings) == 0:
                    attribute_markings = event_markings
            else:
                attribute_markings = event_markings

            # Elements
            tags = []
            galaxies = []
            if "Tag" in attribute:
                tags = attribute["Tag"]
            if "Galaxy" in attribute:
                galaxies = attribute["Galaxy"]
            attribute_elements = self.prepare_elements(
                galaxies, tags, author, attribute_markings
            )

            ### Create the indicator
            observable_resolver = resolved_attribute["resolver"]
            observable_type = resolved_attribute["type"]
            observable_value = resolved_attribute["value"]
            name = resolved_attribute["value"]
            pattern_type = "stix"
            # observable type is yara for instance
            if observable_resolver in PATTERNTYPES:
                pattern_type = observable_resolver
                pattern = observable_value
                name = (
                    attribute["comment"]
                    if len(attribute["comment"]) > 0
                    else observable_type
                )
            # observable type is not in stix 2
            elif observable_resolver not in OPENCTISTIX2:
                return None
            # observable type is in stix
            else:
                if "transform" in OPENCTISTIX2[observable_resolver]:
                    if (
                        OPENCTISTIX2[observable_resolver]["transform"]["operation"]
                        == "remove_string"
                    ):
                        observable_value = observable_value.replace(
                            OPENCTISTIX2[observable_resolver]["transform"]["value"],
                            "",
                        )
                lhs = ObjectPath(
                    OPENCTISTIX2[observable_resolver]["type"],
                    OPENCTISTIX2[observable_resolver]["path"],
                )
                genuine_pattern = str(
                    ObservationExpression(
                        EqualityComparisonExpression(lhs, observable_value)
                    )
                )
                pattern = genuine_pattern

            if event_threat_level == "1":
                score = 90
            elif event_threat_level == "2":
                score = 60
            elif event_threat_level == "3":
                score = 30
            else:
                score = 50

            indicator = None
            if self.misp_create_indicators:
                indicator = Indicator(
                    id=OpenCTIStix2Utils.generate_random_stix_id("indicator"),
                    name=name,
                    description=attribute["comment"],
                    pattern_type=pattern_type,
                    pattern=pattern,
                    valid_from=datetime.utcfromtimestamp(
                        int(attribute["timestamp"])
                    ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    labels=attribute_tags,
                    created_by_ref=author,
                    object_marking_refs=attribute_markings,
                    external_references=attribute_external_references,
                    created=datetime.utcfromtimestamp(
                        int(attribute["timestamp"])
                    ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    modified=datetime.utcfromtimestamp(
                        int(attribute["timestamp"])
                    ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    custom_properties={
                        "x_opencti_main_observable_type": observable_type,
                        "x_opencti_detection": attribute["to_ids"],
                        "x_opencti_score": score,
                    },
                )
            observable = None
            if self.misp_create_observables:
                observable = SimpleObservable(
                    id=OpenCTIStix2Utils.generate_random_stix_id(
                        "x-opencti-simple-observable"
                    ),
                    key=observable_type
                    + "."
                    + ".".join(OPENCTISTIX2[observable_resolver]["path"]),
                    value=observable_value,
                    description=attribute["comment"],
                    x_opencti_score=score,
                    labels=attribute_tags,
                    created_by_ref=author,
                    object_marking_refs=attribute_markings,
                    external_references=attribute_external_references,
                )
            sightings = []
            identities = []
            if "Sighting" in attribute:
                for misp_sighting in attribute["Sighting"]:
                    if "Organisation" in misp_sighting:
                        sighted_by = Identity(
                            id="identity--" + misp_sighting["Organisation"]["uuid"],
                            name=misp_sighting["Organisation"]["name"],
                            identity_class="organization",
                        )
                        identities.append(sighted_by)
                    else:
                        sighted_by = None

                    if indicator is not None:
                        sighting = Sighting(
                            id=OpenCTIStix2Utils.generate_random_stix_id("sighting"),
                            sighting_of_ref=indicator["id"],
                            first_seen=datetime.utcfromtimestamp(
                                int(misp_sighting["date_sighting"])
                            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                            last_seen=datetime.utcfromtimestamp(
                                int(misp_sighting["date_sighting"])
                            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                            where_sighted_refs=[sighted_by]
                            if sighted_by is not None
                            else None,
                        )
                        sightings.append(sighting)
                    if observable is not None:
                        sighting = Sighting(
                            id=OpenCTIStix2Utils.generate_random_stix_id("sighting"),
                            sighting_of_ref=observable["id"],
                            first_seen=datetime.utcfromtimestamp(
                                int(misp_sighting["date_sighting"])
                            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                            last_seen=datetime.utcfromtimestamp(
                                int(misp_sighting["date_sighting"])
                            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                            where_sighted_refs=[sighted_by]
                            if sighted_by is not None
                            else None,
                        )
                        sightings.append(sighting)

            ### Create the relationships
            relationships = []
            if indicator is not None and observable is not None:
                relationships.append(
                    Relationship(
                        id=OpenCTIStix2Utils.generate_random_stix_id("relationship"),
                        relationship_type="based-on",
                        created_by_ref=author,
                        source_ref=indicator.id,
                        target_ref=observable.id,
                    )
                )
            # Event threats
            for threat in (
                event_elements["intrusion_sets"]
                + event_elements["malwares"]
                + event_elements["tools"]
            ):
                if indicator is not None:
                    relationships.append(
                        Relationship(
                            id=OpenCTIStix2Utils.generate_random_stix_id(
                                "relationship"
                            ),
                            relationship_type="indicates",
                            created_by_ref=author,
                            source_ref=indicator.id,
                            target_ref=threat.id,
                            description=attribute["comment"],
                            object_marking_refs=attribute_markings,
                            confidence=self.helper.connect_confidence_level,
                        )
                    )
                if observable is not None:
                    relationships.append(
                        Relationship(
                            id=OpenCTIStix2Utils.generate_random_stix_id(
                                "relationship"
                            ),
                            relationship_type="related-to",
                            created_by_ref=author,
                            source_ref=observable.id,
                            target_ref=threat.id,
                            description=attribute["comment"],
                            object_marking_refs=attribute_markings,
                            confidence=self.helper.connect_confidence_level,
                        )
                    )

            # Attribute threats
            for threat in (
                attribute_elements["intrusion_sets"]
                + attribute_elements["malwares"]
                + attribute_elements["tools"]
            ):
                if indicator is not None:
                    relationships.append(
                        Relationship(
                            id=OpenCTIStix2Utils.generate_random_stix_id(
                                "relationship"
                            ),
                            relationship_type="indicates",
                            created_by_ref=author,
                            source_ref=indicator.id,
                            target_ref=threat.id,
                            description=attribute["comment"],
                            object_marking_refs=attribute_markings,
                            confidence=self.helper.connect_confidence_level,
                        )
                    )
                if observable is not None:
                    relationships.append(
                        Relationship(
                            id=OpenCTIStix2Utils.generate_random_stix_id(
                                "relationship"
                            ),
                            relationship_type="related-to",
                            created_by_ref=author,
                            source_ref=observable.id,
                            target_ref=threat.id,
                            description=attribute["comment"],
                            object_marking_refs=attribute_markings,
                            confidence=self.helper.connect_confidence_level,
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
                        id=OpenCTIStix2Utils.generate_random_stix_id("relationship"),
                        relationship_type="uses",
                        created_by_ref=author,
                        source_ref=threat.id,
                        target_ref=attack_pattern.id,
                        description=attribute["comment"],
                        object_marking_refs=attribute_markings,
                        confidence=self.helper.connect_confidence_level,
                    )
                    relationships.append(relationship_uses)
                    if indicator is not None:
                        relationship_indicates = Relationship(
                            id=OpenCTIStix2Utils.generate_random_stix_id(
                                "relationship"
                            ),
                            relationship_type="indicates",
                            created_by_ref=author,
                            source_ref=indicator.id,
                            target_ref=relationship_uses.id,
                            description=attribute["comment"],
                            confidence=self.helper.connect_confidence_level,
                            object_marking_refs=attribute_markings,
                        )
                        relationships.append(relationship_indicates)
                    if observable is not None:
                        relationship_indicates = Relationship(
                            id=OpenCTIStix2Utils.generate_random_stix_id(
                                "relationship"
                            ),
                            relationship_type="related-to",
                            created_by_ref=author,
                            source_ref=observable.id,
                            target_ref=relationship_uses.id,
                            description=attribute["comment"],
                            confidence=self.helper.connect_confidence_level,
                            object_marking_refs=attribute_markings,
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
                        id=OpenCTIStix2Utils.generate_random_stix_id("relationship"),
                        relationship_type="uses",
                        confidence=self.helper.connect_confidence_level,
                        created_by_ref=author,
                        source_ref=threat.id,
                        target_ref=attack_pattern.id,
                        description=attribute["comment"],
                        object_marking_refs=attribute_markings,
                    )
                    relationships.append(relationship_uses)
                    if indicator is not None:
                        relationship_indicates = Relationship(
                            id=OpenCTIStix2Utils.generate_random_stix_id(
                                "relationship"
                            ),
                            relationship_type="indicates",
                            created_by_ref=author,
                            source_ref=indicator.id,
                            target_ref=relationship_uses.id,
                            description=attribute["comment"],
                            confidence=self.helper.connect_confidence_level,
                            object_marking_refs=attribute_markings,
                        )
                        relationships.append(relationship_indicates)
                    if observable is not None:
                        relationship_indicates = Relationship(
                            id=OpenCTIStix2Utils.generate_random_stix_id(
                                "relationship"
                            ),
                            relationship_type="indicates",
                            created_by_ref=author,
                            source_ref=observable.id,
                            target_ref=relationship_uses.id,
                            description=attribute["comment"],
                            confidence=self.helper.connect_confidence_level,
                            object_marking_refs=attribute_markings,
                        )
                        relationships.append(relationship_indicates)
            return {
                "indicator": indicator,
                "observable": observable,
                "relationships": relationships,
                "attribute_elements": attribute_elements,
                "markings": attribute_markings,
                "identities": identities,
                "sightings": sightings,
            }

    def prepare_elements(self, galaxies, tags, author, markings):
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
                                id=OpenCTIStix2Utils.generate_random_stix_id(
                                    "intrusion-set"
                                ),
                                name=name,
                                labels=["intrusion-set"],
                                description=galaxy_entity["description"],
                                created_by_ref=author,
                                object_marking_refs=markings,
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
                                id=OpenCTIStix2Utils.generate_random_stix_id(
                                    "tool"
                                ),
                                name=name,
                                labels=["tool"],
                                description=galaxy_entity["description"],
                                created_by_ref=author,
                                object_marking_refs=markings,
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
                                id=OpenCTIStix2Utils.generate_random_stix_id(
                                    "malware"
                                ),
                                name=name,
                                is_family=True,
                                aliases=aliases,
                                labels=[galaxy["name"]],
                                description=galaxy_entity["description"],
                                created_by_ref=author,
                                object_marking_refs=markings,
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
                                id=OpenCTIStix2Utils.generate_random_stix_id(
                                    "attack-pattern"
                                ),
                                name=name,
                                description=galaxy_entity["description"],
                                created_by_ref=author,
                                object_marking_refs=markings,
                                custom_properties={
                                    "x_mitre_id": galaxy_entity["meta"]["external_id"][
                                        0
                                    ],
                                    "x_opencti_aliases": aliases,
                                },
                            )
                        )
                        added_names.append(name)
        for tag in tags:
            # Get the linked intrusion sets
            if (
                tag["name"].startswith("misp-galaxy:threat-actor")
                or tag["name"].startswith(
                    "misp-galaxy:mitre-mobile-attack-intrusion-set"
                )
                or tag["name"].startswith("misp-galaxy:microsoft-activity-group")
                or tag["name"].startswith("misp-galaxy:mitre-threat-actor")
                or tag["name"].startswith(
                    "misp-galaxy:mitre-enterprise-attack-threat-actor"
                )
                or tag["name"].startswith("misp-galaxy:mitre-intrusion-set")
                or tag["name"].startswith(
                    "misp-galaxy:mitre-enterprise-attack-intrusion-set"
                )
            ):
                tag_value_split = tag["name"].split('="')
                tag_value = tag_value_split[1][:-1].strip()
                if " - G" in tag_value:
                    name = tag_value.split(" - G")[0]
                elif "APT " in tag_value:
                    name = tag_value.replace("APT ", "APT")
                else:
                    name = tag_value
                if name not in added_names:
                    elements["intrusion_sets"].append(
                        IntrusionSet(
                            id=OpenCTIStix2Utils.generate_random_stix_id(
                                "intrusion-set"
                            ),
                            name=name,
                            description="Imported from MISP tag",
                            created_by_ref=author,
                            object_marking_refs=markings,
                        )
                    )
                    added_names.append(name)
            # Get the linked tools
            if tag["name"].startswith("misp-galaxy:mitre-tool") or tag[
                "name"
            ].startswith("misp-galaxy:mitre-enterprise-attack-tool"):
                tag_value_split = tag["name"].split('="')
                tag_value = tag_value_split[1][:-1].strip()
                if " - S" in tag_value:
                    name = tag_value.split(" - S")[0]
                else:
                    name = tag_value
                if name not in added_names:
                    elements["tools"].append(
                        Tool(
                            id=OpenCTIStix2Utils.generate_random_stix_id("tool"),
                            name=name,
                            description="Imported from MISP tag",
                            created_by_ref=author,
                            object_marking_refs=markings,
                        )
                    )
                    added_names.append(name)
            # Get the linked malwares
            if (
                tag["name"].startswith("misp-galaxy:mitre-malware")
                or tag["name"].startswith("misp-galaxy:mitre-enterprise-attack-malware")
                or tag["name"].startswith("misp-galaxy:misp-ransomware")
                or tag["name"].startswith("misp-galaxy:misp-tool")
                or tag["name"].startswith("misp-galaxy:misp-android")
                or tag["name"].startswith("misp-galaxy:misp-malpedia")
            ):
                tag_value_split = tag["name"].split('="')
                tag_value = tag_value_split[1][:-1].strip()
                if " - S" in tag_value:
                    name = tag_value.split(" - S")[0]
                else:
                    name = tag_value
                if name not in added_names:
                    elements["malwares"].append(
                        Malware(
                            id=OpenCTIStix2Utils.generate_random_stix_id("malware"),
                            name=name,
                            description="Imported from MISP tag",
                            created_by_ref=author,
                            object_marking_refs=markings,
                        )
                    )
                    added_names.append(name)
            # Get the linked attack_patterns
            if tag["name"].startswith("mitre-attack:attack-pattern"):
                tag_value_split = tag["name"].split('="')
                tag_value = tag_value_split[1][:-1].strip()
                if " - T" in tag_value:
                    name = tag_value.split(" - T")[0]
                else:
                    name = tag_value
                if name not in added_names:
                    elements["attack_patterns"].append(
                        AttackPattern(
                            id=OpenCTIStix2Utils.generate_random_stix_id(
                                "attack-pattern"
                            ),
                            name=name,
                            description="Imported from MISP tag",
                            created_by_ref=author,
                            object_marking_refs=markings,
                        )
                    )
                    added_names.append(name)
        return elements

    def resolve_type(self, type, value):
        types = {
            "yara": [{"resolver": "yara"}],
            "md5": [{"resolver": "file-md5", "type": "File"}],
            "sha1": [{"resolver": "file-sha1", "type": "File"}],
            "sha256": [{"resolver": "file-sha256", "type": "File"}],
            "filename": [{"resolver": "file-name", "type": "File"}],
            "pdb": [{"resolver": "pdb-path", "type": "File"}],
            "filename|md5": [
                {"resolver": "file-name", "type": "File"},
                {"resolver": "file-md5", "type": "File"},
            ],
            "filename|sha1": [
                {"resolver": "file-name", "type": "File"},
                {"resolver": "file-sha1", "type": "File"},
            ],
            "filename|sha256": [
                {"resolver": "file-name", "type": "File"},
                {"resolver": "file-sha256", "type": "File"},
            ],
            "ip-src": [{"resolver": "ipv4-addr", "type": "IPv4-Addr"}],
            "ip-dst": [{"resolver": "ipv4-addr", "type": "IPv4-Addr"}],
            "hostname": [{"resolver": "hostname", "type": "X-OpenCTI-Hostname"}],
            "domain": [{"resolver": "domain", "type": "Domain-Name"}],
            "domain|ip": [
                {"resolver": "domain", "type": "Domain-Name"},
                {"resolver": "ipv4-addr", "type": "IPv4-Addr"},
            ],
            "email-subject": [{"resolver": "email-subject", "type": "Email-Message"}],
            "email-src": [{"resolver": "email-address", "type": "Email-Addr"}],
            "email-dst": [{"resolver": "email-address", "type": "Email-Addr"}],
            "url": [{"resolver": "url", "type": "Url"}],
            "windows-service-name": [
                {"resolver": "windows-service-name", "type": "Process"}
            ],
            "windows-service-displayname": [
                {"resolver": "windows-service-display-name", "type": "Process"}
            ],
            "windows-scheduled-task": [
                {"resolver": "windows-scheduled-task", "type": "X-OpenCTI-Text"}
            ],
        }
        if type in types:
            resolved_types = types[type]
            if len(resolved_types) == 2:
                values = value.split("|")
                if resolved_types[0]["resolver"] == "ipv4-addr":
                    resolver_0 = self.detect_ip_version(values[0])
                    type_0 = self.detect_ip_version(values[0], True)
                else:
                    resolver_0 = resolved_types[0]["resolver"]
                    type_0 = resolved_types[0]["type"]
                if resolved_types[1]["resolver"] == "ipv4-addr":
                    resolver_1 = self.detect_ip_version(values[1])
                    type_1 = self.detect_ip_version(values[1], True)
                else:
                    resolver_1 = resolved_types[1]["resolver"]
                    type_1 = resolved_types[1]["type"]
                return [
                    {"resolver": resolver_0, "type": type_0, "value": values[0]},
                    {"resolver": resolver_1, "type": type_1, "value": values[1]},
                ]
            else:
                if resolved_types[0] == "ipv4-addr":
                    resolver_0 = self.detect_ip_version(value)
                    type_0 = self.detect_ip_version(value, True)
                else:
                    resolver_0 = resolved_types[0]["resolver"]
                    type_0 = resolved_types[0]["type"]
                return [{"resolver": resolver_0, "type": type_0, "value": value}]

    def detect_ip_version(self, value, type=False):
        if len(value) > 16:
            if type:
                return "IPv6-Addr"
            return "ipv6-addr"
        else:
            if type:
                return "IPv4-Addr"
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
                and not tag["name"].startswith("misp-galaxy:threat-actor")
                and not tag["name"].startswith("misp-galaxy:mitre-threat-actor")
                and not tag["name"].startswith("misp-galaxy:microsoft-activity-group")
                and not tag["name"].startswith(
                    "misp-galaxy:mitre-enterprise-attack-threat-actor"
                )
                and not tag["name"].startswith(
                    "misp-galaxy:mitre-mobile-attack-intrusion-set"
                )
                and not tag["name"].startswith("misp-galaxy:mitre-intrusion-set")
                and not tag["name"].startswith(
                    "misp-galaxy:mitre-enterprise-attack-intrusion-set"
                )
                and not tag["name"].startswith("misp-galaxy:mitre-malware")
                and not tag["name"].startswith(
                    "misp-galaxy:mitre-enterprise-attack-malware"
                )
                and not tag["name"].startswith("misp-galaxy:mitre-attack-pattern")
                and not tag["name"].startswith(
                    "misp-galaxy:mitre-enterprise-attack-attack-pattern"
                )
                and not tag["name"].startswith("misp-galaxy:mitre-tool")
                and not tag["name"].startswith("misp-galaxy:tool")
                and not tag["name"].startswith("misp-galaxy:ransomware")
                and not tag["name"].startswith("misp-galaxy:malpedia")
            ):
                tag_value = tag["name"]
                if '="' in tag["name"]:
                    tag_value_split = tag["name"].split('="')
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
                if '="' in tag_value:
                    tag_value = tag_value.replace('="', "-")[:-1]
                opencti_tags.append(tag_value)
        return opencti_tags


if __name__ == "__main__":
    mispConnector = Misp()
    mispConnector.run()
