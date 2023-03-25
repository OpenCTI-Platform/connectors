import copy
import os
import sys
import time
from datetime import datetime, timezone

import stix2
import yaml
from misp_stix_converter import MISPtoSTIX21Parser as MISPtoSTIX
from pycti import OpenCTIConnectorHelper, get_config_variable
from pymisp import ExpandedPyMISP

FRIENDLY_NAME = "MISP run @ {time}"

FILTER_REPORT = stix2.Filter("type", "=", "report")
FILTER_THREATACTOR = stix2.Filter("type", "=", "threat-actor")
FILTER_INTRUSIONSET = stix2.Filter("type", "=", "intrusion-set")
FILTER_INDICATOR = stix2.Filter("type", "=", "indicator")


class MISP:
    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        self.url = get_config_variable(
            env_var="MISP_URL", yaml_path=["misp", "url"], config=config
        )
        self.key = get_config_variable(
            env_var="MISP_KEY", yaml_path=["misp", "key"], config=config
        )
        self.ssl_verify = get_config_variable(
            env_var="MISP_SSL_VERIFY", yaml_path=["misp", "ssl_verify"], config=config
        )

        self.default_indicators_score = get_config_variable(
            env_var="MISP_DEFAULT_INDICATORS_SCORE",
            yaml_path=["misp", "default_indicators_score"],
            config=config,
            isNumber=True,
        )

        self.create_reports = get_config_variable(
            env_var="MISP_CREATE_REPORTS",
            yaml_path=["misp", "create_reports"],
            config=config,
        )

        interval = get_config_variable(
            env_var="MISP_INTERVAL",
            yaml_path=["misp", "interval"],
            config=config,
            isNumber=True,
        )
        self.interval = interval * 60

        self.import_attributes_with_warnings = get_config_variable(
            env_var="MISP_IMPORT_ATTRIBUTES_WITH_WARNINGS",
            yaml_path=["misp", "import_attributes_with_warnings"],
            config=config,
        )

        self.update_existing_data = get_config_variable(
            env_var="CONNECTOR_UPDATE_EXISTING_DATA",
            yaml_path=["connector", "update_existing_data"],
            config=config,
        )

        self.convert_threatactor_to_intrusionset = get_config_variable(
            env_var="MISP_CONVERT_THREATACTOR_TO_INTRUSIONSET",
            yaml_path=["misp", "convert_threatactor_to_intrusionset"],
            config=config,
            default=True,
        )

        self.import_keyword = get_config_variable(
            env_var="MISP_IMPORT_KEYWORD",
            yaml_path=["misp", "import_keyword"],
            config=config,
        )

        self.create_observables = get_config_variable(
            env_var="MISP_CREATE_OBSERVABLES",
            yaml_path=["misp", "create_observables"],
            config=config,
        )

        self.datetime_attribute = get_config_variable(
            env_var="MISP_DATETIME_ATTRIBUTE",
            yaml_path=["misp", "datetime_attribute"],
            config=config,
            default="timestamp",
        )

        report_description_filter = get_config_variable(
            env_var="MISP_REPORT_DESCRIPTION_FILTER",
            yaml_path=["misp", "report_description_filter"],
            config=config,
            # Example: "type=comment,category=Internal reference"
        )
        self.description_filter = parse_description_filter_config(
            report_description_filter
        )

        self.report_type = get_config_variable(
            env_var="MISP_REPORT_TYPE",
            yaml_path=["misp", "report_type"],
            config=config,
            default="misp-event",
        )

        import_tags = get_config_variable(
            env_var="MISP_IMPORT_TAGS",
            yaml_path=["misp", "import_tags"],
            config=config,
            default="",
        )
        self.import_tags = [tag.strip() for tag in import_tags.split(",")]

        import_tags_not = get_config_variable(
            env_var="MISP_IMPORT_TAGS_NOT",
            yaml_path=["misp", "import_tags_not"],
            config=config,
            default="",
        )
        self.import_tags_not = [tag.strip() for tag in import_tags_not.split(",")]

        import_with_attachments = get_config_variable(
            env_var="MISP_IMPORT_WITH_ATTACHMENTS",
            yaml_path=["misp", "import_with_attachments"],
            config=config,
            default=True,
        )
        self.import_with_attachments = bool(import_with_attachments)

        reference_url = get_config_variable(
            env_var="MISP_REFERENCE_URL",
            yaml_path=["misp", "reference_url"],
            config=config,
            default=self.url,
        )
        self.reference_url = f"{reference_url}/events/view/"

        import_from_date = get_config_variable(
            env_var="MISP_IMPORT_FROM_DATE",
            yaml_path=["misp", "import_from_date"],
            config=config,
        )
        if import_from_date:
            self.import_from_date = Timestamp.from_iso(import_from_date)
        else:
            self.import_from_date = None

        self.import_only_published = get_config_variable(
            env_var="MISP_IMPORT_ONLY_PUBLISHED",
            yaml_path=["misp", "import_only_published"],
            config=config,
        )
        import_creator_orgs = get_config_variable(
            env_var="MISP_IMPORT_CREATOR_ORGS",
            yaml_path=["misp", "import_creator_orgs"],
            config=config,
        )
        self.import_creator_orgs = split_by_comma(import_creator_orgs)

        import_creator_orgs_not = get_config_variable(
            env_var="MISP_IMPORT_CREATOR_ORGS_NOT",
            yaml_path=["misp", "import_creator_orgs_not"],
            config=config,
        )
        self.import_creator_orgs_not = split_by_comma(import_creator_orgs_not)

        import_owner_orgs = get_config_variable(
            env_var="MISP_IMPORT_OWNER_ORGS",
            yaml_path=["misp", "import_owner_orgs"],
            config=config,
        )
        self.import_owner_orgs = split_by_comma(import_owner_orgs)

        import_owner_orgs_not = get_config_variable(
            env_var="MISP_IMPORT_OWNER_ORGS_NOT",
            yaml_path=["misp", "import_owner_orgs_not"],
            config=config,
        )
        self.import_owner_orgs_not = split_by_comma(import_owner_orgs_not)

        import_distribution_levels = get_config_variable(
            env_var="MISP_IMPORT_DISTRIBUTION_LEVELS",
            yaml_path=["misp", "import_distribution_levels"],
            config=config,
        )
        self.import_distribution_levels = split_by_comma(import_distribution_levels)

        import_threat_levels = get_config_variable(
            env_var="MISP_IMPORT_THREAT_LEVELS",
            yaml_path=["misp", "import_threat_levels"],
            config=config,
        )
        self.import_threat_levels = split_by_comma(import_threat_levels)

        self.misp = ExpandedPyMISP(
            url=self.url, key=self.key, ssl=self.ssl_verify, debug=False
        )

    def run(self):

        while True:

            now = Timestamp.now()
            message = FRIENDLY_NAME.format(time=now.iso_format)

            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, message
            )

            current_state = {}
            if current_state:
                current_state = self.helper.get_state()

            last_run_raw = current_state.get("last_run")

            if last_run_raw:
                last_run = Timestamp.from_iso(last_run_raw)
                self.helper.log_info(f"Connector last run: {last_run.iso_format}")
            else:
                last_run = Timestamp.from_unix(0)
                self.helper.log_info("Connector has never run.")

            if (
                self.import_from_date
                and self.import_from_date.unix_format > last_run.unix_format
            ):
                last_run = self.import_from_date
                self.helper.log_info(
                    "Collection of event will be restricted to only "
                    f"import events from {last_run.iso_format}."
                )

            kwargs = {
                "tags": self.misp.build_complex_query(
                    or_parameters=self.import_tags,
                    not_parameters=self.import_tags_not,
                ),
                "with_attachments": self.import_with_attachments,
                self.datetime_attribute: last_run.unix_format,
                "limit": 5,
                "includeWarninglistHits": 1,
            }

            if self.import_keyword:
                kwargs.update({"value": self.import_keyword, "searchall": True})

            current_page = current_state.get("current_page", 1)

            while True:

                kwargs["page"] = current_page

                self.helper.log_info("Fetching MISP events.")

                try:
                    events = self.misp.search(**kwargs)

                    if isinstance(events, dict) and "errors" in events:
                        raise ValueError(events["message"])

                except Exception as e:
                    self.helper.log_error(f"Error fetching misp event: {e}")
                    break

                self.helper.log_info(f"MISP returned {len(events)} events.")

                if len(events) == 0:
                    break

                for event in events:
                    self.process_event(event, work_id)

                current_page += 1
                current_state["current_page"] = current_page

                self.helper.set_state(current_state)

            self.helper.set_state({"last_run": now.iso_format, "current_page": None})

            message = f"Connector successfully, state (last_run={now.iso_format})"

            self.helper.log_info(message)

            self.helper.api.work.to_processed(work_id, message)

            if self.helper.connect_run_and_terminate:
                self.helper.log_info("Connector stop")
                sys.exit(0)

            time.sleep(self.interval)

    def is_valid_to_process(self, event):
        _event = event["Event"]
        event_id = _event["uuid"]
        org_owner = _event["Org"]["name"]
        org_creator = _event["Orgc"]["name"]
        distribution_level = _event["distribution"]
        threat_level = _event["threat_level_id"]
        published = _event["published"]

        if self.import_creator_orgs and org_creator not in self.import_creator_orgs:
            self.helper.log_info(f"Skipping {event_id} due organization creator")
            return False

        if self.import_creator_orgs_not and org_creator in self.import_creator_orgs_not:
            self.helper.log_info(f"Skipping {event_id} due organization creator")
            return False

        if self.import_owner_orgs and org_owner not in self.import_owner_orgs:
            self.helper.log_info(f"Skipping {event_id} due organization owner")
            return False

        if self.import_owner_orgs_not and org_owner in self.import_owner_orgs_not:
            self.helper.log_info(f"Skipping {event_id} due organization owner")
            return False

        if (
            self.import_distribution_levels
            and distribution_level not in self.import_distribution_levels
        ):
            self.helper.log_info(f"Skipping {event_id} due distribution level")
            return False

        if self.import_threat_levels and threat_level not in self.import_threat_levels:
            self.helper.log_info(f"Skipping {event_id} due threat level")
            return False

        if self.import_only_published and not published:
            self.helper.log_info(f"Skipping {event_id} due published only")
            return False

        return True

    def process_event(self, event, work_id):
        env = stix2.Environment(store=stix2.MemoryStore())
        if not self.is_valid_to_process(event):
            return

        event_id = event["Event"]["uuid"]

        self.helper.log_info(f"Processing {event_id} ...")

        if not self.import_attributes_with_warnings:
            self.remove_attributes_flagged_with_warnings(event)

        data = dict(
            attachments=[],
            references=[],
            note={},
            sectors=[],
            description="",
            report_objects=[],
        )

        # IMPORTANT: needs to be executed before MISPtoSTIX
        data = self.collect_specific_attributes(event, data)

        parser = MISPtoSTIX()
        parser.parse_misp_event(event)

        env.add(parser.stix_objects)

        self.report = env.query(FILTER_REPORT)[0]
        self.identity = env.get(self.report.created_by_ref)
        self.confidence = self.helper.connect_confidence_level

        if self.convert_threatactor_to_intrusionset:
            self.transform_threatactor_to_intrusionset(env, data)

        if self.create_observables:
            self.create_observables_from_indicators(event, env, data)

        self.create_note(env, data)
        self.update_report(env, event, data)
        self.apply_markings(env)

        if self.default_indicators_score:
            self.set_default_indicators_score(env)

        self.create_relationship(env)

        if not self.create_reports:
            self.remove_report(env)

        bundle = stix2.Bundle(objects=env.query(), allow_custom=True).serialize()

        self.helper.send_stix2_bundle(
            bundle=bundle, work_id=work_id, update=self.update_existing_data
        )

        return None

    def set_default_indicators_score(self, env):
        for indicator in env.query(FILTER_INDICATOR):
            if "x_opencti_score" not in indicator:
                env.add(
                    indicator.new_version(
                        custom_properties={
                            "x_opencti_score": self.default_indicators_score,
                        }
                    )
                )

    def create_observables_from_indicators(self, event, env, data):
        _event = copy.deepcopy(event)

        for attribute in _event["Event"]["Attribute"]:
            attribute["to_ids"] = False

        for obj in _event["Event"]["Object"]:
            for attribute in obj["Attribute"]:
                attribute["to_ids"] = False

        parser = MISPtoSTIX()
        parser.parse_misp_event(_event)

        for item in parser.stix_objects:
            if stix2.utils.is_sco(item):
                env.add(item)
                data["report_objects"].append(item["id"])

    def create_relationship(self, env):
        intrusionsets = []
        for intrusionset in env.query(FILTER_INTRUSIONSET):
            intrusionsets.append(intrusionset)

        mapping = {
            "location": {
                "relationship": "targets",
                "direction": "to"
            },
            "attack-pattern": {
                "relationship": "uses",
                "direction": "to"
            },
            "identity": {
                "relationship": "targets",
                "direction": "to"
            },
            "indicator": {
                "relationship": "indicates",
                "direction": "from"
            },
            "malware": {
                "relationship": "uses",
                "direction": "to"
            },
            "tool": {
                "relationship": "uses",
                "direction": "to"
            },
            "vulnerability": {
                "relationship": "targets",
                "direction": "to"
            }
        }

        for item in env.query():

            if item.type not in mapping.keys():
                continue

            relationship = mapping[item.type]["relationship"]
            direction = mapping[item.type]["direction"]

            for intrusionset in intrusionsets:
                source = intrusionset if direction == "to" else item
                destination = item if direction == "to" else intrusionset

                env.add(
                    stix2.Relationship(
                        relationship_type=relationship,
                        source_ref=source.id,
                        target_ref=destination.id,
                        created_by_ref=self.identity.id,
                        allow_custom=True,
                    )
                )

    def remove_report(self, env):
        datasource = env.source.data_sources[0]._data
        del datasource[self.report.id]

    def remove_attributes_flagged_with_warnings(self, event):
        attributes = []
        for attribute in event["Event"]["Attribute"]:
            if "warnings" not in attribute:
                attributes.append(attribute)

        event["Event"]["Attribute"] = attributes

    def get_references(self, attributes):
        references = []
        for attribute in attributes:
            references.append(
                stix2.ExternalReference(
                    source_name=attribute["category"],
                    external_id=attribute["uuid"],
                    url=attribute["value"],
                )
            )
        return references

    def get_attachments(self, attributes):
        attachments = []

        for attribute in attributes:
            filename = attribute["value"]
            extension = filename.split(".")[-1].lower()

            if extension != "pdf":
                continue

            data = attribute.get("data")

            if data:
                attachments.append(
                    {
                        "name": filename,
                        "data": data,
                        "mime_type": "application/pdf",
                    }
                )

        return attachments

    def transform_threatactor_to_intrusionset(self, env, data):
        intrusionset_keys = stix2.IntrusionSet._properties.keys()
        datasource = env.source.data_sources[0]._data

        for threatactor in env.query(FILTER_THREATACTOR):
            properties = {}

            for key in dict(threatactor):

                if key in ["id", "type"]:
                    continue

                if key.startswith("x_"):
                    _key = key
                    _key = _key.replace("_cfr_", "")
                    _key = _key.replace("x_misp", "")
                    _key = _key.replace("_", " ")
                    _key = _key.strip().title()

                    value = threatactor[key]
                    if type(value) != list:
                        value = [value]

                    if _key in data["note"]:
                        data["note"][_key] += value
                    else:
                        data["note"][_key] = value

                if key in intrusionset_keys:
                    properties[key] = threatactor[key]

            intrusionset = stix2.IntrusionSet(
                **properties, custom_properties=properties, allow_custom=True
            )

            env.add(intrusionset)
            datasource[threatactor.id]

            self.report.object_refs.append(intrusionset.id)
            self.report.object_refs.remove(threatactor.id)

    def apply_markings(self, env):
        datasource = env.source.data_sources[0]._data

        for stix_object in env.query():
            if "object_marking_refs" not in stix_object._properties:
                continue

            if stix_object.type == "indicator":
                env.add(
                    stix_object.new_version(
                        object_marking_refs=self.report.object_marking_refs
                    )
                )

            if stix2.utils.is_sco(stix_object):
                stix_object._inner.update(
                    {"object_marking_refs": self.report.object_marking_refs}
                )
                datasource[stix_object.id] = stix_object

    def update_report(self, env, event, data):
        attachments = self.get_attachments(data["attachments"])
        references = self.get_references(data["references"])
        object_refs = self.report.object_refs + data["report_objects"]

        references.append(
            stix2.ExternalReference(
                source_name="MISP Event",
                external_id=event["Event"]["id"],
                url=f"{self.reference_url}{event['Event']['id']}",
            )
        )

        references = self.report.get("external_references", []) + references

        report = self.report.new_version(
            description=data["description"],
            report_types=self.report_type,
            external_references=references,
            object_refs=object_refs,
            custom_properties={"x_opencti_files": attachments},
            confidence=self.confidence,
        )
        env.add(report)

    def create_note(self, env, data):
        text = ""

        for title, value in data["note"].items():
            _value = set(value)
            _value = "* " + "\n* ".join(_value)
            text += f"\n##### {title}\n{_value}"

        env.add(
            stix2.Note(
                abstract="Analysis",
                content=text,
                confidence=self.confidence,
                created_by_ref=self.identity.id,
                object_refs=[self.report],
                object_marking_refs=self.report.get("object_marking_refs", []),
                note_types=["external", "analysis"],
                allow_custom=True,
            )
        )

    def has_description(self, attribute):
        for key, value in self.description_filter.items():
            if attribute.get(key, "") != value:
                return False
        else:
            return True

    def collect_specific_attributes(self, event, data):
        attributes = event["Event"]["Attribute"]

        clean_attributes = []

        for attribute in attributes:

            if (
                attribute["category"] == "External analysis"
                and attribute["type"] == "attachment"
            ):
                data["attachments"].append(attribute)

            elif (
                attribute["category"] == "External analysis"
                and attribute["type"] == "link"
            ):
                data["references"].append(attribute)

            elif (
                attribute["category"] == "External analysis"
                and attribute["type"] == "text"
            ):
                data["note"]["Analysis"] = [attribute["value"]]

            elif self.has_description(attribute):
                data["description"] = attribute["value"]

            else:
                clean_attributes.append(attribute)

        event["Event"]["Attribute"] = clean_attributes

        return data


class Timestamp:
    def __init__(self, value):
        if type(value) == datetime:
            self._value = value.replace(microsecond=0)
        else:
            raise TypeError("Value must be a datetime object")

    @classmethod
    def from_iso(cls, iso):
        return cls(datetime.fromisoformat(iso).replace(tzinfo=timezone.utc))

    @classmethod
    def from_unix(cls, unix):
        return cls(datetime.fromtimestamp(int(unix), timezone.utc))

    @classmethod
    def now(cls):
        return cls(datetime.now(timezone.utc))

    @property
    def iso_format(self):
        return self._value.astimezone(timezone.utc).isoformat()

    @property
    def unix_format(self):
        return int(self._value.timestamp())

    @property
    def value(self):
        return self._value

    def __str__(self):
        return str(self._value)


def parse_description_filter_config(config):
    filters = dict()

    if not config:
        return filters

    for item in config.split(","):
        key, value = item.split(":")
        filters[key] = value

    return filters


def split_by_comma(value):
    if not value:
        return []

    value = value.strip()

    if value == "":
        return []

    return value.split(",")
