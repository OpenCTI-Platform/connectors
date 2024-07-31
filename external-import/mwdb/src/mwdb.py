import calendar
import os
import random
import re
import sys
import time
from datetime import datetime
from typing import Any, Dict, Mapping, Optional

import mwdblib
import stix2
import yaml
from dateutil import parser
from dateutil.relativedelta import relativedelta
from pycti import Malware, OpenCTIConnectorHelper, get_config_variable
from stix2 import URL, Bundle, File, IPv4Address, Relationship
from stix2.v21.vocab import HASHING_ALGORITHM_SHA_256

__version__ = "6.2.9"
BANNER = f"""

 ██████   ██████ █████   ███   █████ ██████████   ███████████
░░██████ ██████ ░░███   ░███  ░░███ ░░███░░░░███ ░░███░░░░░███
 ░███░█████░███  ░███   ░███   ░███  ░███   ░░███ ░███    ░███
 ░███░░███ ░███  ░███   ░███   ░███  ░███    ░███ ░██████████
 ░███ ░░░  ░███  ░░███  █████  ███   ░███    ░███ ░███░░░░░███
 ░███      ░███   ░░░█████░█████░    ░███    ███  ░███    ░███
 █████     █████    ░░███ ░░███      ██████████   ███████████
░░░░░     ░░░░░      ░░░   ░░░      ░░░░░░░░░░   ░░░░░░░░░░░
\n
\n
                              MWDB Connector, version {__version__}
"""


class MWDB:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        self.helper = OpenCTIConnectorHelper(config)

        self.mwdb_url = get_config_variable("MWDB_URL", ["mwdb", "url"], config)

        self.mwdb_interval = get_config_variable(
            "MWDB_INTERVAL", ["mwdb", "interval"], config, True
        )

        self.create_indicators = get_config_variable(
            "MWDB_CREATE_INDICATORS",
            ["mwdb", "create_indicators"],
            config,
            False,
            True,
        )

        self.verify_ssl = get_config_variable(
            "MWDB_SSL_VERIFY",
            ["mwdb", "ssl_verify"],
            config,
            False,
            True,
        )

        self.create_observables = get_config_variable(
            "MWDB_CREATE_OBSERVABLES",
            ["mwdb", "create_observables"],
            config,
            False,
            True,
        )

        self.update_existing_data = get_config_variable(
            "MWDB_UPDATE_EXISTING_DATA",
            ["mwdb", "update_existing_data"],
            config,
            False,
            True,
        )

        self.mwdb_token = get_config_variable("MWDB_TOKEN", ["mwdb", "token"], config)

        self.mwdb = mwdblib.MWDB(
            api_url=self.mwdb_url,
            api_key=self.mwdb_token,
            verify_ssl=self.verify_ssl,
            config_path=None,  # Don't use ~/.mwdb configuration
        )

        self.import_config = get_config_variable(
            "MWDB_IMPORT_CONFIG", ["mwdb", "import_config"], config, False, False
        )

        self.org_name = get_config_variable(
            "MWDB_ORG_NAME", ["mwdb", "org_name"], config, False, False
        )

        self.org_description = get_config_variable(
            "MWDB_ORG_DESCRIPTION", ["mwdb", "org_description"], config, False, False
        )

        self.tag_filter = get_config_variable(
            "MWDB_TAG_FILTER", ["mwdb", "tag_filter"], config, False, False
        )

        self.score = get_config_variable(
            "MWDB_CONFIDENCE_LEVEL", ["mwdb", "confidence_level"], config, True, 50
        )

        self.max_start_retention = get_config_variable(
            "MWDB_MAX_START_RETENTION", ["mwdb", "max_start_retention"], config, True, 6
        )

        ## Verify setting of the starting date in the config
        ## ELSE retrieve le last month.
        self.start_date = get_config_variable(
            "MWDB_START_DATE", ["mwdb", "start_date"], config, None
        )
        if not self.start_date or not re.match(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z",
            self.start_date,
        ):
            last6month = datetime.now() - relativedelta(months=self.max_start_retention)
            self.start_date = last6month.isoformat()

        ## CHECK IF IT'S IN ISO FORMAT
        self.identity = self.helper.api.identity.create(
            type="Organization", name=self.org_name, description=self.org_description
        )
        self.workid = None

    @staticmethod
    def _current_unix_timestamp() -> int:
        return int(time.time())

    def _load_state(self) -> Dict[str, Any]:
        current_state = self.helper.get_state()
        if not current_state:
            return {}
        return current_state

    @staticmethod
    def _get_state_value(
        state: Optional[Mapping[str, Any]], key: str, default: Optional[Any] = None
    ) -> Any:
        if state is not None:
            return state.get(key, default)
        return default

    def _is_scheduled(self, last_run: Optional[int], current_time: int) -> bool:
        if last_run is None:
            self._info("Connector first run")
            return True
        time_diff = current_time - last_run
        return time_diff >= self._get_interval()

    def _info(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_info(fmt_msg)

    def _error(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_error(fmt_msg)

    def get_interval(self):
        return int(self.mwdb_interval) * 60 * 60 * 24

    def next_run(self, seconds):
        return

    def process_c2(self, value, virus, configtype):
        objects = []
        tags = []
        port = ""
        indicatorc2 = None
        observablec2 = None
        if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d{1,5})?", value):
            port = None
            if ":" in value:
                port = value.split(":")[1]
                value = value.split(":")[0]

        external_reference = self.helper.api.external_reference.create(
            source_name=self.org_name + " url ref",
            url=self.mwdb_url + "config/" + virus["malware"]["sha256"],
        )

        if configtype == "c2-ip":
            description = "C2 IP Address: " + value
            if port:
                description = description + " Port: " + port
            pattern = "[ipv4-addr:value = '" + value + "']"
            relation_description = "Malware communicates with C2"
            tags = ["C2"]
        elif configtype == "c2-url-ref":
            description = "C2 URL containing a list of possible references"
            pattern = "[url:value = '" + value + "']"
            relation_description = "Malware communicates with this url"
            tags = ["C2 LIST"]
        else:
            description = "C2 - URL" + value
            pattern = "[url:value = '" + value + "']"
            relation_description = "Malware communicates with C2"
            tags = ["C2"]

        if str(self.create_indicators).capitalize() == "True":
            indicatorc2 = stix2.Indicator(
                name=value,
                description=description,
                # confidence=self.helper.connect_confidence_level,
                pattern_type="stix2",
                pattern=pattern,
                valid_from=parser.parse(virus["malware"]["upload_time"]),
                labels=[x for x in virus["mal_tag"]["yara"] if x],
                created_by_ref=self.identity["standard_id"],
                object_marking_refs=[stix2.TLP_GREEN["id"]],
                external_references=[external_reference],
                created=parser.parse(virus["malware"]["upload_time"]),
                modified=parser.parse(virus["malware"]["upload_time"]),
                custom_properties={
                    "x_opencti_score": self.score,
                },
            )
            objects.append(indicatorc2)

        if str(self.create_observables).capitalize() == "True":
            custom_properties = {
                "description": description,
                "x_opencti_score": self.score,
                "labels": tags,
                "created_by_ref": self.identity["standard_id"],
                "external_references": [external_reference],
            }

            if configtype == "c2-ip":
                observablec2 = IPv4Address(
                    value=value,
                    custom_properties=custom_properties,
                    object_marking_refs=[stix2.TLP_GREEN["id"]],
                )
            else:
                observablec2 = URL(
                    name=value,
                    custom_properties=custom_properties,
                    object_marking_refs=[stix2.TLP_GREEN["id"]],
                )
            objects.append(observablec2)

        if indicatorc2 and observablec2:
            relationc2 = Relationship(
                source_ref=indicatorc2["id"],
                target_ref=observablec2["id"],
                relationship_type="related-to",
                description=relation_description,
                created_by_ref=self.identity["standard_id"],
                confidence=self.score,
            )

            objects.append(relationc2)

        if virus["indicator"] and indicatorc2:
            relationc2c = Relationship(
                source_ref=virus["indicator"]["id"],
                target_ref=indicatorc2["id"],
                relationship_type="related-to",
                created_by_ref=self.identity["standard_id"],
                description=relation_description,
                confidence=self.score,
            )
            objects.append(relationc2c)

        if virus["observable"] and observablec2:
            relation2c2 = Relationship(
                source_ref=virus["observable"]["id"],
                target_ref=virus["observable"]["id"],
                relationship_type="related-to",
                created_by_ref=self.identity["standard_id"],
                description=relation_description,
                confidence=self.score,
            )
            objects.append(relation2c2)
        return objects

    ## A function to process malware config data
    def process_config(self, config, virus):
        c2obj = []
        if "c2" in config.cfg:
            for c2 in config.cfg["c2"]:
                if re.match("^https?://.*", c2):
                    c2obj.extend(self.process_c2(c2, virus, "c2-url"))
                if re.match(
                    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d{1,5})?",
                    c2,
                ):
                    c2obj.extend(self.process_c2(c2, virus, "c2-ip"))

        if "attr" in config.cfg:
            if "url4cnc" in config.cfg["attr"].keys():
                for url in config.cfg["attr"]["url4cnc"]:
                    if re.match("^https?://.*", url):
                        c2obj.extend(self.process_c2(url, virus, "c2-url-ref"))

        return c2obj

    ## A function to process malware tags using a CERT.PL taxonomies
    def process_tags(self, tags) -> Mapping:
        attributes = {"yara": [], "family": [], "runnable": [], "extra": []}
        for tag in tags:
            if "yara" in tag:
                color = "%06x" % random.randint(0, 0xFFFFFF)
                self.helper.api.label.read_or_create_unchecked(
                    value=tag.split(":")[1], color=color
                )
                attributes["yara"].append(tag.split(":")[1])
            elif "family" in tag:
                attributes["family"].append(tag.split(":")[1])
            elif "runnable" in tag:
                attributes["runnable"].append(tag.split(":")[1])
            else:
                attributes["extra"].append(tag)
        return attributes

    def process_extratag(self, attributes_extra, sample):
        relatsions = []
        for taglabel in attributes_extra:
            if self.tag_filter:
                if re.match(self.tag_filter, taglabel.lower()):
                    continue

            if re.match("CVE-", taglabel.upper()):
                # create a CVE and continue
                cve = self.helper.api.vulnerability.read(
                    filters={
                        "mode": "and",
                        "filters": [{"key": "name", "values": [taglabel.upper()]}],
                        "filterGroups": [],
                    }
                )
                relationship = Relationship(
                    source_ref=sample["observable"]["id"],
                    target_ref=cve["id"],
                    relationship_type="related-to",
                    created_by_ref=self.identity["standard_id"],
                )
                relatsions.append(relationship)

            ## first search in unstructured tag malware
            fullsearch = self.helper.api.malware.read(
                filters={
                    "mode": "and",
                    "filters": [{"key": "name", "values": [taglabel.lower().strip()]}],
                    "filterGroups": [],
                }
            )
            if fullsearch:
                for malwsearc in fullsearch:
                    if (
                        malwsearc["name"].lower().strip()
                        == taglabel.lower().strip().replace(" ", "")
                        or malwsearc["name"].lower().strip() == taglabel.lower()
                    ):
                        ### create relation and continue indicates
                        relationship = Relationship(
                            source_ref=sample["observable"]["id"],
                            target_ref=malwsearc["id"],
                            relationship_type="related-to",
                            created_by_ref=self.identity["standard_id"],
                        )
                        relatsions.append(relationship)

            ## second search for intrusion set like APT
            fullsearch = self.helper.api.intrusion_set.read(
                filters={
                    "mode": "and",
                    "filters": [{"key": "name", "values": [taglabel.lower().strip()]}],
                    "filterGroups": [],
                }
            )
            if fullsearch:
                for intrusion in fullsearch:
                    if intrusion[
                        "name"
                    ].lower().strip() == taglabel.lower().strip() or intrusion[
                        "name"
                    ].lower().strip() == taglabel.lower().strip().replace(
                        " ", ""
                    ):
                        relationship = Relationship(
                            source_ref=sample["observable"]["id"],
                            target_ref=intrusion["id"],
                            relationship_type="related-to",
                            created_by_ref=self.identity["standard_id"],
                        )
                        relatsions.append(relationship)
                        ### create relation and continue related-to
        return relatsions

    def process_virus(self, malware):
        bundle_objects = []
        virus = {
            "mal_tag": None,
            "malware_entity": None,
            "indicator": None,
            "observable": None,
            "malware": malware.data,
        }
        external_reference = self.helper.api.external_reference.create(
            source_name=self.org_name + " url ref",
            url=self.mwdb_url + "file/" + malware.sha256,
        )

        virus["mal_tag"] = self.process_tags(malware.tags)

        if virus["mal_tag"] and len(virus["mal_tag"]["family"]) > 0:
            malware_id = Malware.generate_id(
                str(virus["mal_tag"]["family"][0]).capitalize()
            )
            # virus["malware_entity"] = Malware(id=malware_id, name=str(virus["mal_tag"]["family"][0]).capitalize(), created_by_ref=self.identity["standard_id"], is_family=True, allow_custom=True)
            virus["malware_entity"] = stix2.Malware(
                id=malware_id,
                name=str(virus["mal_tag"]["family"][0]).capitalize(),
                created_by_ref=self.identity["standard_id"],
                is_family=True,
                allow_custom=True,
            )
            bundle_objects.append(virus["malware_entity"])

        if virus["mal_tag"] and len(virus["mal_tag"]["family"]) > 0:
            description = (
                "A " + str(virus["mal_tag"]["family"][0]).capitalize() + " sample"
            )
        else:
            description = "A potential harming artifact"

        if str(self.create_indicators).capitalize() == "True":
            pattern = "[file:hashes.sha256 = '" + malware.sha256 + "']"

            if str(self.create_indicators).capitalize() == "True":
                virus["indicator"] = stix2.Indicator(
                    name=str(malware.file_name).replace("-" + malware.sha256, ""),
                    description=description,
                    confidence=self.helper.connect_confidence_level,
                    pattern_type="stix2",
                    pattern=pattern,
                    valid_from=malware.upload_time,
                    labels=[x for x in virus["mal_tag"]["yara"] if x],
                    created_by_ref=self.identity["standard_id"],
                    object_marking_refs=[stix2.TLP_GREEN["id"]],
                    external_references=[external_reference],
                    created=malware.upload_time,
                    modified=malware.upload_time,
                    custom_properties={
                        "x_opencti_score": self.score,
                    },
                )

                bundle_objects.append(virus["indicator"])

            if str(self.create_observables).capitalize() == "True":
                custom_properties = {
                    "description": description,
                    "x_opencti_score": self.score,
                    "labels": [x for x in virus["mal_tag"]["yara"] if x],
                    "created_by_ref": self.identity["standard_id"],
                    "external_references": [external_reference],
                    "hashes": {HASHING_ALGORITHM_SHA_256: malware.sha256},
                }
                virus["observable"] = File(
                    name=malware.sha256,
                    custom_properties=custom_properties,
                    object_marking_refs=[stix2.TLP_GREEN["id"]],
                )
                bundle_objects.append(virus["observable"])

            if virus["observable"] and virus["indicator"]:
                relationship = Relationship(
                    source_ref=virus["indicator"]["id"],
                    target_ref=virus["observable"]["id"],
                    relationship_type="based-on",
                    created_by_ref=self.identity["standard_id"],
                )
                bundle_objects.append(relationship)

            if (
                virus["indicator"]
                and virus["malware_entity"]
                and len(virus["mal_tag"]["family"]) > 0
            ):
                relationshipmal = Relationship(
                    source_ref=virus["indicator"]["id"],
                    target_ref=virus["malware_entity"]["id"],
                    description="An hash associatated with a malware "
                    + str(virus["mal_tag"]["family"][0]).capitalize(),
                    relationship_type="based-on",
                    created_by_ref=self.identity["standard_id"],
                    confidence=self.score,
                )
                bundle_objects.append(relationshipmal)

            if str(self.import_config).capitalize() == "True":
                ## PROCESSING CONFIG
                if malware.config and self.import_config:
                    bundle_objects.extend(self.process_config(malware.config, virus))

            if (
                len(virus["mal_tag"]["extra"]) > 0
                and str(self.create_observables).capitalize() == "True"
            ):
                extra_tag = self.process_extratag(virus["mal_tag"]["extra"], virus)
                if extra_tag:
                    for relationextra in extra_tag:
                        if relationextra:
                            bundle_objects.append(relationextra)

            updateopencti = str(self.update_existing_data).capitalize() == "True"
            bundle = Bundle(objects=bundle_objects, allow_custom=True).serialize()
            self.helper.send_stix2_bundle(
                bundle,
                update=updateopencti,
                work_id=self.workid,
            )

    def start_up(self):
        while True:
            try:
                timestamp = int(time.time())
                now = datetime.utcfromtimestamp(timestamp)
                friendly_name = "MWDB DEV run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                self.workid = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                current_state = self.helper.get_state()
                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    self.helper.log_info(
                        "Connector last run: "
                        + datetime.utcfromtimestamp(last_run).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )
                else:
                    last_run = None
                    self.helper.log_info("Connector has never run")

                conf_startdate = calendar.timegm(
                    parser.parse(self.start_date).utctimetuple()
                )
                if last_run is None or (
                    (timestamp - last_run) > ((int(self.mwdb_interval)) * 60 * 60 * 24)
                ):
                    self.helper.log_info("MWDB importing")
                    if not last_run or last_run < conf_startdate:
                        current_date = conf_startdate
                    else:
                        current_date = last_run

                    querysearch = "upload_time:[{date} TO *]".format(
                        date=datetime.fromtimestamp(current_date).strftime("%Y-%m-%d")
                    )
                    try:
                        malware_files = self.mwdb.search_files(
                            querysearch, chunk_size=100
                        )
                        for malware_file in malware_files:
                            self.process_virus(malware_file)
                        date = datetime.utcnow()
                        utc_time = calendar.timegm(date.utctimetuple())
                        state = {"last_run": utc_time}
                        self.helper.set_state(state)
                    except Exception as e:
                        self.helper.log_error(str(e))
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                sys.exit(0)
            except Exception as e:
                self.helper.log_error(str(e))

            if self.helper.connect_run_and_terminate:
                self.helper.log_info("Connector stop")
                self.helper.force_ping()
                sys.exit(0)
            time.sleep(60)

    def run(self):
        self.helper.log_info("Fetching MWDB dataset...")
        color = "%06x" % random.randint(0, 0xFFFFFF)
        self.helper.api.label.read_or_create_unchecked(value="C2", color=color)
        color = "%06x" % random.randint(0, 0xFFFFFF)
        self.helper.api.label.read_or_create_unchecked(value="C2 LIST", color=color)
        self.start_up()
        exit(0)


if __name__ == "__main__":
    try:
        print(BANNER)
        MWDBConnector = MWDB()
        MWDBConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
