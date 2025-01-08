import datetime
import gzip
import json
import os
import re
import sys
import time

import requests
import stix2
import yaml
from pycti import (
    Indicator,
    MarkingDefinition,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)


def load_stix(file_path):
    with open(file_path, "r") as file:
        data = json.load(file)

    return data


def extract_patterns(stix_data):
    patterns = set()
    for obj in stix_data.get("objects", []):
        if "pattern" in obj:
            patterns.add(obj["pattern"])
    return patterns


def filter_stix_objects(stix_data, patterns_to_exclude):
    filtered_objects = []
    for obj in stix_data.get("objects", []):
        if obj.get("type") in ["infrastructure", "identity"]:
            continue
        if "pattern" in obj and obj["pattern"] in patterns_to_exclude:
            continue
        filtered_objects.append(obj)
    return filtered_objects


def extract_ioc_types(stix_data):
    ioc_details = []
    pattern_regex = re.compile(
        r"url:value\s*=\s*'([^']+)'|ipv4-addr:value\s*=\s*'([^']+)'"
    )
    for obj in stix_data.get("objects", []):
        if "pattern" in obj:
            match = pattern_regex.search(obj["pattern"])
            if match:
                url_value = match.group(1) or match.group(2) or match.group(3)
                if re.match(r"https?://", url_value):
                    ioc_type = "URL"
                elif re.match(r"^\d{1,3}(\.\d{1,3}){3}$", url_value):
                    ioc_type = "IPv4-Addr"
                else:
                    ioc_type = "Domain"
                name = obj.get("name", "N/A")
                watchlist_name = obj.get("indicator_types", [])
                if watchlist_name:
                    watchlist_name = watchlist_name[0]
                else:
                    watchlist_name = "[watchlist not referenced]"
                ioc_details.append((url_value, ioc_type, name, watchlist_name))
    return ioc_details


class Fortinet:
    """Fortinet connector"""

    def __init__(self):
        """Initializer"""

        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config_file_path = config_file_path.replace("\\", "/")
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        # Extra config
        self.fortinet_api_key = get_config_variable(
            "FORTINET_API_KEY",
            ["fortinet", "api_key"],
            config,
        )

        self.fortinet_interval = get_config_variable(
            "FORTINET_INTERVAL",
            ["fortinet", "interval"],
            config,
            isNumber=True,
            default=24,
        )

        self.ioc_score = get_config_variable(
            "FORTINET_IOC_SCORE",
            ["fortinet", "ioc_score"],
            config,
            isNumber=True,
            default=50,
        )

        self.fortinet_url = get_config_variable(
            "FORTINET_URL",
            ["fortinet", "url"],
            config,
            default="https://premiumapi.fortinet.com/v1/cti/feed/stix2?cc=all",
        )

        self.fortinet_marking = get_config_variable(
            "FORTINET_MARKING",
            ["fortinet", "marking_definition"],
            config,
            default="TLP:AMBER+STRICT",
        )

        self.identity_id = "identity--da04cc3f-ad56-5cf3-a1f0-860685179cdf"

    def set_marking(self):
        if self.fortinet_marking == "TLP:WHITE" or self.fortinet_marking == "TLP:CLEAR":
            marking = stix2.TLP_WHITE
        elif self.fortinet_marking == "TLP:GREEN":
            marking = stix2.TLP_GREEN
        elif self.fortinet_marking == "TLP:AMBER":
            marking = stix2.TLP_AMBER
        elif self.fortinet_marking == "TLP:AMBER+STRICT":
            marking = stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                allow_custom=True,
                x_opencti_definition_type="TLP",
                x_opencti_definition="TLP:AMBER+STRICT",
            )
        elif self.fortinet_marking == "TLP:RED":
            marking = stix2.TLP_RED
        else:
            marking = stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="TLP",
                definition={"TLP": "AMBER+STRICT"},
                allow_custom=True,
                x_opencti_definition_type="TLP",
                x_opencti_definition="TLP:AMBER+STRICT",
            )

        self.fortinet_marking = marking

    def get_fortinet_data_request(self):
        headers = {"Token": "{}".format(self.fortinet_api_key)}
        filename = "fortinet_ioc.json.backup"
        response = requests.get(
            self.fortinet_url,
            headers=headers,
            cookies=None,
            verify=False,
            timeout=(600, 600),
            stream=True,
        )  # this request aims to have the url containing IOCs
        url = response.json()[0]["data"]
        response = requests.get(
            url,
            headers=headers,
            cookies=None,
            verify=True,
            timeout=(600, 600),
            stream=True,
        )  # this request will retrieve the IOC in zip format
        open(filename, "wb").write(
            gzip.decompress(response.content)
        )  # this action will unzip the response and write the content in a json file

    def create_stix_object(self, ioc_detail):
        stix_objects = []
        object_type = ioc_detail[1]
        name = ioc_detail[0]
        description = str(ioc_detail[2]) + " " + str(ioc_detail[3])

        if object_type == "Domain":
            pattern = f"[domain-name:value = '{ioc_detail[0]}']"
            observable_type = "Domain-Name"
            observable = stix2.DomainName(
                value=name,
                object_marking_refs=self.fortinet_marking,
                custom_properties={
                    "x_opencti_score": self.ioc_score,
                    "x_opencti_description": description,
                    "created_by_ref": self.identity_id,
                },
            )
        elif object_type == "URL":
            pattern = f"[url:value = '{ioc_detail[0]}']"
            observable_type = "Url"
            observable = stix2.URL(
                value=name,
                object_marking_refs=self.fortinet_marking,
                custom_properties={
                    "x_opencti_score": self.ioc_score,
                    "x_opencti_description": description,
                    "created_by_ref": self.identity_id,
                },
            )
        elif object_type == "IPv4-Addr":
            pattern = f"[ipv4-addr:value = '{ioc_detail[0]}']"
            observable_type = "IPv4-Addr"
            observable = stix2.IPv4Address(
                value=name,
                object_marking_refs=self.fortinet_marking,
                custom_properties={
                    "x_opencti_score": self.ioc_score,
                    "x_opencti_description": description,
                    "created_by_ref": self.identity_id,
                },
            )
        else:
            return None
        stix_objects.append(observable)

        if pattern:
            try:
                indicator = stix2.Indicator(
                    id=Indicator.generate_id(pattern),
                    name=name,
                    pattern=pattern,
                    pattern_type="stix",
                    description=description,
                    created_by_ref=self.identity_id,
                    labels=[str(ioc_detail[2]), str(ioc_detail[3])],
                    object_marking_refs=self.fortinet_marking,
                    custom_properties={
                        "x_opencti_score": self.ioc_score,
                        "x_opencti_main_observable_type": observable_type,
                    },
                )
                stix_objects.append(indicator)

                relationship = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "based-on", indicator["id"], observable["id"]
                    ),
                    relationship_type="based-on",
                    source_ref=indicator["id"],
                    target_ref=observable["id"],
                    created_by_ref=self.identity_id,
                    object_marking_refs=self.fortinet_marking,
                )

                stix_objects.append(relationship)

            except:
                stix_objects.pop()

            return stix_objects

    def create_fortinet_org(self):
        identity = stix2.Identity(
            id=self.identity_id,
            spec_version="2.1",
            name="Fortinet",
            confidence=100,
            identity_class="organization",
            type="identity",
            object_marking_refs=stix2.TLP_WHITE,
        )

        return identity

    def create_stix_bundle(self):

        identity = self.create_fortinet_org()

        stix_objects = [identity, self.fortinet_marking]

        # Filter to process only new IOCs (those that were not present in the previous day's file)
        stix_new = load_stix("fortinet_ioc.json.backup")
        stix_old = load_stix("fortinet_ioc_old.json")
        patterns_old = extract_patterns(stix_old)
        filtered_objects = filter_stix_objects(stix_new, patterns_old)
        stix_new["objects"] = filtered_objects

        ioc_details = extract_ioc_types(stix_new)

        for ioc_detail in ioc_details:
            objects = self.create_stix_object(ioc_detail)
            stix_objects.extend(objects)

        bundle = stix2.Bundle(
            objects=stix_objects,
            allow_custom=True,
        )
        return bundle

    def opencti_bundle(self, work_id):

        # Check that there is the file from the previous day to compare and identify the new indicators to ingest
        if os.path.isfile("fortinet_ioc_old.json"):
            self.get_fortinet_data_request()
            bundle = self.create_stix_bundle()
            bundle_dict = json.loads(str(bundle))
            bundle_dict = json.dumps(bundle_dict, indent=4)

            self.helper.send_stix2_bundle(bundle_dict, work_id=work_id)

            os.remove("fortinet_ioc_old.json")
            os.rename("fortinet_ioc.json.backup", "fortinet_ioc_old.json")

        # Send only the Fortinet organization to ingest
        else:
            self.get_fortinet_data_request()
            os.rename("fortinet_ioc.json.backup", "fortinet_ioc_old.json")

            fortinet_org = self.create_fortinet_org()

            bundle = stix2.Bundle(
                objects=fortinet_org,
                allow_custom=True,
            )

            bundle_dict = json.loads(str(bundle))
            bundle_dict = json.dumps(bundle_dict, indent=4)
            self.helper.send_stix2_bundle(bundle_dict, work_id=work_id)

    def send_bundle(self, work_id, serialized_bundle: str):
        try:
            self.helper.send_stix2_bundle(
                serialized_bundle,
                entities_types=self.helper.connect_scope,
                work_id=work_id,
            )
        except Exception as e:
            self.helper.connector_logger.error(f"Error while sending bundle: {e}")

    def process_data(self):
        try:
            self.helper.connector_logger.info("Synchronizing with Fortinet APIs...")
            timestamp = int(time.time())
            now = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc)
            friendly_name = "Fortinet run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            current_state = self.helper.get_state()
            if current_state is None:
                self.helper.set_state(
                    {"last_run": str(now.strftime("%Y-%m-%d %H:%M:%S"))}
                )
            current_state = self.helper.get_state()
            self.helper.connector_logger.info(
                "Get IOC since " + current_state["last_run"]
            )
            self.opencti_bundle(work_id)
            self.helper.set_state({"last_run": now.astimezone().isoformat()})
            message = "End of synchronization"
            self.helper.api.work.to_processed(work_id, message)
            self.helper.connector_logger.info(message)
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("Connector stop")
            sys.exit(0)
        except Exception as e:
            self.helper.connector_logger.error(str(e))

    def run(self):
        self.helper.connector_logger.info("Fetching Fortinet datasets...")
        self.set_marking()
        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", None)
        if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
        else:
            while True:
                self.process_data()
                time.sleep(self.fortinet_interval * 60 * 60)


if __name__ == "__main__":
    try:
        fortinetConnector = Fortinet()
        fortinetConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
