import json
import os
import re
import ssl
import time
import urllib
from datetime import datetime
from urllib import parse

import certifi
import stix2
import yaml
from pycti import (
    Indicator,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)


class abuseipdbipblacklistimport:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.api_url = get_config_variable(
            "ABUSEIPDB_URL", ["abuseipdbipblacklistimport", "api_url"], config
        )
        self.api_key = get_config_variable(
            "ABUSEIPDB_API_KEY", ["abuseipdbipblacklistimport", "api_key"], config
        )
        self.score = get_config_variable(
            "ABUSEIPDB_SCORE", ["abuseipdbipblacklistimport", "score"], config, True
        )
        self.limit = get_config_variable(
            "ABUSEIPDB_LIMIT", ["abuseipdbipblacklistimport", "limit"], config, True
        )
        self.interval = get_config_variable(
            "ABUSEIPDB_INTERVAL",
            ["abuseipdbipblacklistimport", "interval"],
            config,
            True,
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )
        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="AbuseIPDB",
            description="AbuseIPDB is a project dedicated to helping combat the spread of hackers, spammers, and abusive activity on the internet",
        )

    def get_interval(self):
        return int(self.interval) * 60 * 60 * 24

    def next_run(self, seconds):
        return

    def run(self):
        self.helper.log_info("abuseIPDB dataset...")
        while True:
            try:
                # Get the current timestamp and check
                timestamp = int(time.time())
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
                # If the last_run is more than interval-1 day
                if last_run is None or (
                    (timestamp - last_run) > ((int(self.interval) - 1) * 60 * 60 * 24)
                ):
                    # Initiate the run
                    self.helper.log_info("Connector will run!")
                    now = datetime.utcfromtimestamp(timestamp)
                    friendly_name = "AbuseIPDB connector run @ " + now.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )
                    try:
                        # Requesting data over AbuseIPDB
                        req = urllib.request.Request(self.api_url)
                        req.add_header("Key", self.api_key)
                        req.add_header("Accept", "application/json")
                        req.method = "GET"
                        body = parse.urlencode(
                            {
                                "confidenceMinimum": str(self.score),
                                "limit": str(self.limit),
                            }
                        ).encode()

                        response = urllib.request.urlopen(
                            req,
                            context=ssl.create_default_context(cafile=certifi.where()),
                            data=body,
                        )
                        image = response.read()
                        data_json = json.loads(image)

                        # preparing the bundle to be sent to OpenCTI worker
                        external_reference = stix2.ExternalReference(
                            source_name="AbuseIPDB database",
                            url="https://www.abuseipdb.com/",
                            description="AbuseIPDB database URL",
                        )
                        bundle_objects = []

                        # Filling the bundle
                        ipv4validator = re.compile(
                            "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
                        )
                        for d in data_json["data"]:
                            if ipv4validator.match(d["ipAddress"]):
                                pattern = "[ipv4-addr:value = '" + d["ipAddress"] + "']"
                                stix_indicator = stix2.Indicator(
                                    id=Indicator.generate_id(pattern),
                                    name=d["ipAddress"],
                                    description="Agressive IP known malicious on AbuseIPDB"
                                    + " - countryCode: "
                                    + str(d["countryCode"])
                                    + " - abuseConfidenceScore: "
                                    + str(d["abuseConfidenceScore"])
                                    + " - lastReportedAt: "
                                    + str(d["lastReportedAt"]),
                                    created_by_ref=self.identity["standard_id"],
                                    confidence=self.helper.connect_confidence_level,
                                    pattern_type="stix",
                                    pattern=pattern,
                                    external_references=[external_reference],
                                    object_marking_refs=[stix2.TLP_WHITE],
                                    custom_properties={
                                        "x_opencti_score": d["abuseConfidenceScore"],
                                        "x_opencti_main_observable_type": "IPv4-Addr",
                                    },
                                )
                                stix_observable = stix2.IPv4Address(
                                    type="ipv4-addr",
                                    spec_version="2.1",
                                    value=d["ipAddress"],
                                    object_marking_refs=[stix2.TLP_WHITE],
                                    custom_properties={
                                        "description": "Agressive IP known malicious on AbuseIPDB"
                                        + " - countryCode: "
                                        + str(d["countryCode"])
                                        + " - abuseConfidenceScore: "
                                        + str(d["abuseConfidenceScore"])
                                        + " - lastReportedAt: "
                                        + str(d["lastReportedAt"]),
                                        "x_opencti_score": d["abuseConfidenceScore"],
                                        "created_by_ref": self.identity["standard_id"],
                                        "external_references": [external_reference],
                                    },
                                )
                            else:
                                pattern = "[ipv6-addr:value = '" + d["ipAddress"] + "']"
                                stix_indicator = stix2.Indicator(
                                    id=Indicator.generate_id(pattern),
                                    name=d["ipAddress"],
                                    description="Agressive IP known malicious on AbuseIPDB"
                                    + " - countryCode: "
                                    + str(d["countryCode"])
                                    + " - abuseConfidenceScore: "
                                    + str(d["abuseConfidenceScore"])
                                    + " - lastReportedAt: "
                                    + str(d["lastReportedAt"]),
                                    created_by_ref=self.identity["standard_id"],
                                    confidence=self.helper.connect_confidence_level,
                                    pattern_type="stix",
                                    pattern=pattern,
                                    external_references=[external_reference],
                                    object_marking_refs=[stix2.TLP_WHITE],
                                    custom_properties={
                                        "x_opencti_score": d["abuseConfidenceScore"],
                                        "x_opencti_main_observable_type": "IPv6-Addr",
                                    },
                                )
                                stix_observable = stix2.IPv6Address(
                                    type="ipv6-addr",
                                    spec_version="2.1",
                                    value=d["ipAddress"],
                                    object_marking_refs=[stix2.TLP_WHITE],
                                    custom_properties={
                                        "description": "Agressive IP known malicious on AbuseIPDB"
                                        + " - countryCode: "
                                        + str(d["countryCode"])
                                        + " - abuseConfidenceScore: "
                                        + str(d["abuseConfidenceScore"])
                                        + " - lastReportedAt: "
                                        + str(d["lastReportedAt"]),
                                        "x_opencti_score": d["abuseConfidenceScore"],
                                        "created_by_ref": self.identity["standard_id"],
                                        "external_references": [external_reference],
                                    },
                                )
                            # Adding the IP to the list
                            stix_relationship = stix2.Relationship(
                                id=StixCoreRelationship.generate_id(
                                    "based-on", stix_indicator.id, stix_observable.id
                                ),
                                relationship_type="based-on",
                                source_ref=stix_indicator.id,
                                target_ref=stix_observable.id,
                                object_marking_refs=[stix2.TLP_WHITE],
                            )
                            bundle_objects.append(stix_indicator)
                            bundle_objects.append(stix_observable)
                            bundle_objects.append(stix_relationship)
                        # Creating the bundle from the list
                        bundle = stix2.Bundle(bundle_objects, allow_custom=True)
                        bundle_json = bundle.serialize()
                        # Sending the bundle
                        self.helper.send_stix2_bundle(
                            bundle_json,
                            update=self.update_existing_data,
                            work_id=work_id,
                        )
                    except Exception as e:
                        self.helper.log_error(str(e))
                    # Store the current timestamp as a last run
                    message = "Connector successfully run, storing last_run as " + str(
                        timestamp
                    )
                    self.helper.log_info(message)
                    self.helper.set_state({"last_run": timestamp})
                    self.helper.api.work.to_processed(work_id, message)
                    self.helper.log_info(
                        "Last_run stored, next run in: "
                        + str(round(self.get_interval() / 60 / 60 / 24, 2))
                        + " days"
                    )
                    time.sleep(60)
                else:
                    # wait for next run
                    new_interval = self.get_interval() - (timestamp - last_run)
                    self.helper.log_info(
                        "Connector will not run, next run in: "
                        + str(round(new_interval / 60 / 60 / 24, 2))
                        + " days"
                    )
                    time.sleep(60)
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
                time.sleep(60)


if __name__ == "__main__":
    try:
        connector = abuseipdbipblacklistimport()
        connector.run()
    except:
        time.sleep(10)
        exit(0)
