import csv
import datetime
import os
import ssl
import sys
import time
import traceback
import urllib.request

import certifi
import stix2
import yaml
from dateutil.parser import parse
from pycti import OpenCTIConnectorHelper, StixCoreRelationship, get_config_variable


class ThreatFox:
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
        self.threatfox_csv_url = get_config_variable(
            "THREATFOX_CSV_URL", ["threatfox", "csv_url"], config
        )
        self.threatfox_import_offline = get_config_variable(
            "THREATFOX_IMPORT_OFFLINE", ["threatfox", "import_offline"], config, False, True
        )
        self.threatfox_interval = get_config_variable(
            "THREATFOX_INTERVAL", ["threatfox", "interval"], config, False
        )
        self.create_indicators = get_config_variable(
            "THREATFOX_CREATE_INDICATORS",
            ["threatfox", "create_indicators"],
            config,
            False,
            True,
        )
        self.threats_from_labels = get_config_variable(
            "THREATFOX_THREATS_FROM_LABELS",
            ["threatfox", "threats_from_labels"],
            config,
            False,
            True,
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )
        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="Threat Fox | Abuse.ch",
            description="abuse.ch is operated by a random swiss guy fighting malware for non-profit, running a couple of projects helping internet service providers and network operators protecting their infrastructure from malware.",
        )

    def get_interval(self, offset=0):
        return (float(self.threatfox_interval) * 60 * 60 * 24) + offset

    def next_run(self, seconds):
        return

    def run(self):
        self.helper.log_info("Fetching Threat Fox dataset...")
        while True:
            try:
                # Get the current timestamp and check
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    self.helper.log_info(
                        "Connector last run: "
                        + datetime.datetime.utcfromtimestamp(last_run).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )
                else:
                    last_run = None
                    self.helper.log_info("Connector has never run")
                # If the last_run is more than interval-1 day
                if last_run is None or (
                    (timestamp - last_run) > self.get_interval(offset=-1)
                ):
                    self.helper.log_info("Connector will run!")
                    now = datetime.datetime.utcfromtimestamp(timestamp)
                    friendly_name = "Threat Fox run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )

                    # initialize the threat cache with each run
                    if self.threats_from_labels:
                        treat_cache = {}

                    try:
                        response = urllib.request.urlopen(
                            self.threatfox_csv_url,
                            context=ssl.create_default_context(cafile=certifi.where()),
                        )
                        image = response.read()
                        with open(
                            os.path.dirname(os.path.abspath(__file__)) + "/data.csv",
                            "wb",
                        ) as file:
                            file.write(image)
                        fp = open(
                            os.path.dirname(os.path.abspath(__file__)) + "/data.csv",
                            "r",
                        )
                        rdr = csv.reader(filter(lambda row: row[0] != "#", fp))
                        bundle_objects = []
                        ## the csv-file hast the following columns
                        # id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter

                        if (
                            current_state is not None
                            and "last_processed_entry" in current_state
                        ):
                            last_processed_entry = current_state[
                                "last_processed_entry"
                            ]  # epoch time format
                        else:
                            self.helper.log_info(
                                "'last_processed_entry' state not found, setting it to epoch start."
                            )
                            last_processed_entry = 0  # start of the epoch

                        last_processed_entry_running_max = last_processed_entry

                        for i, row in enumerate(rdr):
                            # Pre-process row data for efficiency
                            ioc_value = row[2].strip().replace('"', '')
                            ioc_type = row[3].strip().strip('"')
                            self.helper.log_info(f"ioc_type: '{ioc_type}'")

                            entry_date = datetime.datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S")
                            if i % 5000 == 0:
                                self.helper.log_info(
                                    f"Process entry {i} with dateadded='{entry_date.strftime('%Y-%m-%d %H:%M:%S')}'"
                                )

                            # skip entry if newer events already processed in the past
                            if last_processed_entry > entry_date.timestamp():
                                continue
                            last_processed_entry_running_max = max(
                                entry_date.timestamp(), last_processed_entry_running_max
                            )

                            observable_type = ""  # new variable
                            if ioc_type == "ip:port":
                                pattern_value = "[ipv4-addr:value = '" + ioc_value.split(":")[0] + "']"
                                indicator_type = "IP"
                                observable_type = "ipv4-addr"  # set observable_type
                            elif ioc_type == "domain":
                                pattern_value = "[domain-name:value = '" + ioc_value + "']"
                                indicator_type = "malicious-activity"
                                observable_type = "domain-name"  # set observable_type
                            elif ioc_type == "url":
                                pattern_value = "[url:value = '" + ioc_value + "']"
                                indicator_type = "malicious-activity"
                                observable_type = "url"  # set observable_type
                            else:
                                self.helper.log_warning(f"Unrecognized ioc_type: {ioc_type}")
                                continue

                            stix_observable = stix2.Indicator(
                                indicator_types=[indicator_type],
                                pattern_type="stix",
                                pattern=pattern_value,
                                valid_from=datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                                labels=[row[i].replace('"', '') for i in range(4, 9) if row[i]],
                                object_marking_refs=[stix2.TLP_WHITE],
                                created_by_ref=self.identity["standard_id"],
                            )
                            self.helper.log_info("Indicator created: " + str(stix_observable))
                            bundle_objects.append(stix_observable)

                            malware_type = ""
                            if row[4] == "botnet_cc":
                                malware_type = "Bot"
                            elif row[4] == "payload_delivery":
                                malware_type = "dropper"
                            else:
                                malware_type = ""

                                # Create the malware object
                                self.helper.log_info("Creating Malware object...")
                                malware_object = stix2.Malware(
                                    name=row[5].replace('"', ''),
                                    aliases=[row[i].replace('"', '') for i in range(6, 8) if row[i]],
                                    created_by_ref=self.identity["standard_id"],
                                    object_marking_refs=[stix2.TLP_WHITE],
                                    description="Threat: " + row[5].replace('"', '') + " - Reporter: " + row[
                                        13].replace('"', ''),
                                    is_family="false",
                                    labels=[row[i].replace('"', '') for i in range(4, 9) if row[i] != "None"],
                                    malware_types=[malware_type] if malware_type else None,
                                )
                                self.helper.log_info("Malware object created: " + str(malware_object))
                                bundle_objects.append(malware_object)

                                # Create a relationship between the indicator and the malware object
                                self.helper.log_info("Creating Relationship...")
                                relationship = stix2.Relationship(
                                    source_ref=stix_observable.id,
                                    target_ref=malware_object.id,
                                    relationship_type="indicates",
                                    created_by_ref=self.identity["standard_id"],
                                    object_marking_refs=[stix2.TLP_WHITE],
                                    description="Indicates relationship between indicator and malware",
                                )
                                self.helper.log_info("Relationship created: " + str(relationship))
                                bundle_objects.append(relationship)

                        fp.close()
                        bundle = stix2.Bundle(
                            objects=bundle_objects, allow_custom=True
                        ).serialize()
                        self.helper.send_stix2_bundle(
                            bundle,
                            update=self.update_existing_data,
                            work_id=work_id,
                        )
                        print(bundle)
                        if os.path.exists(
                            os.path.dirname(os.path.abspath(__file__)) + "/data.csv"
                        ):
                            os.remove(
                                os.path.dirname(os.path.abspath(__file__)) + "/data.csv"
                            )
                    except Exception:
                        self.helper.log_error(traceback.format_exc())
                    # Store the current timestamp as a last run
                    message = "Connector successfully run, storing last_run as " + str(
                        timestamp
                    )
                    self.helper.log_info(message)
                    self.helper.set_state(
                        {
                            "last_run": timestamp,
                            "last_processed_entry": last_processed_entry_running_max,
                        }
                    )
                    self.helper.api.work.to_processed(work_id, message)
                    self.helper.log_info(
                        "Last_run stored, next run in: "
                        + str(round(self.get_interval() / 60 / 60 / 24, 2))
                        + " days"
                    )
                else:
                    new_interval = self.get_interval() - (timestamp - last_run)
                    self.helper.log_info(
                        "Connector will not run, next run in: "
                        + str(round(new_interval / 60 / 60 / 24, 2))
                        + " days"
                    )

            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                sys.exit(0)
            except Exception:
                self.helper.log_error(traceback.format_exc())

            if self.helper.connect_run_and_terminate:
                self.helper.log_info("Connector stop")
                sys.exit(0)

            time.sleep(60)


if __name__ == "__main__":
    try:
        ThreatFoxConnector = ThreatFox()
        ThreatFoxConnector.run()
    except Exception:
        print(traceback.format_exc())
        time.sleep(10)
        sys.exit(0)
