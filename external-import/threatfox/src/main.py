import csv
import datetime
import io
import os
import ssl
import sys
import time
import traceback
import urllib.request
import zipfile

import stix2
import validators
import yaml
from pycti import (
    Indicator,
    Malware,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)


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
            "THREATFOX_IMPORT_OFFLINE",
            ["threatfox", "import_offline"],
            config,
            False,
            True,
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
        self.ioc_to_import = get_config_variable(
            "THREATFOX_IOC_TO_IMPORT",
            ["threatfox", "ioc_to_import"],
            config,
            False,
            "all_types",
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )

        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="Threat Fox | Abuse.ch",
            description="abuse.ch is operated by a random swiss guy fighting malware for non-profit, running a couple "
            "of projects helping internet service providers and network operators protecting their "
            "infrastructure from malware.",
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
                    friendly_name = "Threat Fox run @ " + now.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )

                    last_processed_entry_running_max = 0

                    try:
                        response = urllib.request.urlopen(
                            self.threatfox_csv_url,
                            context=ssl.create_default_context(),
                        )
                        data = response.read()
                        try:
                            zipped_file = io.BytesIO(data)
                            with zipfile.ZipFile(zipped_file, "r") as zip_ref:
                                with zip_ref.open("full.csv") as full_file:
                                    csv_data = full_file.read()
                        except zipfile.BadZipFile:
                            # Treat as an unzipped CSV from /recent/
                            csv_data = data

                        with open(
                            os.path.dirname(os.path.abspath(__file__)) + "/data.csv",
                            "wb",
                        ) as file:
                            file.write(csv_data)
                        fp = open(
                            os.path.dirname(os.path.abspath(__file__)) + "/data.csv",
                            "r",
                            encoding="utf-8",
                        )
                        csv.register_dialect(
                            "custom",
                            delimiter=",",
                            quotechar='"',
                            skipinitialspace=True,
                        )
                        rdr = csv.reader(
                            (line for line in fp if not line.startswith("#")),
                            dialect="custom",
                        )
                        # rdr = csv.reader(filter(lambda row: row[0] != "#", fp))
                        bundle_objects = []
                        # the csv-file has the following columns:
                        # first_seen_utc, ioc_id, ioc_value, ioc_type, threat_type, fk_malware, malware_alias,
                        # malware_printable, last_seen_utc, reference, tags, anonymous, reporter

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

                        # If importing a subset of IOCs
                        wanted_ioc = []
                        if self.ioc_to_import:
                            for ioc in self.ioc_to_import.split(","):
                                wanted_ioc.append(ioc.strip())
                        else:
                            wanted_ioc.append("all_types")

                        for i, row in enumerate(rdr):

                            data_object = {
                                "first_seen_utc": row[0],
                                "ioc_id": row[1],
                                "ioc_value": row[2],
                                "ioc_type": row[3],
                                "threat_type": row[4],
                                "fk_malware": row[5] if row[5] != "unknown" else "",
                                "malware_alias": row[6].split(","),
                                "malware_printable": (
                                    row[7] if row[7] != "Unknown malware" else ""
                                ),
                                "last_seen_utc": row[8],
                                "confidence_level": row[9],
                                "reference": row[10],
                                "tags": row[11].split(","),
                                "anonymous": row[12],
                                "reporter": row[13],
                            }

                            # Pre-process row data for efficiency
                            ioc_value = data_object["ioc_value"]
                            ioc_type = data_object["ioc_type"]
                            data_object["malware_alias"].insert(
                                0, data_object["fk_malware"]
                            )
                            ioc_aliases = [
                                x
                                for x in data_object["malware_alias"]
                                if x not in {"None", ""}
                            ]
                            data_object["tags"].insert(0, data_object["threat_type"])
                            ioc_labels = [
                                x for x in data_object["tags"] if x not in {"None", ""}
                            ]

                            self.helper.log_info(f"ioc_type: '{ioc_type}'")

                            # Skip unwanted IOC types
                            if not (ioc_type in wanted_ioc):
                                self.helper.log_info(
                                    f"Unwanted ioc_type skipped: {ioc_type}"
                                )
                                continue

                            entry_date = datetime.datetime.strptime(
                                data_object["first_seen_utc"], "%Y-%m-%d %H:%M:%S"
                            )
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

                            if ioc_type == "ip:port":
                                pattern_value = (
                                    "[ipv4-addr:value = '"
                                    + ioc_value.split(":")[0]
                                    + "']"
                                )
                                indicator_type = "ipv4"
                                observable_type = "IPv4-Addr"
                            elif ioc_type == "domain":
                                pattern_value = (
                                    "[domain-name:value = '" + ioc_value + "']"
                                )
                                indicator_type = "domain"
                                observable_type = "Domain-Name"
                            elif ioc_type == "url":
                                pattern_value = "[url:value = '" + ioc_value + "']"
                                indicator_type = "url"
                                observable_type = "Url"
                            elif ioc_type == "md5_hash":
                                pattern_value = (
                                    "[file:hashes.MD5 = '" + ioc_value + "']"
                                )
                                indicator_type = "md5"
                                observable_type = "StixFile"
                            elif ioc_type == "sha1_hash":
                                pattern_value = (
                                    "[file:hashes.SHA1 = '" + ioc_value + "']"
                                )
                                indicator_type = "sha1"
                                observable_type = "StixFile"
                            elif ioc_type == "sha256_hash":
                                pattern_value = (
                                    "[file:hashes.'SHA-256' = '" + ioc_value + "']"
                                )
                                indicator_type = "sha256"
                                observable_type = "StixFile"
                            else:
                                self.helper.log_warning(
                                    f"Unrecognized ioc_type: {ioc_type}"
                                )
                                continue

                            # Check if we have an external reference
                            if validators.url(data_object["reference"]):
                                indicator_external_reference = [
                                    stix2.ExternalReference(
                                        source_name="ThreatFox source reference",
                                        url=data_object["reference"],
                                    )
                                ]

                                stix_indicator = stix2.Indicator(
                                    name=ioc_value,
                                    id=Indicator.generate_id(pattern_value),
                                    indicator_types=[indicator_type],
                                    pattern_type="stix",
                                    pattern=pattern_value,
                                    valid_from=datetime.datetime.utcnow().strftime(
                                        "%Y-%m-%dT%H:%M:%S.%fZ"
                                    ),
                                    labels=ioc_labels,
                                    object_marking_refs=[stix2.TLP_WHITE],
                                    created_by_ref=self.identity["standard_id"],
                                    external_references=indicator_external_reference,
                                    custom_properties={
                                        "x_opencti_main_observable_type": observable_type
                                    },
                                )

                            else:
                                stix_indicator = stix2.Indicator(
                                    name=ioc_value,
                                    id=Indicator.generate_id(pattern_value),
                                    indicator_types=[indicator_type],
                                    pattern_type="stix",
                                    pattern=pattern_value,
                                    valid_from=datetime.datetime.utcnow().strftime(
                                        "%Y-%m-%dT%H:%M:%S.%fZ"
                                    ),
                                    labels=ioc_labels,
                                    object_marking_refs=[stix2.TLP_WHITE],
                                    created_by_ref=self.identity["standard_id"],
                                    custom_properties={
                                        "x_opencti_main_observable_type": observable_type
                                    },
                                )

                            self.helper.log_info(
                                "Indicator created: " + str(stix_indicator)
                            )

                            bundle_objects.append(stix_indicator)

                            if not data_object["malware_printable"]:
                                continue

                            if data_object["threat_type"] == "botnet_cc":
                                malware_type = "Bot"
                            elif data_object["threat_type"] == "payload_delivery":
                                malware_type = "dropper"
                            else:
                                malware_type = ""

                            # Create the malware object
                            self.helper.log_info("Creating Malware object...")
                            malware_object = stix2.Malware(
                                id=Malware.generate_id(
                                    data_object["malware_printable"]
                                ),
                                name=data_object["malware_printable"],
                                aliases=ioc_aliases,
                                created_by_ref=self.identity["standard_id"],
                                object_marking_refs=[stix2.TLP_WHITE],
                                description="Threat: "
                                + data_object["fk_malware"]
                                + " - Reporter: "
                                + data_object["reporter"],
                                is_family="false",
                                labels=ioc_labels,
                                malware_types=[malware_type] if malware_type else None,
                            )
                            self.helper.log_info(
                                "Malware object created: " + str(malware_object)
                            )
                            bundle_objects.append(malware_object)

                            # Create a relationship between the indicator and the malware object
                            self.helper.log_info("Creating Relationship...")
                            relationship = stix2.Relationship(
                                id=StixCoreRelationship.generate_id(
                                    "indicates",
                                    stix_indicator.id,
                                    malware_object.id,
                                ),
                                source_ref=stix_indicator.id,
                                target_ref=malware_object.id,
                                relationship_type="indicates",
                                created_by_ref=self.identity["standard_id"],
                                object_marking_refs=[stix2.TLP_WHITE],
                                description="Indicates relationship between indicator and malware",
                            )
                            self.helper.log_info(
                                "Relationship created: " + str(relationship)
                            )
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
                self.helper.force_ping()
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
