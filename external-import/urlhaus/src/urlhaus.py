import csv
import datetime
import os
import ssl
import sys
import time
import traceback
import urllib.request

import stix2
import yaml
from dateutil.parser import parse
from pycti import (
    Indicator,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)


class URLhaus:
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
        self.urlhaus_csv_url = get_config_variable(
            "URLHAUS_CSV_URL", ["urlhaus", "csv_url"], config
        )
        self.urlhaus_import_offline = get_config_variable(
            "URLHAUS_IMPORT_OFFLINE", ["urlhaus", "import_offline"], config, False, True
        )
        self.urlhaus_interval = get_config_variable(
            "URLHAUS_INTERVAL", ["urlhaus", "interval"], config, False
        )
        self.threats_from_labels = get_config_variable(
            "URLHAUS_THREATS_FROM_LABELS",
            ["urlhaus", "threats_from_labels"],
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
            name="Abuse.ch",
            description="abuse.ch is operated by a random swiss guy fighting malware for non-profit, running a couple of projects helping internet service providers and network operators protecting their infrastructure from malware.",
        )

    def get_interval(self, offset=0):
        return (float(self.urlhaus_interval) * 60 * 60 * 24) + offset

    def next_run(self, seconds):
        return

    def run(self):
        self.helper.log_info("Fetching URLhaus dataset...")
        while True:
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
                friendly_name = "URLhaus run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )

                # initialize the threat cache with each run
                if self.threats_from_labels:
                    treat_cache = {}

                try:
                    response = urllib.request.urlopen(
                        self.urlhaus_csv_url,
                        context=ssl.create_default_context(),
                    )
                except urllib.error.HTTPError:
                    # we only accept HTTPError
                    self.helper.log_error(traceback.format_exc())
                    time.sleep(60)
                    continue

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
                    entry_date = parse(row[1])

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

                    if row[3] == "online" or self.urlhaus_import_offline:
                        external_reference = stix2.ExternalReference(
                            source_name="Abuse.ch URLhaus",
                            url=row[7],
                            description="URLhaus repository URL",
                        )
                        pattern = "[url:value = '" + row[2] + "']"
                        stix_indicator = stix2.Indicator(
                            id=Indicator.generate_id(pattern),
                            name=row[2],
                            description="Threat: "
                            + row[5]
                            + " - Reporter: "
                            + row[8]
                            + " - Status: "
                            + row[3],
                            created_by_ref=self.identity["standard_id"],
                            confidence=self.helper.connect_confidence_level,
                            pattern_type="stix",
                            valid_from=entry_date,
                            created=entry_date,
                            pattern=pattern,
                            external_references=[external_reference],
                            object_marking_refs=[stix2.TLP_WHITE],
                            custom_properties={
                                "x_opencti_score": 80,
                                "x_opencti_main_observable_type": "Url",
                            },
                        )
                        stix_observable = stix2.URL(
                            value=row[2],
                            object_marking_refs=[stix2.TLP_WHITE],
                            custom_properties={
                                "description": "Threat: "
                                + row[5]
                                + " - Reporter: "
                                + row[8]
                                + " - Status: "
                                + row[3],
                                "x_opencti_score": 80,
                                "labels": [x for x in row[6].split(",") if x],
                                "created_by_ref": self.identity["standard_id"],
                                "external_references": [external_reference],
                            },
                        )
                        stix_relationship = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "based-on",
                                stix_indicator.id,
                                stix_observable.id,
                            ),
                            relationship_type="based-on",
                            source_ref=stix_indicator.id,
                            target_ref=stix_observable.id,
                            object_marking_refs=[stix2.TLP_WHITE],
                        )
                        bundle_objects.append(stix_indicator)
                        bundle_objects.append(stix_observable)
                        bundle_objects.append(stix_relationship)
                        if self.threats_from_labels:
                            for label in row[6].split(","):
                                if label and label is not None:
                                    # implementing a primitive caching
                                    threat = None
                                    try:
                                        threat = treat_cache[label]
                                    except KeyError:
                                        custom_attributes = """
                                            id
                                            standard_id
                                            entity_type
                                        """
                                        entities = (
                                            self.helper.api.stix_domain_object.list(
                                                types=[
                                                    "Threat-Actor",
                                                    "Intrusion-Set",
                                                    "Malware",
                                                    "Campaign",
                                                    "Incident",
                                                    "Tool",
                                                ],
                                                filters={
                                                    "mode": "and",
                                                    "filters": [
                                                        {
                                                            "key": "name",
                                                            "values": [label],
                                                        }
                                                    ],
                                                    "filterGroups": [],
                                                },
                                                customAttributes=custom_attributes,
                                            )
                                        )
                                        if len(entities) > 0:
                                            threat = entities[0]
                                            treat_cache[label] = threat
                                    if threat is not None:
                                        stix_threat_relation_indicator = stix2.Relationship(
                                            id=StixCoreRelationship.generate_id(
                                                "indicates",
                                                stix_indicator.id,
                                                threat["standard_id"],
                                                entry_date,
                                                entry_date,
                                            ),
                                            source_ref=stix_indicator.id,
                                            target_ref=threat["standard_id"],
                                            relationship_type="indicates",
                                            start_time=entry_date,
                                            stop_time=entry_date
                                            + datetime.timedelta(0, 3),
                                            confidence=self.helper.connect_confidence_level,
                                            created_by_ref=self.identity["standard_id"],
                                            object_marking_refs=[stix2.TLP_WHITE],
                                            created=entry_date,
                                            modified=entry_date,
                                            allow_custom=True,
                                        )
                                        stix_threat_relation_observable = stix2.Relationship(
                                            id=StixCoreRelationship.generate_id(
                                                "related-to",
                                                stix_observable.id,
                                                threat["standard_id"],
                                                entry_date,
                                                entry_date,
                                            ),
                                            source_ref=stix_observable.id,
                                            target_ref=threat["standard_id"],
                                            relationship_type="related-to",
                                            start_time=entry_date,
                                            stop_time=entry_date
                                            + datetime.timedelta(0, 3),
                                            confidence=self.helper.connect_confidence_level,
                                            created_by_ref=self.identity["standard_id"],
                                            object_marking_refs=[stix2.TLP_WHITE],
                                            created=entry_date,
                                            modified=entry_date,
                                            allow_custom=True,
                                        )
                                        bundle_objects.append(
                                            stix_threat_relation_indicator
                                        )
                                        bundle_objects.append(
                                            stix_threat_relation_observable
                                        )
                fp.close()
                bundle = stix2.Bundle(
                    objects=bundle_objects, allow_custom=True
                ).serialize()
                self.helper.send_stix2_bundle(
                    bundle,
                    update=self.update_existing_data,
                    work_id=work_id,
                )
                if os.path.exists(
                    os.path.dirname(os.path.abspath(__file__)) + "/data.csv"
                ):
                    os.remove(os.path.dirname(os.path.abspath(__file__)) + "/data.csv")

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

            if self.helper.connect_run_and_terminate:
                self.helper.log_info("Connector stop")
                self.helper.force_ping()
                sys.exit(0)

            time.sleep(60)


if __name__ == "__main__":
    try:
        URLhausConnector = URLhaus()
    except Exception:
        print(traceback.format_exc())
        time.sleep(10)
        sys.exit(0)

    try:
        URLhausConnector.run()
    except Exception:
        URLhausConnector.helper.log_error(traceback.format_exc())
        time.sleep(10)
        sys.exit(0)
