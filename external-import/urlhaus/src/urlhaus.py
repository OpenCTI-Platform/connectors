import csv
import datetime
import os
import ssl
import sys
import time
import urllib.request

import certifi
import stix2
import yaml
from dateutil.parser import parse
from pycti import OpenCTIConnectorHelper, StixCoreRelationship, get_config_variable


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
            "URLHAUS_INTERVAL", ["urlhaus", "interval"], config, True
        )
        self.create_indicators = get_config_variable(
            "URLHAUS_CREATE_INDICATORS",
            ["urlhaus", "create_indicators"],
            config,
            False,
            True,
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
        return (float(self.urlhaus_interval) * 60 * 60 * 24 ) + offset

    def next_run(self, seconds):
        return

    def run(self):
        self.helper.log_info("Fetching URLhaus dataset...")
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
                    (timestamp - last_run)
                    > ((int(self.urlhaus_interval) - 1) * 60 * 60 * 24)
                ):
                    self.helper.log_info("Connector will run!")
                    now = datetime.datetime.utcfromtimestamp(timestamp)
                    friendly_name = "URLhaus run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )

                    if self.threats_from_labels:
                        treat_cache = {}
                    try:
                        response = urllib.request.urlopen(
                            self.urlhaus_csv_url,
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
                        # id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
                        
                        if  current_state is not None and "last_processed_entry" in current_state:
                            last_processed_entry = current_state["last_processed_entry"]  # epoch time format
                        else:
                            self.helper.log_info("'last_processed_entry' state not found, setting it to epoch start.")
                            last_processed_entry = 0  # start of the epoch
                        
                        last_processed_entry_running_max = last_processed_entry
                        
                        for i, row in enumerate(rdr):
                            entry_date = parse(row[1])

                            if i % 5000 == 0: 
                                self.helper.log_info(f"Process entry {i} with dateadded='{entry_date.strftime('%Y-%m-%d %H:%M:%S')}'")

                            # skip entry if newer events already processed in the past
                            if last_processed_entry > entry_date.timestamp():
                                continue
                            last_processed_entry_running_max = max(entry_date.timestamp(), last_processed_entry_running_max)

                            if row[3] == "online" or self.urlhaus_import_offline:
                                external_reference = stix2.ExternalReference(
                                    source_name="Abuse.ch URLhaus",
                                    url=row[7],
                                    description="URLhaus repository URL",
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
                                        "x_opencti_create_indicator": self.create_indicators,
                                        "external_references": [external_reference],
                                    },
                                )
                                bundle_objects.append(stix_observable)
                                if self.threats_from_labels:
                                    for label in row[6].split(","):
                                        if label:

                                            # implementing a primitive caching
                                            try:
                                                threat = treat_cache[label]
                                            except KeyError:
                                                custom_attributes = """
                                                    id
                                                    standard_id
                                                    entity_type
                                                """
                                                threat = (
                                                    self.helper.api.stix_domain_object.read(
                                                        filters=[
                                                            {
                                                                "key": "name",
                                                                "values": [label],
                                                            }
                                                        ],
                                                        first=1,
                                                        customAttributes=custom_attributes,
                                                    )
                                                )
                                                treat_cache[label] = threat

                                            if threat is not None:
                                                date = parse(row[1])
                                                relation = stix2.Relationship(
                                                    id=StixCoreRelationship.generate_id(
                                                        "related-to",
                                                        stix_observable.id,
                                                        threat["standard_id"],
                                                        date,
                                                        date,
                                                    ),
                                                    source_ref=stix_observable.id,
                                                    target_ref=threat["standard_id"],
                                                    relationship_type="related-to",
                                                    start_time=date,
                                                    stop_time=date
                                                    + datetime.timedelta(0, 3),
                                                    confidence=self.helper.connect_confidence_level,
                                                    created_by_ref=self.identity[
                                                        "standard_id"
                                                    ],
                                                    object_marking_refs=[
                                                        stix2.TLP_WHITE
                                                    ],
                                                    created=date,
                                                    modified=date,
                                                    allow_custom=True,
                                                )
                                                bundle_objects.append(relation)
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
                            os.remove(
                                os.path.dirname(os.path.abspath(__file__)) + "/data.csv"
                            )
                    except Exception as e:
                        self.helper.log_error(str(e))
                    # Store the current timestamp as a last run
                    message = "Connector successfully run, storing last_run as " + str(
                        timestamp
                    )
                    self.helper.log_info(message)
                    self.helper.set_state({"last_run": timestamp, "last_processed_entry": last_processed_entry_running_max})
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
            except Exception as e:
                self.helper.log_error(str(e))

            if self.helper.connect_run_and_terminate:
                self.helper.log_info("Connector stop")
                sys.exit(0)

            time.sleep(60)


if __name__ == "__main__":
    try:
        URLhausConnector = URLhaus()
        URLhausConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
