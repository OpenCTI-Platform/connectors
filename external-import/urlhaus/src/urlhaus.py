import csv
import os
import ssl
import time
import urllib.request
from datetime import datetime

import certifi
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2 import TLP_WHITE, URL, Bundle, ExternalReference


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

    def get_interval(self):
        return int(self.urlhaus_interval) * 60 * 60 * 24

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
                        + datetime.utcfromtimestamp(last_run).strftime(
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
                    now = datetime.utcfromtimestamp(timestamp)
                    friendly_name = "URLhaus run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )
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
                        for row in rdr:
                            if row[3] == "online" or self.urlhaus_import_offline:
                                external_reference = ExternalReference(
                                    source_name="Abuse.ch URLhaus",
                                    url=row[7],
                                    description="URLhaus repository URL",
                                )
                                stix_observable = URL(
                                    value=row[2],
                                    object_marking_refs=[TLP_WHITE],
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
                        fp.close()
                        bundle = Bundle(
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
                    self.helper.set_state({"last_run": timestamp})
                    self.helper.api.work.to_processed(work_id, message)
                    self.helper.log_info(
                        "Last_run stored, next run in: "
                        + str(round(self.get_interval() / 60 / 60 / 24, 2))
                        + " days"
                    )
                    time.sleep(60)
                else:
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
        URLhausConnector = URLhaus()
        URLhausConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
