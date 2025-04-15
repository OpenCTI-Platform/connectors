import os
import re
import ssl
import sys
import time
import urllib.request
from datetime import datetime

import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2 import TLP_WHITE, Bundle, DomainName, ExternalReference


class Stopforumspam:
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
        self.stopforumspam_url = get_config_variable(
            "STOPFORUMSPAM_URL", ["stopforumspam", "url"], config
        )
        self.stopforumspam_interval = get_config_variable(
            "STOPFORUMSPAM_INTERVAL", ["stopforumspam", "interval"], config, True
        )
        self.create_indicators = get_config_variable(
            "STOPFORUMSPAM_CREATE_INDICATORS",
            ["stopforumspam", "create_indicators"],
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
            name="Stopforumspam",
            description="Stopforumspam is providing malicious domain names",
        )

    def get_interval(self):
        return int(self.stopforumspam_interval) * 60 * 60 * 24

    def next_run(self, seconds):
        return

    def run(self):
        self.helper.log_info("Fetching stopforumspam dataset...")
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
                    > ((int(self.stopforumspam_interval) - 1) * 60 * 60 * 24)
                ):
                    self.helper.log_info("Connector will run!")
                    now = datetime.utcfromtimestamp(timestamp)
                    friendly_name = "Stopforumspam run @ " + now.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )
                    try:
                        response = urllib.request.urlopen(
                            self.stopforumspam_url,
                            context=ssl.create_default_context(),
                        )
                        image = response.read()
                        with open(
                            os.path.dirname(os.path.abspath(__file__)) + "/data.txt",
                            "wb",
                        ) as file:
                            file.write(image)
                        count = 0
                        bundle_objects = []
                        with open(
                            os.path.dirname(os.path.abspath(__file__)) + "/data.txt"
                        ) as fp:
                            for line in fp:
                                count += 1
                                if count <= 3:
                                    continue
                                line = line.strip()
                                matchHtmlTag = re.search(r"^<\/?\w+>", line)
                                if matchHtmlTag:
                                    continue
                                matchBlankLine = re.search(r"^\s*$", line)
                                if matchBlankLine:
                                    continue
                                external_reference = ExternalReference(
                                    source_name="stopforumspam",
                                    url="https://www.stopforumspam.com/downloads/toxic_domains_whole_filtered_50000.txt",
                                    description="Stopforumspam feed URL",
                                )
                                stix_observable = DomainName(
                                    value=line,
                                    object_marking_refs=[TLP_WHITE],
                                    custom_properties={
                                        "description": "Stopforumspam",
                                        "x_opencti_score": 60,
                                        "labels": ["spam"],
                                        "created_by_ref": self.identity["standard_id"],
                                        "x_opencti_create_indicator": self.create_indicators,
                                        "external_references": [external_reference],
                                    },
                                )
                                bundle_objects.append(stix_observable)
                        bundle = Bundle(
                            objects=bundle_objects, allow_custom=True
                        ).serialize()
                        self.helper.send_stix2_bundle(
                            bundle,
                            update=self.update_existing_data,
                            work_id=work_id,
                        )
                        if os.path.exists(
                            os.path.dirname(os.path.abspath(__file__)) + "/data.txt"
                        ):
                            os.remove(
                                os.path.dirname(os.path.abspath(__file__)) + "/data.txt"
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
                self.helper.force_ping()
                sys.exit(0)

            time.sleep(60)


if __name__ == "__main__":
    try:
        StopforumspamConnector = Stopforumspam()
        StopforumspamConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
