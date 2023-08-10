import os
import re
import sys
import time
from datetime import datetime

import requests
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2 import TLP_WHITE, Bundle, DomainName, ExternalReference, IPv4Address


def import_ip_domain(url):
    response = requests.get(url)
    if response.status_code != 200:
        raise Exception("Failed to download file from the URL.")

    iocs = []

    lines = response.text.splitlines()
    description = None
    for line in lines:
        if line.startswith("#"):
            # This line contains a description
            description = line[
                1:
            ].strip()  # Remove the '#' and leading/trailing whitespaces
        elif line.strip() == "":
            # Ignore empty lines
            continue
        elif description is not None or "." in line:
            # This line contains a C2 server (domain or IP), or it follows a description
            iocs.append(
                {
                    "description": description.strip()
                    if description
                    else "",  # Use an empty string if description is None
                    "value": line.strip(),
                }
            )

    return iocs


# Usage example with the new URL
url = "https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/c2-iocs.txt"
c2_iocs = import_ip_domain(url)


class C2iocs:
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
        self.c2iocs_interval = get_config_variable(
            "C2IOCS_INTERVAL", ["c2iocs", "interval"], config, True
        )
        self.create_indicators = get_config_variable(
            "C2IOCS_CREATE_INDICATORS",
            ["c2iocs", "create_indicators"],
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
            name="C2iocs",
            description="C2iocs is a github repository by Neo23x0 providing the IP addresses of c2 servers.",
        )

    def get_interval(self):
        return int(self.c2iocs_interval) * 60 * 60 * 24

    def next_run(self, seconds):
        return

    def run(self):
        self.helper.log_info("Fetching C2iocs dataset...")
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
                    > ((int(self.c2iocs_interval) - 1) * 60 * 60 * 24)
                ):
                    self.helper.log_info("Connector will run!")
                    now = datetime.utcfromtimestamp(timestamp)
                    friendly_name = "C2iocs run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )
                    try:
                        bundle_objects = []
                        for ioc in c2_iocs:
                            external_reference = ExternalReference(
                                source_name="C2iocs",
                                url="https://github.com/Neo23x0/signature-base/blob/master/iocs/c2-iocs.txt",
                                description="The file is from Neo23x0's Github repository and contains C2 server and decription",
                            )
                            if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ioc["value"]):
                                stix_observable = IPv4Address(
                                    value=ioc["value"],
                                    object_marking_refs=[TLP_WHITE],
                                    custom_properties={
                                        "description": ioc["description"],
                                        "x_opencti_score": 70,
                                        "labels": ["c2", "c2 server"],
                                        "created_by_ref": self.identity["standard_id"],
                                        "x_opencti_create_indicator": self.create_indicators,
                                        "external_references": [external_reference],
                                    },
                                )
                                bundle_objects.append(stix_observable)
                            else:
                                stix_observable = DomainName(
                                    value=ioc["value"],
                                    object_marking_refs=[TLP_WHITE],
                                    custom_properties={
                                        "description": ioc["description"],
                                        "x_opencti_score": 70,
                                        "labels": ["c2", "c2 server"],
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
                sys.exit(0)

            time.sleep(60)


if __name__ == "__main__":
    try:
        C2iocsConnector = C2iocs()
        C2iocsConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
