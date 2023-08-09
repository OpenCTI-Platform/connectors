import os
import re
import ssl
import sys
import time
from datetime import datetime, timedelta

import requests
import yaml
from bs4 import BeautifulSoup
from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2 import TLP_WHITE, Bundle, ExternalReference, IPv4Address

# URL du référentiel GitHub
github_url = "https://github.com/pr0xylife/Qakbot"

# Récupérer le contenu HTML de la page
response = requests.get(github_url)
html_content = response.text

# Analyser le contenu HTML avec Beautiful Soup
soup = BeautifulSoup(html_content, "html.parser")

# Rechercher tous les liens de fichiers sur la page
file_links = soup.find_all("a", class_="js-navigation-open")

# Set the reference date (2 days ago)
reference_date = datetime.now().date() - timedelta(days=2)

# List to store the IP addresses
c2_servers = set()

# Iterate over file links and extract IP addresses and ports of C2 servers
for link in file_links:
    file_url = "https://github.com" + link["href"]
    file_response = requests.get(file_url)
    file_content = file_response.text

    ip_port_matches = re.findall(
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+", file_content
    )
    # Extract only the IP addresses without the port
    for match in ip_port_matches:
        ip_addresses = match.split(":")[0]
        # the following line should be in the loop (doesn't appear in the commit)
        c2_servers.add(ip_addresses)


class Qakbot:
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
        self.qakbot_interval = get_config_variable(
            "QAKBOT_INTERVAL", ["qakbot", "interval"], config, True
        )
        self.create_indicators = get_config_variable(
            "QAKBOT_CREATE_INDICATORS",
            ["qakbot", "create_indicators"],
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
            name="Qakbot",
            description="Qakbot is a github repository by pr0xylife providing the IP addresses of c2 servers.",
        )

    def get_interval(self):
        return int(self.qakbot_interval) * 60 * 60 * 24

    def next_run(self, seconds):
        return

    def run(self):
        self.helper.log_info("Fetching Qakbot dataset...")
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
                    > ((int(self.qakbot_interval) - 1) * 60 * 60 * 24)
                ):
                    self.helper.log_info("Connector will run!")
                    now = datetime.utcfromtimestamp(timestamp)
                    friendly_name = "Qakbot run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )
                    try:
                        bundle_objects = []
                        for line in c2_servers:
                                external_reference = ExternalReference(
                                    source_name="Qakbot",
                                    url="https://github.com/pr0xylife/Qakbot",
                                    description="Qakbot repository URL",
                                )
                                stix_observable = IPv4Address(
                                    value=line,
                                    object_marking_refs=[TLP_WHITE],
                                    custom_properties={
                                        "description": "Qakbot address",
                                        "x_opencti_score": 100,
					"labels": ["qbot", "qakbot", "quackbot", "quakbot"],
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
        QakbotConnector = Qakbot()
        QakbotConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
