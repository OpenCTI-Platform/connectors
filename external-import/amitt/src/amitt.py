import os
import time
import urllib.request
from datetime import datetime

import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable


class Amitt:
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
        self.amitt_file_url = get_config_variable(
            "AMITT_FILE_URL", ["amitt", "amitt_file_url"], config
        )
        self.pre_amitt_file_url = get_config_variable(
            "PRE_AMITT_FILE_URL", ["amitt", "pre_amitt_file_url"], config
        )
        self.amitt_interval = get_config_variable(
            "AMITT_INTERVAL", ["amitt", "interval"], config, True
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )
        # Create the corresponding identity
        self.helper.api.identity.create(
            stix_id="identity--c9c1a598-7d0e-42fa-b8ec-e42c3de95ae4",
            type="Organization",
            name="CogSec",
            description="A nonprofit that helps specialists form teams to combat disinformation.",
        )
        self.helper.api.marking_definition.create(
            stix_id="marking-definition--8c9e2257-1c62-4ff0-9de0-1deed93cf282",
            definition_type="statement",
            definition="Copyright 2021, CogSec.",
        )

    def get_interval(self):
        return int(self.amitt_interval) * 60 * 60 * 24

    def run(self):
        self.helper.log_info("Fetching AMITT datasets...")
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
                    > ((int(self.amitt_interval) - 1) * 60 * 60 * 24)
                ):
                    self.helper.log_info("Connector will run!")
                    now = datetime.utcfromtimestamp(timestamp)
                    friendly_name = "AM!TT run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )
                    try:
                        amitt_data = (
                            urllib.request.urlopen(self.amitt_file_url)
                            .read()
                            .decode("utf-8")
                        )
                        self.helper.send_stix2_bundle(
                            amitt_data,
                            entities_types=self.helper.connect_scope,
                            update=self.update_existing_data,
                            work_id=work_id,
                        )
                    except Exception as e:
                        self.helper.log_error(str(e))
                    pre_amitt_data = urllib.request.urlopen(
                        self.pre_amitt_file_url
                    ).read()
                    self.helper.send_stix2_bundle(
                        pre_amitt_data.decode("utf-8"),
                        entities_types=self.helper.connect_scope,
                        update=self.update_existing_data,
                    )
                    # Store the current timestamp as a last run
                    self.helper.log_info(
                        "Connector successfully run, storing last_run as "
                        + str(timestamp)
                    )
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
                exit(0)

            except Exception as e:
                self.helper.log_error(str(e))

            if self.helper.connect_run_and_terminate:
                self.helper.log_info("Connector stop")
                exit(0)

            time.sleep(60)


if __name__ == "__main__":
    try:
        amittConnector = Amitt()
        amittConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
