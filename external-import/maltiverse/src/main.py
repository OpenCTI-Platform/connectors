import json
import os
import sys
import time
from datetime import datetime

import taxii2client.v21 as taxiicli
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable


class MaltiverseConnector:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.interval = get_config_variable(
            "MALTIVERSE_POLL_INTERVAL", ["maltiverse", "poll_interval"], config, True
        )
        self.user = get_config_variable(
            "MALTIVERSE_USER", ["maltiverse", "user"], config, False
        )
        self.passwd = get_config_variable(
            "MALTIVERSE_PASSWD", ["maltiverse", "passwd"], config, False
        )
        feeds = get_config_variable(
            "MALTIVERSE_FEEDS", ["maltiverse", "feeds"], config, False
        )
        self.feeds = feeds.split(",")

    def get_interval(self) -> int:
        return int(self.interval) * 3600

    def run(self):
        self.helper.log_info("Fetching knowledge...")
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
                    > (self.get_interval())
                ):
                    timestamp = int(time.time())
                    now = datetime.utcfromtimestamp(timestamp)
                    friendly_name = "Connector run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )

                    cli = taxiicli.Server('https://api.maltiverse.com/taxii2/',
                                          user=self.user,
                                          password=self.passwd)

                    collections = [col for col in cli.default.collections if col.id in self.feeds]

                    for col in collections:
                        try:
                            self.helper.send_stix2_bundle(
                                json.dumps(col.get_objects()),
                                update=True
                            )
                        except Exception as e:
                            self.helper.log_error("error sending collection: " + str(e))

                    # Store the current timestamp as a last run
                    self.helper.log_info(
                        "Connector successfully run, storing last_run as "
                        + str(timestamp)
                    )
                    self.helper.set_state({"last_run": timestamp})
                    message = (
                        "Last_run stored, next run in: "
                        + str(round(self.get_interval() / 60 / 60 / 24, 2))
                        + " days"
                    )
                    self.helper.api.work.to_processed(work_id, message)
                    self.helper.log_info(message)
                    time.sleep(60)
                else:
                    new_interval = self.get_interval() - (timestamp - last_run)
                    self.helper.log_info(
                        "Connector will not run, next run in: "
                        + str(round(new_interval / 60 / 60 / 24, 2))
                        + " days"
                    )
                    time.sleep(360)
            except Exception as e:
                print(e)


if __name__ == "__main__":
    try:
        connector = MaltiverseConnector()
        connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
