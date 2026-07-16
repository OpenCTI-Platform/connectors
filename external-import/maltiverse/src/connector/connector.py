import json
import time
from datetime import datetime, timezone

import taxii2client.v21 as taxiicli
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper


class MaltiverseConnector:
    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        # Keep existing runtime attributes for minimal changes in the rest of the class
        self.interval = self.config.maltiverse.poll_interval
        self.user = self.config.maltiverse.user
        self.passwd = self.config.maltiverse.passwd
        feeds = self.config.maltiverse.feeds or ""
        self.feeds = [f.strip() for f in feeds.split(",") if f.strip()]

    def get_interval(self) -> int:
        return int(self.interval) * 3600

    def run(self):
        self.helper.log_info("Fetching knowledge...")
        while True:
            try:
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    self.helper.log_info(
                        "Connector last run: "
                        + datetime.fromtimestamp(last_run, tz=timezone.utc).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )
                else:
                    last_run = None
                    self.helper.log_info("Connector has never run")

                if last_run is None or timestamp - last_run > self.get_interval():
                    timestamp = int(time.time())
                    now = datetime.fromtimestamp(timestamp, tz=timezone.utc)
                    friendly_name = "Connector run @ " + now.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )

                    cli = taxiicli.Server(
                        "https://api.maltiverse.com/taxii2/",
                        user=self.user,
                        password=self.passwd,
                    )
                    collections = [
                        col for col in cli.default.collections if col.id in self.feeds
                    ]
                    for col in collections:
                        try:
                            self.helper.send_stix2_bundle(
                                json.dumps(col.get_objects()), work_id=work_id
                            )
                        except Exception as e:
                            self.helper.log_error("error sending collection: " + str(e))

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
                self.helper.log_error(str(e))
