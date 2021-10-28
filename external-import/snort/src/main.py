import os
import re
import time
import yaml
from datetime import datetime, timedelta
from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2.v21 import (Sighting, IPv4Address)


class SnortImportConnector:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.process_interval = get_config_variable(
            "CONNECTOR_PROCESS_INTERVAL", ["connnector", "process_interval"], config, True
        )
        self.alert_priority = get_config_variable(
            "CONNECTOR_MIN_SNORT_PRIORITY", ["connector", "min_snort_priority"], config, True
        )
        # 09/10-15:31:47.157478  [**] [129:12:2] Consecutive TCP small segments exceeding threshold [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 192.168.51.138:3406 -> 192.168.51.135:22
        self.fast_alert_pattern = re.compile("(?P<timestamp>[0-9]{1,2}/[0-9]{1,2}-[0-9]{1,2}:[0-9]{2}:[0-9]{2}.{[" +
                                             "0-9]{6})  \[\*\*] \[(?P<snortdata>[0-9:]*)] (?P<description>.*) \[\*\*] " +
                                             "[Classification: (?P<classification>[^]]*)] [Priority: (?P<priority>[" +
                                             "0-9]{1,3})] {(?P<protocol>[A-Za-z]*)} (?P<source_ip>[0-9]{1," +
                                             "3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})[:]?(?P<source_port>[0-9]{1," +
                                             "5})? (?P<direction_ind>[<>-]{2}) (?P<destination_ip>[0-9]{1," +
                                             "3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})[:]?(?P<destination_port>[" +
                                             "0-9]{1,5})?")

    def get_interval(self):
        return int(self.process_interval)

    def next_run(self, seconds):
        return

    def run(self):
        print("Connector starting...")
        self.helper.log_info("Connector searching for more data...")
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
                        > (int(self.process_interval) - 1)
                ):
                    self.helper.log_info("Connector will run!")
                    now = datetime.utcfromtimestamp(timestamp)
                    friendly_name = "Connector run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )

                    for entry in os.scandir("/opt/opencti-connector-snort/import"):
                        if entry.is_file():
                            with open(entry.path) as alert_log:
                                while True:
                                    line = alert_log.readline()

                                    if not line:
                                        break

                                    self.helper.log_debug(f"Processing line {line}")
                                    line_match = re.match(self.fast_alert_pattern, line).groupdict()
                                    self.helper.log_debug(f"Found {line_match}")

                                    if int(line_match["priority"]) >= self.alert_priority:
                                        self.helper.log_debug(f"Priority >= {self.alert_priority}")

                                        sighting = Sighting(

                                        )

                    self.helper.log_info(
                        "Connector successfully run, storing last_run as "
                        + str(timestamp)
                    )
                    self.helper.set_state({"last_run": timestamp})

                    time.sleep(self.process_interval)
                else:
                    new_interval = self.get_interval() - (timestamp - last_run)
                    self.helper.log_info(
                        "Connector will not run, next run in: "
                        + str(new_interval)
                        + " seconds"
                    )
                    time.sleep(new_interval)
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
                time.sleep(60)


if __name__ == "__main__":
    try:
        connector = SnortImportConnector()
        connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
