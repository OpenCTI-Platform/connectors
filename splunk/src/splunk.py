#!/usr/bin/env python3

import os
import yaml
import time

import splunklib.client as client
import splunklib.results as results

from datetime import datetime
from pycti import OpenCTIConnectorHelper, get_config_variable

class Splunk:
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
        self.splunk_host = get_config_variable(
            "SPLUNK_HOST", ["splunk", "splunk_host"], config
        )
        self.splunk_port = get_config_variable(
            "SPLUNK_PORT", ["splunk", "splunk_port"], config
        )
        self.splunk_username = get_config_variable(
            "SPLUNK_USERNAME", ["splunk", "splunk_username"], config
        )
        self.splunk_connector_password = get_config_variable(
            "SPLUNK_CONNECTOR_PASSWORD", ["splunk", "splunk_connector_password"], config
        )
        self.splunk_indexes = get_config_variable(
            "SPLUNK_INDEXES", ["splunk", "splunk_indexes"], config
        )
        self.splunk_interval = get_config_variable(
            "CONFIG_INTERVAL", ["splunk", "interval"], config, True
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )

    def export_splunk_to_json(self,indexes,host,port,username,password):
        #connecting to the server
        service = client.connect(
            host=host,
            port=port,
            username=username,
            password=password
        )
        #self.helper.log_info("indexname=" + index_name + " host=" + host + " port:" + str(port)
        #+ " username=" + username + " password=" + password)

        indexes_list = indexes.split(",")
        for index_name in indexes_list:
            self.helper.log_info("Fetching '" + index_name + "' index events...")
            search_query = "search index=" + index_name
            job = service.jobs.create(search_query)
            while not job.is_ready():
                self.helper.log_info("Job not ready")
                time.sleep(5)
            else:
                self.helper.log_info("Job ready!")
                
                reader = results.ResultsReader(job.results())

                result = ""
                found = True
                item = None
                for item in reader:
                    #_raw contains the stix data
                    result = result + item["_raw"] + ","
                if item is None:
                    self.helper.log_error("Index '" + index_name + "' not found or has no events")
                    found = False
                if (found):
                    result = result[:-1]
                    result = '{\n"objects": [\n' + result + "\n]\n}"
                    #self.helper.log_info(result)
                    self.helper.send_stix2_bundle(
                                result,
                                entities_types=self.helper.connect_scope,
                                update=self.update_existing_data,
                    )               

    def get_interval(self):
        return int(self.splunk_interval) * 60 * 60 * 24

    def run(self):
        self.helper.log_info("Fetching Splunk datasets...")
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
                    > ((int(self.splunk_interval) - 1) * 60 * 60 * 24)
                ):
                    self.helper.log_info("Connector will run!")
                    # Getting data from Splunk
                    self.helper.log_info("Requesting the index " + self.splunk_indexes)
                    self.export_splunk_to_json(self.splunk_indexes,
                                                self.splunk_host,
                                                self.splunk_port,
                                                self.splunk_username,
                                                self.splunk_connector_password
                    )     
                    # Store the current timestamp as a last run
                    self.helper.log_info(
                        "Connector successfully run, storing last_run as "
                        + str(timestamp)
                    )
                    self.helper.set_state({"last_run": timestamp})
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
        splunkConnector = Splunk()
        splunkConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
