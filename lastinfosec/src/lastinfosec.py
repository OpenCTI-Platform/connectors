import os
import yaml
import time
import requests
import json
import datetime

from pycti import OpenCTIConnectorHelper, get_config_variable, OpenCTIApiClient


class LastInfoSec:
    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.lastinfosec_url = get_config_variable(
            "CONFIG_LIS_URL", ["lastinfosec", "api_url"], config
        )
        self.lastinfosec_apikey = get_config_variable(
            "CONFIG_LIS_APIKEY", ["lastinfosec", "api_key"], config
        )
        self.opencti_url = get_config_variable(
            "OPENCTI_URL", ["opencti", "url"], config
        )
        self.opencti_id = get_config_variable(
            "OPENCTI_TOKEN", ["opencti", "token"], config
        )
        self.update_existing_data = True
        self.api = OpenCTIApiClient(self.opencti_url, self.opencti_id)

    def run(self):
        self.helper.log_info("Fetching lastinfosec datasets...")
        while True:
            try:
                # Get the current timestamp and check
                timestamp = int(time.time())
                now = datetime.datetime.utcfromtimestamp(timestamp)
                friendly_name = "MITRE run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                lastinfosec_data = requests.get(
                    self.lastinfosec_url + self.lastinfosec_apikey
                ).json()
                if "message" in lastinfosec_data.keys():
                    for data in lastinfosec_data["message"]:
                        sdata = json.dumps(data)
                        self.helper.send_stix2_bundle(sdata, work_id=work_id)
                    # Store the current timestamp as a last run
                    message = (
                        "Connector successfully run, storing last_run as {0}".format(
                            timestamp
                        )
                    )
                    self.helper.set_state({"last_run": timestamp})
                    self.helper.api.work.to_processed(work_id, message)
                    self.helper.log_info(message)
                    time.sleep(3500)
                else:
                    message = "Connector successfully run, storing last_run as {0}".format(
                            timestamp
                        )
                    self.helper.set_state({"last_run": timestamp})
                    self.helper.api.work.to_processed(work_id, message)
                    self.helper.log_info(message)
                    time.sleep(300)
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                exit(0)
            except Exception as e:
                self.helper.log_error("run:" + str(e))
                time.sleep(60)


if __name__ == "__main__":
    try:
        lastInfoSecConnector = LastInfoSec()
        lastInfoSecConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
