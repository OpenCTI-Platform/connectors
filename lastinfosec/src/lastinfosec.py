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
            "CONFIG_LIS_URL_CTI", ["lastinfosec", "api_url_cti"], config
        )
        self.lastinfosec_apikey = get_config_variable(
            "CONFIG_LIS_APIKEY_CTI", ["lastinfosec", "api_key_cti"], config
        )
        self.opencti_url = get_config_variable(
            "OPENCTI_URL", ["opencti", "url"], config
        )
        self.opencti_id = get_config_variable(
            "OPENCTI_TOKEN", ["opencti", "token"], config
        )
        self.proxy_http = get_config_variable(
            "PROXY_HTTP", ["opencti", "proxy_http"], config
        )
        self.proxy_https = get_config_variable(
            "PROXY_HTTPS", ["opencti", "proxy_https"], config
        )
        self.update_existing_data = True
        self.api = OpenCTIApiClient(self.opencti_url, self.opencti_id)

    def push_data(self, lastinfosec_data, timestamp, work_id):
        if "message" in lastinfosec_data.keys():
            for data in lastinfosec_data["message"]:
                sdata = json.dumps(data)
                self.helper.send_stix2_bundle(sdata, work_id=work_id)
                # Store the current timestamp as a last run
                message = ("Connector successfully run, storing last_run as {0}".format(timestamp))
                self.helper.set_state({"last_run": timestamp})
                self.helper.api.work.to_processed(work_id, message)
                self.helper.log_info(message)
        else:
            message = ("Connector error run, storing last_run as {0}".format(timestamp))
            self.helper.set_state({"last_run": timestamp})
            self.helper.api.work.to_processed(work_id, message)
            self.helper.log_info(message)
            time.sleep(300)

    def run(self):
        self.helper.log_info("Fetching lastinfosec datasets...")
        while True:
            try:
                # Get the current timestamp and check
                timestamp = int(time.time())
                now = datetime.datetime.utcfromtimestamp(timestamp)
                friendly_name = "LastInfoSec CTI run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )

                proxy_dic = {}
                if self.proxy_http is not None:
                    proxy_dic["http"] = self.proxy_http
                if self.proxy_https is not None:
                    proxy_dic["https"] = self.proxy_https
                
                if self.lastinfosec_url is not None and self.lastinfosec_apikey is not None:
                    lastinfosec_data = requests.get(self.lastinfosec_url + self.lastinfosec_apikey,
                                                    proxies=proxy_dic).json()
                    self.push_data(lastinfosec_data, timestamp, work_id)
                else:
                    self.helper.log_info("CTI Feed not configured")
                time.sleep(3500)
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
        time.sleep(100)
        exit(0)
