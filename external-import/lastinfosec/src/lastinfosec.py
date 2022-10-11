import datetime
import json
import os
import sys
import time

import requests
import yaml
from pycti import OpenCTIApiClient, OpenCTIConnectorHelper, get_config_variable


class LastInfoSec:
    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        self.lastinfosec_cti_url = "https://api.client.lastinfosec.com/v2/stix21/getbyminutes/{}?api_key={}&headers=false&platform=opencti"
        self.lastinfosec_cve_url = "https://api.client.lastinfosec.com/v2/stix21/vulnerabilities/getlasthour?api_key={}&headers=false&platform=opencti"
        self.lastinfosec_tactic_url = "https://api.client.lastinfosec.com/v2/stix21/tactic/getlast24hour?api_key={}&headers=false&platform=opencti"
        self.lastinfosec_apikey = get_config_variable(
            "CONFIG_LIS_APIKEY", ["lastinfosec", "api_key"], config
        )

        self.lastinfosec_cti_enabled = get_config_variable(
            "CONFIG_LIS_CTI_ENABLED", ["lastinfosec", "cti", "is_enabled"], config
        )
        self.lastinfosec_cti_interval = get_config_variable(
            "CONFIG_LIS_CTI_INTERVAL", ["lastinfosec", "cti", "interval"], config
        )

        self.lastinfosec_cve_enabled = get_config_variable(
            "CONFIG_LIS_CVE_ENABLED", ["lastinfosec", "cve", "is_enabled"], config
        )

        self.lastinfosec_tactic_enabled = get_config_variable(
            "CONFIG_LIS_TACTIC_ENABLED", ["lastinfosec", "tactic", "is_enabled"], config
        )

        self.opencti_url = get_config_variable(
            "OPENCTI_URL", ["opencti", "url"], config
        )
        self.opencti_id = get_config_variable(
            "OPENCTI_TOKEN", ["opencti", "token"], config
        )
        self.update_existing_data = get_config_variable(
            "OPENCTI_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )
        self.proxy_http = get_config_variable(
            "PROXY_HTTP", ["opencti", "proxy_http"], config
        )
        self.proxy_https = get_config_variable(
            "PROXY_HTTPS", ["opencti", "proxy_https"], config
        )

        total_enabled = 0
        if self.lastinfosec_cti_enabled:
            total_enabled += 1
        if self.lastinfosec_cve_enabled:
            total_enabled += 1
        if self.lastinfosec_tactic_enabled:
            total_enabled += 1

        if total_enabled == 0:
            raise Exception("You must enable one feed")
        elif total_enabled > 1:
            raise Exception("You can enable only one feed per connector")

        self.api = OpenCTIApiClient(self.opencti_url, self.opencti_id)

    def run(self):
        self.helper.log_info("Fetching lastinfosec datasets...")
        if not self.helper.get_run_and_terminate():
            while True:
                time_to_sleep = self.process_data()
                time.sleep(time_to_sleep)
        else:
            self.process_data()

    def process_data(self):
        time_to_sleep = 0
        try:
            if (
                self.lastinfosec_cti_enabled
                and self.lastinfosec_cti_url is not None
                and self.lastinfosec_apikey is not None
            ):
                url = self.lastinfosec_cti_url.format(
                    self.lastinfosec_cti_interval, self.lastinfosec_apikey
                )
                run_interval = self.lastinfosec_cti_interval * 60
                time_to_sleep = self.fetch_data(url, run_interval)
            elif (
                self.lastinfosec_cve_enabled
                and self.lastinfosec_cve_url is not None
                and self.lastinfosec_apikey is not None
            ):
                url = self.lastinfosec_cve_url.format(self.lastinfosec_apikey)
                run_interval = 3600  # 1h in second
                time_to_sleep = self.fetch_data(url, run_interval)
            elif (
                self.lastinfosec_tactic_enabled
                and self.lastinfosec_tactic_url is not None
                and self.lastinfosec_apikey is not None
            ):
                url = self.lastinfosec_tactic_url.format(self.lastinfosec_apikey)
                run_interval = 86400  # 24h in second
                time_to_sleep = self.fetch_data(url, run_interval)
            else:
                self.helper.log_info("CTI Feed not configured")
                time.sleep(60)
                sys.exit(0)
        except (KeyboardInterrupt, SystemExit):
            self.helper.log_info("Connector stop")
            sys.exit(0)
        except Exception as e:
            self.helper.log_error("run:" + str(e))
            time.sleep(60)

        return time_to_sleep

    def fetch_data(self, url: str, run_interval: int):
        # Get the current timestamp and check
        start = time.perf_counter()
        time_to_sleep = 0
        timestamp = int(time.time())
        now = datetime.datetime.utcfromtimestamp(timestamp)

        proxy_dic = {}
        if self.proxy_http is not None:
            proxy_dic["http"] = self.proxy_http
        if self.proxy_https is not None:
            proxy_dic["https"] = self.proxy_https

        req = requests.get(url, proxies=proxy_dic)
        if req.status_code == 200:
            lastinfosec_data = req.json()
            if isinstance(lastinfosec_data, list) and len(lastinfosec_data) > 0:
                friendly_name = "LastInfoSec CTI run @ " + now.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                self.push_data(lastinfosec_data, timestamp, work_id)
            stop = time.perf_counter()
            process_time_seconds = stop - start
            time_to_sleep = run_interval - process_time_seconds
        else:
            message = "Connector error run, storing last_run as {0}".format(timestamp)
            self.helper.set_state({"last_run": timestamp})
            self.helper.log_info(message)
            time.sleep(150)

        return time_to_sleep

    def push_data(self, bundles, timestamp, work_id):
        for bundle in bundles:
            sdata = json.dumps(bundle)
            self.helper.send_stix2_bundle(sdata, work_id=work_id)
            # Store the current timestamp as a last run
            message = "Connector successfully run, storing last_run as {0}".format(
                timestamp
            )
            self.helper.set_state({"last_run": timestamp})
            self.helper.api.work.to_processed(work_id, message)
            self.helper.log_info(message)


if __name__ == "__main__":
    try:
        lastInfoSecConnector = LastInfoSec()
        lastInfoSecConnector.run()
    except Exception as e:
        print(e)
        time.sleep(100)
        sys.exit(0)
