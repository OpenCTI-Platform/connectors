import os
import yaml
import time
import requests

from dateutil.parser import parse
from datetime import datetime
from requests.auth import HTTPBasicAuth
from pycti import OpenCTIConnectorHelper, get_config_variable


class Mitre:
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
        self.fireeye_api_url = get_config_variable(
            "FIREEYE_API_URL", ["fireeye", "api_url"], config
        )
        self.fireeye_api_v3_public = get_config_variable(
            "FIREEYE_API_V3_PUBLIC", ["fireeye", "api_v3_public"], config
        )
        self.fireeye_api_v3_secret = get_config_variable(
            "FIREEYE_API_V3_SECRET", ["fireeye", "api_v3_secret"], config
        )
        self.fireeye_organization = get_config_variable(
            "FIREEYE_ORGANIZATION", ["fireeye", "organization"], config
        )
        self.fireeye_collections = get_config_variable(
            "FIREEYE_COLLECTIONS", ["fireeye", "collections"], config
        ).split(",")
        self.fireeye_import_start_date = get_config_variable(
            "FIREEYE_IMPORT_START_DATE",
            ["fireeye", "import_start_date"],
            config,
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )

        # Init variables
        self.auth_token = None
        self._get_token()

    def _get_token(self):
        r = requests.post(
            self.fireeye_api_url + "/token",
            auth=HTTPBasicAuth(self.fireeye_api_v3_public, self.fireeye_api_v3_secret),
            data={"grant_type": "client_credentials"},
        )
        if r.status_code != 200:
            raise ValueError("FireEye Authentication failed")
        data = r.json()
        self.auth_token = data.get("access_token")

    def _query(self, url, retry=False):
        print(url)
        headers = {
            "authorization": "Bearer " + self.auth_token,
            "accept": "application/vnd.oasis.stix+json; version=2.1",
            "x-app-name": "opencti-connector-4.0.0",
        }
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            return r
        elif r.status_code == 401 and not retry:
            self._get_token()
            return self._query(url, True)
        elif r.status_code == 401:
            raise ValueError("Query failed, permission denied")

    def _import_collection(self, collection, added_after):
        have_next_page = True
        url = None
        while have_next_page:
            if url is None:
                url = (
                    self.fireeye_api_url
                    + "/collections/"
                    + collection
                    + "/objects"
                    + "?added_after="
                    + str(added_after)
                )
            result = self._query(url)
            print(result.text)
            # self.helper.send_stix2_bundle(
            #    result.text,
            #    None,
            #    self.update_existing_data,
            # )
            headers = result.headers
            if "Link" in headers:
                have_next_page = True
                url = headers
            else:
                have_next_page = False

    def run(self):
        self.helper.log_info("Fetching FireEye API...")
        while True:
            try:
                current_state = self.helper.get_state()
                if (
                    current_state is None
                    or "last_element_timestamp" not in current_state
                ):
                    import_start_date = int(
                        parse(self.fireeye_import_start_date).timestamp()
                    )
                    self.helper.set_state(
                        {
                            "last_element_timestamp": {
                                "indicators": import_start_date,
                                "reports": import_start_date,
                            }
                        }
                    )
                    current_state = self.helper.get_state()
                last_element_timestamp = current_state["last_element_timestamp"]
                if "indicators" in self.fireeye_collections:
                    self.helper.log_info(
                        "Get indicators created after "
                        + str(last_element_timestamp["indicators"])
                    )
                    indicators_timestamp = self._import_collection(
                        "indicators", last_element_timestamp["indicators"]
                    )
                    current_state = self.helper.get_state()
                    self.helper.set_state(
                        {
                            "last_element_timestamp": {
                                "indicators": indicators_timestamp,
                                "reports": current_state["last_element_timestamp"][
                                    "reports"
                                ],
                            }
                        }
                    )
                if "reports" in self.fireeye_collections:
                    self.helper.log_info(
                        "Get reports created after "
                        + str(last_element_timestamp["reports"])
                    )
                    reports_timestamp = self._import_collection(
                        "reports", last_element_timestamp["reports"]
                    )
                    current_state = self.helper.get_state()
                    self.helper.set_state(
                        {
                            "last_element_timestamp": {
                                "indicators": current_state["last_element_timestamp"][
                                    "indicators"
                                ],
                                "reports": reports_timestamp,
                            }
                        }
                    )
                print("Sleep")
                time.sleep(60)
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
                time.sleep(60)


if __name__ == "__main__":
    try:
        mitreConnector = Mitre()
        mitreConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
