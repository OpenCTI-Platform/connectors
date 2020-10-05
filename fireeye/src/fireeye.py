import os
import yaml
import time
import requests
import json

from urllib.parse import urlparse, parse_qs
from dateutil.parser import parse
from requests.auth import HTTPBasicAuth
from pycti import OpenCTIConnectorHelper, get_config_variable


class FireEye:
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
        self.added_after = parse(self.fireeye_import_start_date).timestamp()

        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="FireEye",
            description="FireEye is a publicly traded cybersecurity company headquartered in Milpitas, California. It has been involved in the detection and prevention of major cyber attacks. It provides hardware, software, and services to investigate cybersecurity attacks, protect against malicious software, and analyze IT security risks. FireEye was founded in 2004.",
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
        headers = {
            "authorization": "Bearer " + self.auth_token,
            "accept": "application/vnd.oasis.stix+json; version=2.1",
            "x-app-name": "opencti-connector-4.0.0",
        }
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            return r
        elif (r.status_code == 401 or r.status_code == 403) and not retry:
            self._get_token()
            return self._query(url, True)
        elif r.status_code == 401 or r.status_code == 403:
            raise ValueError("Query failed, permission denied")
        else:
            print(r.text)
            raise ValueError("An unknown error occurred")

    def _import_collection(
        self, collection, last_id_modified_timestamp=None, last_id=None
    ):
        have_next_page = True
        url = None
        last_object = None
        while have_next_page:
            if url is None:
                if last_id_modified_timestamp is not None:
                    url = (
                        self.fireeye_api_url
                        + "/collections/"
                        + collection
                        + "/objects"
                        + "?added_after="
                        + str(self.added_after)
                        + "&length=500"
                        + "&last_id_modified_timestamp="
                        + str(last_id_modified_timestamp)
                    )
                else:
                    url = (
                        self.fireeye_api_url
                        + "/collections/"
                        + collection
                        + "/objects"
                        + "?added_after="
                        + str(self.added_after)
                        + "&length=500"
                    )
            result = self._query(url)
            parsed_result = json.loads(result.text)
            if "objects" in parsed_result and len(parsed_result) > 0:
                last_object = parsed_result["objects"][-1]
                if last_object["id"] != last_id:
                    final_objects = []
                    for stix_object in parsed_result["objects"]:
                        if "created_by_ref" not in stix_object:
                            stix_object["created_by_ref"] = self.identity["standard_id"]
                        if stix_object["type"] != "marking-definition":
                            stix_object["object_marking_refs"] = [
                                "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
                            ]
                        final_objects.append(stix_object)
                    final_bundle = {"type": "bundle", "objects": final_objects}
                    self.helper.send_stix2_bundle(
                        json.dumps(final_bundle),
                        None,
                        self.update_existing_data,
                    )
                    headers = result.headers
                    if "Link" in headers:
                        have_next_page = True
                        link = headers["Link"].split(";")
                        url = link[0][1:-1]
                        last_id_modified_timestamp = parse_qs(urlparse(url).query)[
                            "last_id_modified_timestamp"
                        ][0]
                    else:
                        have_next_page = False
                else:
                    have_next_page = False
        return {
            "last_id_modified_timestamp": last_id_modified_timestamp,
            "last_id": last_object["id"] if "id" in last_object else None,
        }

    def run(self):
        while True:
            try:
                self.helper.log_info("Synchronizing with FireEye API...")
                current_state = self.helper.get_state()
                if (
                    current_state is None
                    or "last_id_modified_timestamp" not in current_state
                ):
                    self.helper.set_state(
                        {
                            "last_id_modified_timestamp": {
                                "indicators": None,
                                "reports": None,
                            },
                            "last_id": {
                                "indicators": None,
                                "reports": None,
                            },
                        }
                    )
                    current_state = self.helper.get_state()
                last_id_modified_timestamp = current_state["last_id_modified_timestamp"]
                last_id = current_state["last_id"]
                if "indicators" in self.fireeye_collections:
                    self.helper.log_info(
                        "Get indicators created after "
                        + str(last_id_modified_timestamp["indicators"])
                    )
                    indicators_last = self._import_collection(
                        "indicators",
                        last_id_modified_timestamp["indicators"],
                        last_id["indicators"],
                    )
                    current_state = self.helper.get_state()
                    self.helper.set_state(
                        {
                            "last_id_modified_timestamp": {
                                "indicators": indicators_last[
                                    "last_id_modified_timestamp"
                                ],
                                "reports": current_state["last_id_modified_timestamp"][
                                    "reports"
                                ],
                            },
                            "last_id": {
                                "indicators": indicators_last["last_id"],
                                "reports": current_state["last_id"]["reports"],
                            },
                        }
                    )
                if "reports" in self.fireeye_collections:
                    self.helper.log_info(
                        "Get reports created after "
                        + str(last_id_modified_timestamp["reports"])
                    )
                    reports_last = self._import_collection(
                        "reports",
                        last_id_modified_timestamp["reports"],
                        last_id["reports"],
                    )
                    current_state = self.helper.get_state()
                    self.helper.set_state(
                        {
                            "last_id_modified_timestamp": {
                                "indicators": current_state[
                                    "last_id_modified_timestamp"
                                ]["indicators"],
                                "reports": reports_last["last_id_modified_timestamp"],
                            },
                            "last_id": {
                                "indicators": current_state["last_id"]["indicators"],
                                "reports": reports_last["last_id"],
                            },
                        }
                    )
                self.helper.log_info("End of synchronization")
                time.sleep(60)
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
                time.sleep(60)


if __name__ == "__main__":
    try:
        fireeyeConnector = FireEye()
        fireeyeConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
