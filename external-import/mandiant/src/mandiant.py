import datetime
import json
import os
import time
import requests
import yaml
import stix2

from dateutil.parser import parse
from pycti import OpenCTIConnectorHelper, get_config_variable
from requests.auth import HTTPBasicAuth

searchable_types = [
    "threat-actor",
    "malware",
    "autonomous-system",
    "email-message",
    "x-mandiant-com-cpe",
    "ipv4-addr",
    "vulnerability",
    "indicator",
    "artifact",
    "x-mandiant-com-exploit",
    "domain-name",
    "url",
    "email-addr",
    "windows-registry-key",
    "x-mandiant-com-weakness",
    "location",
    "file",
    "report",
    "x-mandiant-com-exploitation",
    "identity",
    "all",
]


class Mandiant:
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
        self.mandiant_api_url = get_config_variable(
            "MANDIANT_API_URL", ["mandiant", "api_url"], config
        )
        self.mandiant_api_v4_key_id = get_config_variable(
            "MANDIANT_API_V4_KEY_ID", ["mandiant", "api_v4_key_id"], config
        )
        self.mandiant_api_v4_key_secret = get_config_variable(
            "MANDIANT_API_V4_KEY_SECRET", ["mandiant", "api_v4_key_secret"], config
        )
        self.mandiant_collections = get_config_variable(
            "MANDIANT_COLLECTIONS", ["mandiant", "collections"], config
        ).split(",")
        self.mandiant_threat_actor_as_intrusion_set = get_config_variable(
            "MANDIANT_THREAT_ACTOR_AS_INTRUSION_SET",
            ["mandiant", "threat_actor_as_intrusion_set"],
            config,
            False,
            True,
        )
        self.mandiant_import_start_date = get_config_variable(
            "MANDIANT_IMPORT_START_DATE",
            ["mandiant", "import_start_date"],
            config,
        )
        self.mandiant_interval = get_config_variable(
            "MANDIANT_INTERVAL", ["mandiant", "interval"], config, True
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )
        self.added_after = parse(self.mandiant_import_start_date).timestamp()

        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="Mandiant",
            description="Mandiant is recognized by enterprises, governments and law enforcement agencies worldwide as the market leader in threat intelligence and expertise gained on the frontlines of cyber security. ",
        )

        self.marking = self.helper.api.marking_definition.create(
            definition_type="COMMERCIAL",
            definition="MANDIANT",
            x_opencti_order=99,
            x_opencti_color="#a01526",
        )

        # Init variables
        self.auth_token = None
        self._get_token()
        self.cache = {}

    def get_interval(self):
        return int(self.mandiant_interval) * 60

    def _get_token(self):
        headers = {
            "accept": "application/json",
            "x-app-name": "opencti-connector-5.2.4",
        }
        r = requests.post(
            self.mandiant_api_url + "/token",
            auth=HTTPBasicAuth(
                self.mandiant_api_v4_key_id, self.mandiant_api_v4_key_secret
            ),
            data={"grant_type": "client_credentials"},
            headers=headers,
        )
        if r.status_code != 200:
            raise ValueError("Mandiant Authentication failed")
        data = r.json()
        self.auth_token = data.get("access_token")

    def _query(self, url, limit=None, offset=None, retry=False):
        headers = {
            "authorization": "Bearer " + self.auth_token,
            "accept": "application/json",
            "x-app-name": "opencti-connector-5.2.4",
        }
        params = {}
        if limit is not None:
            params["limit"] = str(limit)
        if offset is not None:
            params["offset"] = str(offset)
        r = requests.get(url, params=params, headers=headers)
        if r.status_code == 200:
            return r.json()
        elif (r.status_code == 401 or r.status_code == 403) and not retry:
            self._get_token()
            return self._query(url, True)
        elif r.status_code == 401 or r.status_code == 403:
            raise ValueError("Query failed, permission denied")
        else:
            raise ValueError("An unknown error occurred")

    def _import_actor(self, work_id, current_state):
        url = self.mandiant_api_url + "/v4/actor"
        no_more_result = False
        limit = 30
        offset = current_state["actor"]
        while no_more_result is False:
            self.helper.log_info(
                "Iterating with limit=" + str(limit) + " and offset=" + str(offset)
            )
            result = self._query(url, limit, offset)
            if len(result["threat-actors"]) > 0:
                actors = []
                for actor in result["threat-actors"]:
                    if self.mandiant_threat_actor_as_intrusion_set:
                        actor["type"] = "intrusion-set"
                        actor["id"] = actor["id"].replace(
                            "threat-actor", "intrusion-set"
                        )
                    else:
                        actor["type"] = "threat-actor"
                    actor["created_by_ref"] = self.identity["standard_id"]
                    actor["object_marking_refs"] = [
                        stix2.TLP_AMBER.get("id"),
                        self.marking["id"],
                    ]
                    actors.append(actor)
                self.helper.send_stix2_bundle(
                    json.dumps({"type": "bundle", "objects": actors}),
                    update=self.update_existing_data,
                    work_id=work_id,
                )
                current_state["actor"] = offset + result["total_count"]
                offset = offset + limit
            else:
                no_more_result = True
        return current_state

    def _import_malware(self, work_id, current_state):
        url = self.mandiant_api_url + "/v4/malware"
        no_more_result = False
        limit = 10
        offset = current_state["malware"]
        while no_more_result is False:
            self.helper.log_info(
                "Iterating with limit=" + str(limit) + " and offset=" + str(offset)
            )
            result = self._query(url, limit, offset)
            if len(result["malware"]) > 0:
                malwares = []
                for malware in result["malware"]:
                    malware["type"] = "malware"
                    malware["created_by_ref"] = self.identity["standard_id"]
                    malware["object_marking_refs"] = [
                        stix2.TLP_AMBER.get("id"),
                        self.marking["id"],
                    ]
                    malwares.append(malware)
                self.helper.send_stix2_bundle(
                    json.dumps({"type": "bundle", "objects": malwares}),
                    update=self.update_existing_data,
                    work_id=work_id,
                )
                current_state["malware"] = offset + result["total_count"]
                self.helper.set_state(current_state)
                offset = offset + limit
            else:
                no_more_result = True
        return current_state

    def run(self):
        while True:
            try:
                self.helper.log_info("Synchronizing with Mandiant API...")
                timestamp = int(time.time())
                now = datetime.datetime.utcfromtimestamp(timestamp)
                friendly_name = "Mandiant run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                current_state = self.helper.get_state()
                if current_state is None:
                    self.helper.set_state(
                        {
                            "actor": 0,
                            "malware": 0,
                            "indicator": 0,
                            "vulnerability": 0,
                            "report": 0,
                        }
                    )

                if "actor" in self.mandiant_collections:
                    current_state = self.helper.get_state()
                    self.helper.log_info(
                        "Get ACTOR after position " + str(current_state["actor"])
                    )
                    new_state = self._import_actor(work_id, current_state)
                    self.helper.set_state(new_state)
                if "malware" in self.mandiant_collections:
                    current_state = self.helper.get_state()
                    self.helper.log_info(
                        "Get MALWARE after position " + str(current_state["malware"])
                    )
                    new_state = self._import_malware(work_id, current_state)
                    self.helper.set_state(new_state)
                # if "indicator" in self.mandiant_collections:
                #     current_state = self.helper.get_state()
                #     self.helper.log_info(
                #         "Get INDICATOR after position "
                #         + str(current_state["indicator"])
                #     )
                #     new_state = self._import_indicator(current_state)
                #     self.helper.set_state(new_state)
                # if "vulnerability" in self.mandiant_collections:
                #     current_state = self.helper.get_state()
                #     self.helper.log_info(
                #         "Get VULNERABILITY after position "
                #         + str(current_state["vulnerability"])
                #     )
                #     new_state = self._import_vulnerability(current_state)
                #     self.helper.set_state(new_state)
                # if "report" in self.mandiant_collections:
                #     current_state = self.helper.get_state()
                #     self.helper.log_info(
                #         "Get ACTOR after position " + str(current_state["actor"])
                #     )
                #     new_state = self._import_report(current_state)
                #     self.helper.set_state(new_state)

                message = "End of synchronization"
                self.helper.api.work.to_processed(work_id, message)
                self.helper.log_info(message)
                time.sleep(self.get_interval())
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
                time.sleep(60)


if __name__ == "__main__":
    try:
        mandiantConnector = Mandiant()
        mandiantConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
