import os
import yaml
import time
import requests
import json
import datetime

from urllib.parse import urlparse, parse_qs
from dateutil.parser import parse
from requests.auth import HTTPBasicAuth
from pycti import OpenCTIConnectorHelper, get_config_variable


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
        self.mandiant_api_v3_public = get_config_variable(
            "MANDIANT_API_V3_PUBLIC", ["mandiant", "api_v3_public"], config
        )
        self.mandiant_api_v3_secret = get_config_variable(
            "MANDIANT_API_V3_SECRET", ["mandiant", "api_v3_secret"], config
        )
        self.mandiant_collections = get_config_variable(
            "MANDIANT_COLLECTIONS", ["mandiant", "collections"], config
        ).split(",")
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

    def get_interval(self):
        return int(self.mandiant_interval) * 60

    def _get_token(self):
        r = requests.post(
            self.mandiant_api_url + "/token",
            auth=HTTPBasicAuth(
                self.mandiant_api_v3_public, self.mandiant_api_v3_secret
            ),
            data={"grant_type": "client_credentials"},
        )
        if r.status_code != 200:
            raise ValueError("Mandiant Authentication failed")
        data = r.json()
        self.auth_token = data.get("access_token")

    def _search(self, stix_id, retry=False):
        time.sleep(3)
        self.helper.log_info("Searching for " + stix_id)
        headers = {
            "authorization": "Bearer " + self.auth_token,
            "accept": "application/vnd.oasis.stix+json; version=2.1",
            "x-app-name": "opencti-connector-5.1.1",
        }
        body = """
            {
                "queries": [
                    {
                        "type": "ENTITY_TYPE",
                        "query": "id = 'ENTITY_ID'"
                    }
                ],
                "include_connected_objects": false
            }
        """
        entity_type = stix_id.split("--")[0]
        if entity_type not in searchable_types:
            return None
        body = body.replace("ENTITY_TYPE", entity_type).replace("ENTITY_ID", stix_id)
        r = requests.post(
            self.mandiant_api_url + "/collections/search", data=body, headers=headers
        )
        if r.status_code == 200:
            return r
        elif (r.status_code == 401 or r.status_code == 403) and not retry:
            self._get_token()
            return self._search(stix_id, True)
        elif r.status_code == 204 or r.status_code == 205:
            return None
        elif r.status_code == 401 or r.status_code == 403:
            raise ValueError("Query failed, permission denied")
        else:
            print(r)
            raise ValueError("An unknown error occurred")

    def _query(self, url, retry=False):
        headers = {
            "authorization": "Bearer " + self.auth_token,
            "accept": "application/vnd.oasis.stix+json; version=2.1",
            "x-app-name": "opencti-connector-5.1.1",
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
            raise ValueError("An unknown error occurred")

    def _send_entity(self, bundle, work_id):
        if "objects" in bundle and len(bundle) > 0:
            final_objects = []
            for stix_object in bundle["objects"]:
                if "created_by_ref" not in stix_object:
                    stix_object["created_by_ref"] = self.identity["standard_id"]
                if stix_object["type"] != "marking-definition":
                    stix_object["object_marking_refs"] = [
                        "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
                    ]
                    stix_object["object_marking_refs"].append(
                        self.marking["standard_id"]
                    )
                final_objects.append(stix_object)
            final_bundle = {"type": "bundle", "objects": final_objects}
            self.helper.send_stix2_bundle(
                json.dumps(final_bundle),
                update=self.update_existing_data,
                work_id=work_id,
            )

    def _import_collection(
        self, collection, last_id_modified_timestamp=None, last_id=None, work_id=None
    ):
        have_next_page = True
        url = None
        last_object = None
        while have_next_page:
            if url is None:
                if last_id_modified_timestamp is not None:
                    url = (
                        self.mandiant_api_url
                        + "/collections/"
                        + collection
                        + "/objects"
                        + "?added_after="
                        + str(self.added_after)
                        + "&length=100"
                        + "&last_id_modified_timestamp="
                        + str(last_id_modified_timestamp)
                    )
                else:
                    url = (
                        self.mandiant_api_url
                        + "/collections/"
                        + collection
                        + "/objects"
                        + "?added_after="
                        + str(self.added_after)
                        + "&length=100"
                    )
            result = self._query(url)
            parsed_result = json.loads(result.text)
            if "objects" in parsed_result and len(parsed_result) > 0:
                last_object = parsed_result["objects"][-1]
                object_ids = [
                    stix_object["id"] for stix_object in parsed_result["objects"]
                ]
                if last_object["id"] != last_id:
                    final_objects = []
                    for stix_object in parsed_result["objects"]:
                        if stix_object["type"] == "relationship":
                            # If the source_ref is not in the current bundle
                            if stix_object["source_ref"] not in object_ids:
                                # Search entity in OpenCTI
                                opencti_entity = (
                                    self.helper.api.stix_domain_object.read(
                                        id=stix_object["source_ref"]
                                    )
                                )
                                # If the entity is not found
                                if opencti_entity is None:
                                    # Search the entity in Mandiant
                                    mandiant_entity = self._search(
                                        stix_object["source_ref"]
                                    )
                                    # If the entity is found
                                    if mandiant_entity is not None:
                                        mandiant_entity_decoded = json.loads(
                                            mandiant_entity.text
                                        )
                                        # Send the entity before this bundle
                                        self._send_entity(
                                            mandiant_entity_decoded, work_id
                                        )
                            # Search if the entity is not in bundle
                            if stix_object["target_ref"] not in object_ids:
                                opencti_entity = (
                                    self.helper.api.stix_domain_object.read(
                                        id=stix_object["target_ref"]
                                    )
                                )
                                if opencti_entity is None:
                                    mandiant_entity = self._search(
                                        stix_object["target_ref"]
                                    )
                                    if mandiant_entity is not None:
                                        mandiant_entity_decoded = json.loads(
                                            mandiant_entity.text
                                        )
                                        self._send_entity(
                                            mandiant_entity_decoded, work_id
                                        )
                        if (
                            "object_refs" in stix_object
                            and len(stix_object["object_refs"]) > 0
                        ):
                            for object_ref in stix_object["object_refs"]:
                                if object_ref not in object_ids:
                                    opencti_entity = (
                                        self.helper.api.stix_domain_object.read(
                                            id=object_ref
                                        )
                                    )
                                    if opencti_entity is None:
                                        mandiant_entity = self._search(object_ref)
                                        if mandiant_entity is not None:
                                            mandiant_entity_decoded = json.loads(
                                                mandiant_entity.text
                                            )
                                            self._send_entity(
                                                mandiant_entity_decoded, work_id
                                            )
                        if "created_by_ref" not in stix_object:
                            stix_object["created_by_ref"] = self.identity["standard_id"]
                        if stix_object["type"] != "marking-definition":
                            stix_object["object_marking_refs"] = [
                                "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
                            ]
                            stix_object["object_marking_refs"].append(
                                self.marking["standard_id"]
                            )
                        final_objects.append(stix_object)
                    final_bundle = {"type": "bundle", "objects": final_objects}
                    self.helper.send_stix2_bundle(
                        json.dumps(final_bundle),
                        update=self.update_existing_data,
                        work_id=work_id,
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
                self.helper.log_info("Synchronizing with Mandiant API...")
                timestamp = int(time.time())
                now = datetime.datetime.utcfromtimestamp(timestamp)
                friendly_name = "Mandiant run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
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
                if "indicators" in self.mandiant_collections:
                    self.helper.log_info(
                        "Get indicators created after "
                        + str(last_id_modified_timestamp["indicators"])
                    )
                    indicators_last = self._import_collection(
                        "indicators",
                        last_id_modified_timestamp["indicators"],
                        last_id["indicators"],
                        work_id,
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
                if "reports" in self.mandiant_collections:
                    self.helper.log_info(
                        "Get reports created after "
                        + str(last_id_modified_timestamp["reports"])
                    )
                    reports_last = self._import_collection(
                        "reports",
                        last_id_modified_timestamp["reports"],
                        last_id["reports"],
                        work_id,
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
