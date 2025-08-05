import builtins
import json
import sys
import time
from datetime import datetime

import requests
from bs4 import BeautifulSoup
from pycti import OpenCTIConnectorHelper
from threatmatch.config import ConnectorSettings


class Connector:
    def __init__(self, helper: OpenCTIConnectorHelper, config: ConnectorSettings):
        self.helper = helper
        self.config = config
        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="Security Alliance",
            description="Security Alliance is a cyber threat intelligence product and services company, formed in 2007.",
        )

    def get_interval(self):
        return int(self.config.threatmatch.interval) * 60

    def next_run(self, seconds):
        return

    def _get_token(self):
        r = requests.post(
            self.config.threatmatch.url + "/api/developers-platform/token",
            json={
                "client_id": self.config.threatmatch.client_id,
                "client_secret": self.config.threatmatch.client_secret,
            },
        )
        if r.status_code != 200:
            raise ValueError("ThreatMatch Authentication failed")
        data = r.json()
        return data.get("access_token")

    def _get_item(self, token, type, item_id):
        headers = {"Authorization": "Bearer " + token}
        r = requests.get(
            self.config.threatmatch.url + "/api/stix/" + type + "/" + str(item_id),
            headers=headers,
        )
        if r.status_code != 200:
            self.helper.connector_logger.error(str(r.text))
            return []
        if r.status_code == 200:
            data = r.json()["objects"]
            for object in data:
                object["description"] = BeautifulSoup(
                    object.get("description", ""), "html.parser"
                ).get_text()
            return data

    def _process_list(self, work_id, token, type, list):
        if len(list) > 0:
            if builtins.type(list[0]) is dict:
                bundle = list
                self._process_bundle(work_id, bundle)
            else:
                for item in list:
                    bundle = self._get_item(token, type, item)
                    self._process_bundle(work_id, bundle)

    def _process_bundle(self, work_id, bundle):
        if len(bundle) > 0:
            final_objects = []
            for stix_object in bundle:
                if "error" in stix_object:
                    continue
                if "created_by_ref" not in stix_object:
                    stix_object["created_by_ref"] = self.identity["standard_id"]
                if "object_refs" in stix_object and stix_object["type"] not in [
                    "report",
                    "note",
                    "opinion",
                    "observed-data",
                ]:
                    del stix_object["object_refs"]
                    pass
                final_objects.append(stix_object)
                final_bundle = {"type": "bundle", "objects": final_objects}
                final_bundle_json = json.dumps(final_bundle)
                self.helper.send_stix2_bundle(final_bundle_json, work_id=work_id)

    def run(self):
        self.helper.connector_logger.info("Fetching ThreatMatch...")
        while True:
            try:
                # Get the current timestamp and check
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    self.helper.connector_logger.info(
                        "Connector last run: "
                        + datetime.utcfromtimestamp(last_run).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )
                else:
                    last_run = None
                    self.helper.connector_logger.info("Connector has never run")
                # If the last_run is more than interval-1 day
                if last_run is None or (
                    (timestamp - last_run)
                    > ((int(self.config.threatmatch.interval) - 1) * 60)
                ):
                    self.helper.connector_logger.info("Connector will run!")
                    now = datetime.utcfromtimestamp(timestamp)
                    friendly_name = "ThreatMatch run @ " + now.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )
                    try:
                        token = self._get_token()
                        import_from_date = "2010-01-01 00:00"
                        if last_run is not None:
                            import_from_date = datetime.utcfromtimestamp(
                                last_run
                            ).strftime("%Y-%m-%d %H:%M")
                        elif self.config.threatmatch.import_from_date is not None:
                            import_from_date = self.config.threatmatch.import_from_date

                        headers = {"Authorization": "Bearer " + token}
                        if self.config.threatmatch.import_profiles:
                            r = requests.get(
                                self.config.threatmatch.url + "/api/profiles/all",
                                headers=headers,
                                json={
                                    "mode": "compact",
                                    "date_since": import_from_date,
                                },
                            )
                            if r.status_code != 200:
                                self.helper.connector_logger.error(str(r.text))
                            data = r.json()
                            self._process_list(
                                work_id, token, "profiles", data.get("list")
                            )
                        if self.config.threatmatch.import_alerts:
                            r = requests.get(
                                self.config.threatmatch.url + "/api/alerts/all",
                                headers=headers,
                                json={
                                    "mode": "compact",
                                    "date_since": import_from_date,
                                },
                            )
                            if r.status_code != 200:
                                self.helper.connector_logger.error(str(r.text))
                            data = r.json()
                            self._process_list(
                                work_id, token, "alerts", data.get("list")
                            )
                        if self.config.threatmatch.import_iocs:
                            response = requests.get(
                                self.config.threatmatch.url + "/api/taxii/groups",
                                headers=headers,
                            ).json()
                            all_results_id = response[0]["id"]
                            date = datetime.strptime(import_from_date, "%Y-%m-%d %H:%M")
                            date = date.isoformat(timespec="milliseconds") + "Z"
                            params = {
                                "groupId": all_results_id,
                                "stixTypeName": "indicator",
                                "modifiedAfter": date,
                            }
                            r = requests.get(
                                self.config.threatmatch.url + "/api/taxii/objects",
                                headers=headers,
                                params=params,
                            )
                            if r.status_code != 200:
                                self.helper.connector_logger.error(str(r.text))
                            more = r.json()["more"]
                            if not more:
                                data = r.json()["objects"]
                            else:
                                data = []
                            # This bit is necessary to load all the indicators to upload by checking by date
                            while more:
                                params["modifiedAfter"] = date
                                r = requests.get(
                                    self.config.threatmatch.url + "/api/taxii/objects",
                                    headers=headers,
                                    params=params,
                                )
                                if r.status_code != 200:
                                    self.helper.connector_logger.error(str(r.text))
                                data.extend(r.json().get("objects", []))
                                date = r.json()["objects"][-1]["modified"]
                                more = r.json().get("more", False)
                            self.helper.connector_logger.info(data)
                            self._process_list(work_id, token, "indicators", data)
                    except Exception as e:
                        self.helper.connector_logger.error(str(e))
                    # Store the current timestamp as a last run
                    message = "Connector successfully run, storing last_run as " + str(
                        timestamp
                    )
                    self.helper.connector_logger.info(message)
                    self.helper.set_state({"last_run": timestamp})
                    self.helper.api.work.to_processed(work_id, message)
                    self.helper.connector_logger.info(
                        "Last_run stored, next run in: "
                        + str(round(self.get_interval() / 60, 2))
                        + " minutes"
                    )
                else:
                    new_interval = self.get_interval() - (timestamp - last_run)
                    self.helper.connector_logger.info(
                        "Connector will not run, next run in: "
                        + str(round(new_interval / 60 / 60 / 24, 2))
                        + " days"
                    )

            except (KeyboardInterrupt, SystemExit):
                self.helper.connector_logger.info("Connector stop")
                sys.exit(0)

            except Exception as e:
                self.helper.connector_logger.error(str(e))

            if self.helper.connect_run_and_terminate:
                self.helper.connector_logger.info("Connector stop")
                sys.exit(0)

            time.sleep(60)
