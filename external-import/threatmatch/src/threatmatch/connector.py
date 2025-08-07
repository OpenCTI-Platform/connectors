import builtins
import json
import sys
import time
from datetime import UTC, datetime
from typing import Any

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
        return int(self.config.connector.duration_period.total_seconds())

    def next_run(self, seconds):
        return

    def _get_token(self):
        r = requests.post(
            self.config.threatmatch.url.encoded_string()
            + "/api/developers-platform/token",
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
            self.config.threatmatch.url.encoded_string()
            + "/api/stix/"
            + type
            + "/"
            + str(item_id),
            headers=headers,
        )
        if r.status_code != 200:
            self.helper.connector_logger.error(str(r.text))
            return []
        if r.status_code == 200:
            data = r.json()["objects"]
            for object in data:
                if "description" in object and object["description"]:
                    object["description"] = BeautifulSoup(
                        object["description"], "html.parser"
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

    def _collect_intelligence(self, last_run: int, work_id: str) -> None:
        import_from_date = "2010-01-01 00:00"
        if last_run is not None:
            import_from_date = datetime.fromtimestamp(last_run, tz=UTC).strftime(
                "%Y-%m-%d %H:%M"
            )
        elif self.config.threatmatch.import_from_date is not None:
            import_from_date = self.config.threatmatch.import_from_date

        token = self._get_token()
        headers = {"Authorization": "Bearer " + token}
        if self.config.threatmatch.import_profiles:
            r = requests.get(
                self.config.threatmatch.url.encoded_string() + "/api/profiles/all",
                headers=headers,
                json={
                    "mode": "compact",
                    "date_since": import_from_date,
                },
            )
            if r.status_code != 200:
                self.helper.connector_logger.error(str(r.text))
            data = r.json()
            self._process_list(work_id, token, "profiles", data.get("list"))
        if self.config.threatmatch.import_alerts:
            r = requests.get(
                self.config.threatmatch.url.encoded_string() + "/api/alerts/all",
                headers=headers,
                json={
                    "mode": "compact",
                    "date_since": import_from_date,
                },
            )
            if r.status_code != 200:
                self.helper.connector_logger.error(str(r.text))
            data = r.json()
            self._process_list(work_id, token, "alerts", data.get("list"))
        if self.config.threatmatch.import_iocs:
            response = requests.get(
                self.config.threatmatch.url.encoded_string() + "/api/taxii/groups",
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
                self.config.threatmatch.url.encoded_string() + "/api/taxii/objects",
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
                    self.config.threatmatch.url.encoded_string() + "/api/taxii/objects",
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

    @property
    def state(self) -> dict[str, Any]:
        return self.helper.get_state() or {}

    def _get_last_run(self) -> int | None:
        if last_run := self.state.get("last_run"):
            self.helper.connector_logger.info(
                "Connector last run: "
                + datetime.fromtimestamp(last_run, tz=UTC).strftime("%Y-%m-%d %H:%M:%S")
            )
        else:
            self.helper.connector_logger.info("Connector has never run")
        return last_run

    def _process_data(self):
        # Get the current timestamp and check
        timestamp = int(time.time())
        last_run = self._get_last_run()

        self.helper.connector_logger.info("Connector will run!")
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id,
            "ThreatMatch run @ "
            + datetime.fromtimestamp(timestamp, tz=UTC).strftime("%Y-%m-%d %H:%M:%S"),
        )

        try:
            self._collect_intelligence(last_run, work_id)
        except Exception as e:
            self.helper.connector_logger.error(str(e))
        # Store the current timestamp as a last run
        message = "Connector successfully run, storing last_run as " + str(timestamp)
        self.helper.connector_logger.info(message)
        self.helper.set_state({"last_run": timestamp})
        self.helper.api.work.to_processed(work_id, message)
        self.helper.connector_logger.info(
            "Last_run stored, next run in: "
            + str(round(self.get_interval() / 60, 2))
            + " minutes"
        )

    def _process(self):
        try:
            self._process_data()
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("Connector stop")
            sys.exit(0)
        except Exception as e:
            self.helper.connector_logger.error(str(e))

    def run(self):
        self.helper.connector_logger.info("Fetching ThreatMatch...")
        self.helper.schedule_process(
            message_callback=self._process,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
