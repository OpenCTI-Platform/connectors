import builtins
import json
import sys
from datetime import UTC, datetime
from typing import Any

import requests
from bs4 import BeautifulSoup
from pycti import OpenCTIConnectorHelper
from threatmatch.client import ThreatMatchClient
from threatmatch.config import ConnectorSettings


class Connector:
    def __init__(self, helper: OpenCTIConnectorHelper, config: ConnectorSettings):
        self.helper = helper
        self.config = config
        self.start_datetime = datetime.now(tz=UTC)  # redefined in _process()
        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="Security Alliance",
            description="Security Alliance is a cyber threat intelligence product and services company, formed in 2007.",
        )

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

    def _collect_intelligence(self, last_run: datetime, work_id: str) -> None:
        import_from_date = (
            last_run.strftime("%Y-%m-%d %H:%M")
            if last_run
            else self.config.threatmatch.import_from_date
        )

        with ThreatMatchClient(
            base_url=self.config.threatmatch.url.encoded_string(),
            client_id=self.config.threatmatch.client_id,
            client_secret=self.config.threatmatch.client_secret,
        ) as client:
            headers = {"Authorization": "Bearer " + client.token}
            if self.config.threatmatch.import_profiles:
                profile_ids = client.get_profile_ids(import_from_date=import_from_date)
                self._process_list(work_id, client.token, "profiles", profile_ids)
            if self.config.threatmatch.import_alerts:
                alert_ids = client.get_alert_ids(import_from_date=import_from_date)
                self._process_list(work_id, client.token, "alerts", alert_ids)
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
                        self.config.threatmatch.url.encoded_string()
                        + "/api/taxii/objects",
                        headers=headers,
                        params=params,
                    )
                    if r.status_code != 200:
                        self.helper.connector_logger.error(str(r.text))
                    data.extend(r.json().get("objects", []))
                    date = r.json()["objects"][-1]["modified"]
                    more = r.json().get("more", False)
                self.helper.connector_logger.info(data)
                self._process_list(work_id, client.token, "indicators", data)

    @property
    def state(self) -> dict[str, Any]:
        return self.helper.get_state() or {}

    def _get_last_run(self) -> datetime | None:
        if last_run := self.state.get("last_run"):
            last_run = (
                datetime.fromtimestamp(last_run, tz=UTC)  # For retro compatibility
                if isinstance(last_run, float | int)
                else datetime.fromisoformat(last_run)
            )
        self.helper.connector_logger.info(
            (
                "Connector last run: "
                + (last_run.isoformat(timespec="seconds") if last_run else "never")
            ),
        )
        return last_run

    def _process_data(self):
        last_run = self._get_last_run()
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id,
            "ThreatMatch run @ " + self.start_datetime.isoformat(timespec="seconds"),
        )

        try:
            self._collect_intelligence(last_run, work_id)
        except Exception as e:
            self.helper.connector_logger.error(str(e))
        self.helper.set_state(
            {"last_run": self.start_datetime.isoformat(timespec="seconds")}
        )
        self.helper.api.work.to_processed(
            work_id,
            "Connector successfully run, storing last_run as "
            + self.start_datetime.isoformat(timespec="seconds"),
        )

    def _process(self):
        self.start_datetime = datetime.now(tz=UTC)
        try:
            self.helper.connector_logger.info("Running connector...")
            self._process_data()
            self.helper.connector_logger.info("Connector successfully ran")
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("Connector stop")
            sys.exit(0)
        except Exception as e:
            self.helper.connector_logger.error(str(e))

    def run(self):
        self.helper.connector_logger.info("Connector starting...")
        self.helper.schedule_process(
            message_callback=self._process,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
