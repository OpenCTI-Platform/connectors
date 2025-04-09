"""
STIXIFY Connector
"""

import json
import os
import time
from datetime import UTC, datetime, timedelta
from urllib.parse import urljoin

import requests
import schedule
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable


class StixifyConnector:
    def __init__(self):
        """Read in config variables"""

        config_file_path = "config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        self.helper = OpenCTIConnectorHelper(config)
        self.base_url = self._get_param("base_url") + "/"
        self.api_key = self._get_param("api_key")
        dossier_ids = self._get_param("dossier_ids")
        self.dossier_ids = dossier_ids.split(",") if dossier_ids else []
        self.interval_hours = self._get_param("interval_hours", is_number=True)

        if not self.dossier_ids:
            self.helper.log_error("at least one dossier id required")
            self.helper.stop()
            exit(0)

        self.session = requests.Session()
        self.session.headers = {
            "API-KEY": self.api_key,
        }

    def _get_param(
        self, param_name: str, is_number: bool = False, default_value: str = None
    ) -> int | str:
        return get_config_variable(
            f"STIXIFY_{param_name.upper()}",
            ["stixify", param_name.lower()],
            self.helper.config,
            is_number,
            default_value,
        )

    def list_dossiers(self):
        try:
            return self.retrieve2("v1/dossiers/")
        except:
            self.helper.log_error("failed to fetch dossiers")
        return []

    def get_reports_after_last(self, dossier):
        dossier_id = dossier["id"]
        self.helper.log_info(
            "processing dossier(id={id}, title='{name}')".format_map(dossier)
        )
        dossier_state = self._get_state()["dossiers"].get(
            dossier_id, dict(latest_report="")
        )
        filters = dict()
        if q := dossier_state.get("latest_report"):
            filters.update(created_at_after=q)
        dossier_reports = self.retrieve2(
            f"v1/dossiers/{dossier_id}/reports/",
            params=filters,
        )
        for report in dossier_reports:
            self.process_report(dossier_id, report)

    def process_report(self, dossier_id, report: dict):
        self.helper.log_info(str(report))
        report_id = report["id"]
        report_title = report["stixify_file_metadata"]["name"]
        report_name = f"Report(title={report_title}, id={report_id})"
        self.helper.log_info("Processing " + report_name)
        report_created = report["created_at"]
        try:
            objects = self.retrieve(
                f"v1/reports/{report_id}/objects/", list_key="objects"
            )
            bundle = dict(
                type="bundle",
                id=f"bundle--{report_id}",
                objects=objects,
            )
            self.helper.log_info(
                f"{report_name} sending bundle with {len(objects)} items"
            )
            self.helper.send_stix2_bundle(json.dumps(bundle), work_id=self.work_id)
            ## add some miliseconds to the time so it gets skipped next run
            report_created = (
                datetime.fromisoformat(report_created) + timedelta(milliseconds=990)
            ).isoformat()
            self.set_dossier_state(dossier_id, last_updated=report_created)
        except:
            self.helper.log_error("could not process report " + report_name)

    def retrieve(self, path, list_key, params: dict = None):
        params = params or {}
        params.update(page=1, page_size=200)
        objects: list[dict] = []
        total_results_count = -1
        while total_results_count < len(objects):
            resp = self.session.get(urljoin(self.base_url, path), params=params)
            params.update(page=params["page"] + 1)
            data = resp.json()
            total_results_count = data["total_results_count"]
            objects.extend(data[list_key])
        return objects

    def retrieve2(self, path, params=None):
        path = urljoin(self.base_url, path)
        retval = []
        while path:
            resp = self.session.get(path, params=params)
            resp_data = resp.json()
            path = resp_data.get("next")
            retval.extend(resp_data["results"])
        return retval

    def _run_once(self):
        self.helper.log_info("running as scheduled")
        for dossier in self.list_dossiers():
            dossier_id = dossier["id"]
            dossier_name = dossier["name"]
            dossier_repr = f"Dossier(id={dossier_id}, name={repr(dossier_name)})"
            if dossier_id not in (self.dossier_ids or [dossier_id]):
                self.helper.log_info(
                    f"skipping {dossier_repr} not in config.stixify.dossier_ids"
                )
                continue
            self.helper.log_info(f"processing {dossier_repr}")
            self.get_reports_after_last(dossier)
        self.set_dossier_state(None, None)

    def run_once(self):
        in_error = False
        try:
            self.work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, self.helper.connect_name
            )
            self._run_once()
        except:
            self.helper.log_error("run failed")
            in_error = True
        finally:
            self.helper.api.work.to_processed(
                work_id=self.work_id,
                message="[CONNECTOR] Connector exited gracefully",
                in_error=in_error,
            )
            self.work_id = None

    def set_dossier_state(self, dossier_id, last_updated):
        state = self._get_state()
        if dossier_id:
            dossier_state: dict = state["dossiers"].setdefault(dossier_id, {})
            dossier_state.update(
                latest_report=max(
                    last_updated, dossier_state.get("latest_report", last_updated)
                )
            )
        state["last_run"] = datetime.now(UTC).isoformat()
        self.helper.set_state(state)

    def _get_state(self) -> dict:
        state = self.helper.get_state()
        if not state or "dossiers" not in state:
            state = {"dossiers": {}}
        return state

    def run(self):
        self.helper.log_info("Starting Stixify")
        schedule.every(self.interval_hours).hours.do(self.run_once)
        self.run_once()
        while True:
            schedule.run_pending()
            time.sleep(1)


if __name__ == "__main__":
    StixifyConnector().run()
