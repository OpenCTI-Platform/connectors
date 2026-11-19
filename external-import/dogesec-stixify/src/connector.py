"""
STIXIFY Connector
"""

import json
import sys
import traceback
from contextlib import contextmanager
from datetime import UTC, datetime
from urllib.parse import urljoin

import requests
from pycti import OpenCTIConnectorHelper
from settings import ConnectorSettings


class StixifyException(Exception):
    pass


class StixifyConnector:
    def __init__(self):
        """Read in config variables"""

        self.config = ConnectorSettings()
        self.helper = OpenCTIConnectorHelper(config=self.config.to_helper_config())
        self.base_url = str(self.config.stixify.base_url).strip("/") + "/"
        self.api_key = self.config.stixify.api_key.get_secret_value()
        self.dossier_ids = self.config.stixify.dossier_ids

        if not self.dossier_ids:
            self.helper.log_error("at least one dossier id required")
            self.helper.stop()
            sys.exit(1)

        self.session = requests.Session()
        self.session.headers = {
            "API-KEY": self.api_key,
        }

    def list_dossiers(self):
        try:
            return self.retrieve("v1/dossiers/", list_key="results")
        except Exception:
            self.helper.log_error("failed to fetch dossiers")
            raise StixifyException("failed to fetch dossiers")

    def get_and_process_reports_after_last(self, dossier, work_id):
        dossier_id = dossier["id"]
        self.helper.log_info(
            "processing dossier(id={id}, title='{name}')".format_map(dossier)
        )
        dossier_state = self._get_state()["dossiers"].get(
            dossier_id, dict(last_run_at="")
        )
        filters = dict()
        self.current_run_time = datetime.now(UTC).isoformat()
        if q := dossier_state.get("last_run_at"):
            filters.update(added_after=q)
        dossier_reports = self.retrieve(
            f"v1/dossiers/{dossier_id}/reports/",
            list_key="objects",
            params=filters,
        )
        for report in dossier_reports:
            self.process_report(report, work_id)

    def process_report(self, report: dict, work_id):
        report_id = report["id"]
        report = report.get("stixify_report_metadata", report)
        report_title = report["name"]
        report_name = f"Report(title={report_title}, id={report_id})"
        self.helper.log_info("Processing " + report_name)
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
            self.helper.send_stix2_bundle(json.dumps(bundle), work_id=work_id)
        except Exception:
            self.helper.log_error("could not process report " + report_name)

    def retrieve(self, path, list_key, params: dict = None):
        params = params or {}
        params.update(page=1, page_size=200)
        objects: list[dict] = []
        total_results_count = 1
        while total_results_count > len(objects):
            resp = self.session.get(urljoin(self.base_url, path), params=params)
            params.update(page=params["page"] + 1)
            data = resp.json()
            total_results_count = data["total_results_count"]
            objects.extend(data[list_key])
        return objects

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
            with self._run_in_work(
                f"Dossier: {dossier['name']} ({dossier['id']})"
            ) as work_id:
                self.helper.log_info(f"processing {dossier_repr}")
                self.get_and_process_reports_after_last(dossier, work_id)
                self.set_dossier_state(dossier_id, last_updated=self.current_run_time)
        self.set_dossier_state(None, None)

    @contextmanager
    def _run_in_work(self, work_name: str):
        work_id = self.helper.api.work.initiate_work(self.helper.connect_id, work_name)
        message = "[Stixify] Work done"
        in_error = False
        try:
            yield work_id
        except Exception as e:
            self.helper.log_error(f"work failed: {e}")
            message = "[Stixify] Work failed - " + traceback.format_exc()
            in_error = True
        finally:
            self.helper.api.work.to_processed(
                work_id=work_id, message=message, in_error=in_error
            )

    def run_once(self):
        with self._run_in_work("Stixify Connector Run"):
            self._run_once()

    def set_dossier_state(self, dossier_id, last_updated):
        state = self._get_state()
        if dossier_id:
            dossier_state: dict = state["dossiers"].setdefault(dossier_id, {})
            dossier_state.update(
                last_run_at=max(
                    last_updated, dossier_state.get("last_run_at", last_updated)
                )
            )
        self.helper.set_state(state)

    def _get_state(self) -> dict:
        state = self.helper.get_state()
        if not state or "dossiers" not in state:
            state = {"dossiers": {}}
        return state

    def run(self):
        self.helper.log_info("Starting Stixify")
        self.helper.schedule_process(
            message_callback=self.run_once,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )


if __name__ == "__main__":
    try:
        StixifyConnector().run()
    except BaseException:
        traceback.print_exc()
        exit(1)
