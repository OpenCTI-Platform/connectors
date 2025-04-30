"""
VULMATCH Connector
"""

import os
import time
from datetime import UTC, datetime, timedelta
from urllib.parse import urljoin

import requests
import schedule
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable


def parse_bool(value: str):
    value = str(value).lower()
    return value in ["yes", "y", "true", "1"]


def parse_number(value: int):
    if not value or value <= 0:
        return None
    return value


class VulmatchConnector:
    work_id = None

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
        self.sbom_only = parse_bool(self._get_param("sbom_only"))
        self.cvss_base_score_min = parse_number(
            self._get_param("cvss_base_score_min", is_number=True, default_value=-1)
        )
        self.epss_score_min = parse_number(
            self._get_param("epss_score_min", is_number=True, default_value=-1)
        )
        self.interval_days = self._get_param("interval_days", is_number=True)
        self.days_to_backfill = self._get_param("days_to_backfill", is_number=True)

        self.session = requests.Session()
        self.session.headers = {
            "API-KEY": self.api_key,
        }

    def _get_param(
        self, param_name: str, is_number: bool = False, default_value: str = None
    ) -> int | str:
        return get_config_variable(
            f"VULMATCH_{param_name.upper()}",
            ["vulmatch", param_name.lower()],
            self.helper.config,
            is_number,
            default_value,
        )

    def list_cpes_in_sbom(self):
        if not self.sbom_only:
            return [""]
        try:
            path = "v1/sbom/"
            cpes = [obj["cpe"] for obj in self.retrieve(path, list_key="objects")]
            self.helper.log_info(f"found {len(cpes)} cpes in sbom")
            if not cpes:
                raise Exception("no cpes in sbom")
            return cpes
        except:
            self.helper.log_error("failed to fetch dossiers")
        return []

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

    def get_vulnerabilities(self, cpes):
        modified_min = self._get_state()["last_vulnerability_modified"]
        vulnerabilities = self.retrieve(
            "v1/cve/objects/",
            list_key="objects",
            params=dict(
                epss_score_min=self.epss_score_min,
                cvss_base_score_min=self.cvss_base_score_min,
                cpes_in_pattern=",".join(cpes),
                modified_min=modified_min,
                modified_max=datetime.now(
                    UTC
                ).isoformat(),  # make sure number of items do not increase while retrieving
            ),
        )
        vulnerabilities = [v for v in vulnerabilities if v["modified"] > modified_min]
        self.helper.log_info(f"found {len(vulnerabilities)} cves")
        return sorted(vulnerabilities, key=lambda x: x["modified"])

    def _run_once(self):
        self.helper.log_info("running as scheduled")
        for cpes in chunked(self.list_cpes_in_sbom()):
            vulnerabilities = self.get_vulnerabilities(cpes)
            for vuln in vulnerabilities:
                self.process_vulnerability(vuln)
                self.update_state(vuln["modified"])

    def process_vulnerability(self, vuln):
        cve_name = vuln["name"]
        self.helper.log_info(f"retrieve bundle for {cve_name}")
        cve_work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, f"{self.helper.connect_name} @ {cve_name}"
        )
        try:
            objects = self.retrieve(
                f"v1/cve/objects/{cve_name}/bundle/", list_key="objects"
            )
            bundle = self.helper.stix2_create_bundle(objects)
            self.helper.send_stix2_bundle(bundle, work_id=cve_work_id)
            self.helper.api.work.to_processed(
                work_id=cve_work_id,
                message=f"[{cve_name}] bundle retrieved",
            )
        except:
            self.helper.log_error(
                f"process {cve_name} failed", dict(work_id=cve_work_id)
            )
            self.helper.api.work.report_expectation(
                work_id=cve_work_id,
                error={
                    "error": f"[{cve_name}] could not process",
                    "source": "CONNECTOR",
                },
            )
            self.helper.api.work.to_processed(
                work_id=cve_work_id,
                message=f"[{cve_name}] Retrieve bundle failed",
                in_error=True,
            )

    def run_once(self):
        try:
            self._run_once()
        except:
            self.helper.log_error("run failed")

    def _get_state(self) -> dict:
        state = self.helper.get_state() or dict(
            last_vulnerability_modified=(
                datetime.now(UTC) - timedelta(days=self.days_to_backfill)
            ).isoformat()
        )
        return state

    def update_state(self, vulnerability_modified):
        state = self._get_state()
        state.update(
            last_vulnerability_modified=max(
                vulnerability_modified,
                state.get("last_vulnerability_modified", vulnerability_modified),
            ),
            updated=datetime.now(UTC).isoformat(),
        )
        self.helper.set_state(state)

    def run(self):
        self.helper.log_info("Starting Vulmatch")
        schedule.every(self.interval_days).days.do(self.run_once)
        self.run_once()
        while True:
            schedule.run_pending()
            time.sleep(1)


def chunked(lst):
    start = 0
    size = 50
    while start < len(lst):
        end = start + size
        yield lst[start : start + size]
        start = end


if __name__ == "__main__":
    VulmatchConnector().run()
