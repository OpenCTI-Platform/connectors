"""
VULMATCH Connector
"""

import itertools
import os
import traceback
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from urllib.parse import urljoin

import requests
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable


def parse_bool(value: str):
    value = str(value).lower()
    return value in ["yes", "y", "true", "1"]


def parse_number(value: int):
    if not value or value <= 0:
        return None
    return value


NAMESPACE = uuid.UUID("152ecfe1-5015-522b-97e4-86b60c57036d")
SKIPPED_TYPES = ["grouping", "weakness", "exploit"]


class VulmatchException(Exception):
    pass


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
        self.base_url = self._get_param("base_url").strip("/") + "/"
        self.api_key = self._get_param("api_key")
        self.sbom_only = parse_bool(self._get_param("sbom_only"))
        self.cvss_v2_score_min = parse_number(
            self._get_param("cvss_v2_score_min", is_number=True, default_value=-1)
        )
        self.cvss_v3_score_min = parse_number(
            self._get_param("cvss_v3_score_min", is_number=True, default_value=-1)
        )
        self.cvss_v4_score_min = parse_number(
            self._get_param("cvss_v4_score_min", is_number=True, default_value=-1)
        )
        self.epss_score_min = parse_number(
            self._get_param("epss_score_min", is_number=True, default_value=-1)
        )
        self.interval_days = self._get_param("interval_days", is_number=True)
        self.days_to_backfill = min(
            self._get_param("days_to_backfill", is_number=True), 365
        )

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
                raise VulmatchException("no cpes in sbom")
            return cpes
        except Exception as e:
            self.helper.log_error("failed to fetch CPEs from SBOM")
            raise VulmatchException("failed to fetch CPEs from SBOM") from e

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

    def get_vulnerabilities(self, cpes):
        modified_min = self._get_state()["last_vulnerability_modified"]
        vulnerabilities = self.retrieve(
            "v1/cve/objects/",
            list_key="objects",
            params=dict(
                epss_score_min=self.epss_score_min,
                cvss_v2_score_min=self.cvss_v2_score_min,
                cvss_v3_score_min=self.cvss_v3_score_min,
                cvss_v4_score_min=self.cvss_v4_score_min,
                cpes_in_pattern=",".join(cpes),
                modified_min=modified_min,
                modified_max=datetime.now(
                    UTC
                ).isoformat(),  # make sure number of items do not increase while retrieving
                sort="modified_ascending",
            ),
        )
        vulnerabilities = [v for v in vulnerabilities if v["modified"] > modified_min]
        self.helper.log_info(f"found {len(vulnerabilities)} cves")
        return sorted(vulnerabilities, key=lambda x: x["modified"])

    def _run_once(self):
        self.helper.log_info("running as scheduled")
        for cpes in chunked(self.list_cpes_in_sbom()):
            cpe_str = ",".join(cpes) if cpes[0] else "all"
            with self._run_in_work(f"CPEs: {cpe_str[:50]}"):
                vulnerabilities = self.get_vulnerabilities(cpes)
                for vuln in vulnerabilities:
                    self.process_vulnerability(vuln)
                    self.update_state(vuln["modified"])

    @contextmanager
    def _run_in_work(self, work_name: str):
        work_id = self.helper.api.work.initiate_work(self.helper.connect_id, work_name)
        message = "[VULMATCH] Work done"
        in_error = False
        try:
            yield work_id
        except Exception as e:
            self.helper.log_error(f"work failed: {e}")
            message = "[VULMATCH] Work failed - " + traceback.format_exc()
            in_error = True
        finally:
            self.helper.api.work.to_processed(
                work_id=work_id, message=message, in_error=in_error
            )

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
            transformed_objects = self.transform_bundle_objects(objects)
            bundle = self.helper.stix2_create_bundle(transformed_objects)
            self.helper.send_stix2_bundle(bundle, work_id=cve_work_id)
            self.helper.api.work.to_processed(
                work_id=cve_work_id,
                message=f"[{cve_name}] bundle retrieved",
            )
        except Exception:
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
        with self._run_in_work("Vulmatch Connector Run"):
            self._run_once()

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
        self.helper.schedule_process(
            message_callback=self.run_once,
            duration_period=self.interval_days * 86400,
        )

    def transform_bundle_objects(self, bundle_objects):
        """
        This function
        - Removes objects of the following types
        - - weakness
        - - exploit
        - - grouping
        - Adds relationships between software and vulnerability using grouping.object_refs
        """
        objects = {}
        groupings = {}
        x_cpes_vulnerable_mapping = []
        for obj in bundle_objects:
            if obj["type"] == "grouping":
                groupings[obj["id"]] = obj["object_refs"]
            if obj["type"] in SKIPPED_TYPES:
                continue
            if obj.get("relationship_type") == "x-cpes-vulnerable":
                x_cpes_vulnerable_mapping.append(
                    (
                        obj["source_ref"].replace("indicator", "vulnerability"),
                        obj["target_ref"],
                    )
                )
            if obj["type"] == "relationship":
                source_type, _, _ = obj["source_ref"].partition("--")
                target_type, _, _ = obj["target_ref"].partition("--")
                if source_type in SKIPPED_TYPES or target_type in SKIPPED_TYPES:
                    continue
            objects[obj["id"]] = obj
        relationships = []
        for source_ref, target_ref in x_cpes_vulnerable_mapping:
            for software_id in groupings.get(target_ref, []):
                if software_id not in objects:
                    continue
                software_name = objects[software_id]["name"]
                vuln_obj = objects[source_ref]
                vulnerability_name = vuln_obj["name"]
                relationships.append(
                    {
                        "type": "relationship",
                        "spec_version": "2.1",
                        "id": "relationship--"
                        + str(uuid.uuid5(NAMESPACE, f"has+{source_ref}+{software_id}")),
                        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
                        "created": vuln_obj["created"],
                        "modified": vuln_obj["modified"],
                        "relationship_type": "has",
                        "source_ref": software_id,
                        "target_ref": source_ref,
                        "description": f"{software_name} is vulnerable to {vulnerability_name}",
                        "object_marking_refs": vuln_obj["object_marking_refs"],
                        "external_references": [vuln_obj["external_references"][0]],
                    }
                )
        return list(itertools.chain(objects.values(), relationships))


def chunked(lst):
    start = 0
    size = 50
    while start < len(lst):
        end = start + size
        yield lst[start : start + size]
        start = end


if __name__ == "__main__":
    try:
        VulmatchConnector().run()
    except BaseException:
        traceback.print_exc()
        exit(1)
