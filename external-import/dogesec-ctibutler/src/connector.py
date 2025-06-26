"""
CTIBUTLER Connector
"""

import os
import time
from datetime import UTC, datetime
from urllib.parse import urljoin

import requests
import schedule
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable


def parse_bool(value: str):
    value = str(value).lower()
    return value in ["yes", "y", "true", "1"]


KNOWLEDGE_BASES = [
    "cwe",
    "capec",
    "location",
    "attack-mobile",
    "attack-ics",
    "attack-enterprise",
    "disarm",
]


def parse_knowledgebases(value: str):
    if not value:
        return []
    values = value.split(",")
    for v in values:
        assert v in KNOWLEDGE_BASES, f"unknown knowledge base: {v}"
    return values


class VersionAlreadyIngested(Exception):
    pass


class KnowledgeBaseIsEmpty(Exception):
    pass


class CTIButlerConnector:
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
        self.knowledgebases = parse_knowledgebases(self._get_param("knowledgebases"))
        self.interval_days = self._get_param("interval_days", is_number=True)

        self.session = requests.Session()
        self.session.headers = {
            "API-KEY": self.api_key,
        }

    def _get_param(
        self, param_name: str, is_number: bool = False, default_value: str = None
    ) -> int | str:
        return get_config_variable(
            f"CTIBUTLER_{param_name.upper()}",
            ["ctibutler", param_name.lower()],
            self.helper.config,
            is_number,
            default_value,
        )

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

    def get_knowledge_base_objects(self, knowledge_base):
        self.helper.log_info(f"running for {knowledge_base}")
        _, ingested_versions = self.get_knowledge_base_versions(knowledge_base)
        resp = self.session.get(
            urljoin(self.base_url, f"v1/{knowledge_base}/versions/")
        )
        resp.raise_for_status()
        versions = resp.json()["versions"]
        if not versions:
            raise KnowledgeBaseIsEmpty(
                f"knowledge base for {knowledge_base} appears to be empty"
            )
        if versions[0] in ingested_versions:
            raise VersionAlreadyIngested(
                f"version {versions[0]} of {knowledge_base} has already been ingested"
            )

        version = versions[0]

        objects = self.retrieve(
            f"v1/{knowledge_base}/objects/",
            list_key="objects",
            params=dict(
                version=version,
            ),
        )
        self.helper.log_info(
            f"found {len(objects)} objects for {knowledge_base} v{version}"
        )
        return version, objects

    def _run_once(self):
        self.helper.log_info("running as scheduled")
        for base in self.knowledgebases:
            try:
                version, objects = self.get_knowledge_base_objects(base)
                for obj in objects:
                    self.bundle_object(base, obj)
                self.update_state(base, version)
            except VersionAlreadyIngested as e:
                self.helper.log_info(e)
            except:
                self.helper.log_error("cannot process for knowledge base")

    @staticmethod
    def get_object_name(base, obj):
        if refs := obj.get("external_references"):
            name = refs[0].get("external_id")
        name = name or obj["id"]
        return f"{base} => {name}"

    def bundle_object(self, base, obj):
        readable_name = self.get_object_name(base, obj)
        self.helper.log_info(f"retrieve bundle for {readable_name}")
        cve_work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, f"{self.helper.connect_name} @ {readable_name}"
        )
        try:
            objects = self.retrieve(
                f"v1/{base}/objects/{obj['id']}/bundle/", list_key="objects"
            )
            bundle = self.helper.stix2_create_bundle(objects)
            self.helper.send_stix2_bundle(bundle, work_id=cve_work_id)
            self.helper.api.work.to_processed(
                work_id=cve_work_id,
                message=f"[{readable_name}] bundle retrieved",
            )
        except:
            self.helper.log_error(
                f"process {readable_name} failed", dict(work_id=cve_work_id)
            )
            self.helper.api.work.report_expectation(
                work_id=cve_work_id,
                error={
                    "error": f"[{readable_name}] could not process",
                    "source": "CONNECTOR",
                },
            )
            self.helper.api.work.to_processed(
                work_id=cve_work_id,
                message=f"[{readable_name}] Retrieve bundle failed",
                in_error=True,
            )

    def run_once(self):
        try:
            self._run_once()
        except:
            self.helper.log_error("run failed")

    def _get_state(self) -> dict:
        state = self.helper.get_state() or dict(versions=dict())
        return state

    def get_knowledge_base_versions(self, knowledge_base) -> tuple[dict, list]:
        state = self._get_state()
        versions = state["versions"].setdefault(knowledge_base, [])
        return state, versions

    def update_state(self, knowledge_base, version):
        state, versions = self.get_knowledge_base_versions(knowledge_base)
        state.update(
            updated=datetime.now(UTC).isoformat(),
        )
        versions.append(version)
        self.helper.set_state(state)

    def run(self):
        self.helper.log_info("Starting CTIButler")
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
    CTIButlerConnector().run()
