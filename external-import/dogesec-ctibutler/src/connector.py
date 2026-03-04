"""
CTIBUTLER Connector
"""

import os
import traceback
from contextlib import contextmanager
from datetime import UTC, datetime
from urllib.parse import urljoin

import requests
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
    "atlas",
]


class CTIButlerException(Exception):
    pass


def parse_knowledgebases(helper: OpenCTIConnectorHelper, value: str):
    if not value:
        return []
    values = value.split(",")
    for v in values:
        if v not in KNOWLEDGE_BASES:
            message = f"Unsupported knowledge base: {v}"
            helper.log_error(message)
            raise ValueError(message)
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
        self.base_url = self._get_param("base_url").strip("/") + "/"
        self.api_key = self._get_param("api_key")
        self.knowledgebases = parse_knowledgebases(
            self.helper, self._get_param("knowledgebases")
        )
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
        total_results_count = 1
        while total_results_count > len(objects):
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
            urljoin(self.base_url, f"v1/{knowledge_base}/versions/installed/")
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
            with self._run_in_work(f"Knowledge Base: {base}") as work_id:
                try:
                    version, objects = self.get_knowledge_base_objects(base)
                    for obj in objects:
                        self.bundle_object(base, obj, work_id)
                        # manually ping the parent work to keep it alive
                        self.helper.api.work.ping(work_id=self.main_work_id)
                    self.update_state(base, version)
                except VersionAlreadyIngested as e:
                    self.helper.log_info(str(e))
                    raise
                except Exception as e:
                    self.helper.log_error(f"cannot process knowledge base {base}: {e}")
                    raise CTIButlerException(f"failed to process {base}") from e

    @contextmanager
    def _run_in_work(self, work_name: str):
        work_id = self.helper.api.work.initiate_work(self.helper.connect_id, work_name)
        message = "[CTIBUTLER] Work done"
        in_error = False
        try:
            yield work_id
        except Exception as e:
            self.helper.log_error(f"work failed: {e}")
            message = "[CTIBUTLER] Work failed - " + traceback.format_exc()
            in_error = True
        finally:
            self.helper.api.work.to_processed(
                work_id=work_id, message=message, in_error=in_error
            )

    def run_once(self):
        with self._run_in_work("CTIButler Connector Run") as main_work_id:
            self.main_work_id = main_work_id
            self._run_once()

    @staticmethod
    def get_object_name(base, obj):
        name = None
        if refs := obj.get("external_references"):
            name = refs[0].get("external_id")
        name = name or obj["id"]
        return f"{base} => {name}"

    def bundle_object(self, base, obj, work_id):
        readable_name = self.get_object_name(base, obj)
        self.helper.log_info(f"retrieve bundle for {readable_name}")
        try:
            objects = self.retrieve(
                f"v1/{base}/objects/{obj['id']}/bundle/", list_key="objects"
            )
            bundle = self.helper.stix2_create_bundle(objects)
            self.helper.send_stix2_bundle(bundle, work_id=work_id)
        except Exception:
            self.helper.log_error(
                f"process {readable_name} failed", dict(work_id=work_id)
            )
            self.helper.api.work.report_expectation(
                work_id=work_id,
                error={
                    "error": f"[{readable_name}] could not process:\n"
                    + traceback.format_exc(),
                    "source": "CONNECTOR",
                },
            )

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
        self.helper.schedule_process(
            message_callback=self.run_once,
            duration_period=self.interval_days * 24 * 3600,
        )


def chunked(lst):
    start = 0
    size = 50
    while start < len(lst):
        end = start + size
        yield lst[start : start + size]
        start = end


if __name__ == "__main__":
    try:
        CTIButlerConnector().run()
    except BaseException:
        traceback.print_exc()
        exit(1)
