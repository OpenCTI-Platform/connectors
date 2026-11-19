"""
SIEMRULES Connector
"""

import json
import traceback
from contextlib import contextmanager
from datetime import UTC, datetime
from urllib.parse import urljoin

import requests
from pycti import OpenCTIConnectorHelper
from settings import ConnectorSettings


class SiemrulesException(Exception):
    pass


class SiemrulesConnector:
    def __init__(self):
        """Read in config variables"""

        self.config = ConnectorSettings()
        self.helper = OpenCTIConnectorHelper(config=self.config.to_helper_config())
        self.base_url = str(self.config.siemrules.base_url).strip("/") + "/"
        self.api_key = self.config.siemrules.api_key.get_secret_value()
        self.detection_packs = self.config.siemrules.detection_packs
        self.duration_period = self.config.connector.duration_period.total_seconds()

        if not self.detection_packs:
            self.helper.log_error("at least one id is required on detection_packs")
            self.helper.stop()
            exit(0)

        self.session = requests.Session()
        self.session.headers = {
            "API-KEY": self.api_key,
        }

    def list_detection_packs(self):
        try:
            return self.retrieve("v1/detection-packs/", list_key="results")
        except Exception as e:
            self.helper.log_error("failed to fetch detection-packs")
            raise SiemrulesException("failed to fetch detection-packs") from e

    def process_updated_rules(self, dpack, work_id):
        pack_id = dpack["id"]
        self.helper.log_info(
            "processing Pack(id={id}, title='{name}')".format_map(dpack)
        )

        pack_state: dict = self._get_state()["detection-packs"].get(pack_id, {})
        filters = dict()
        if latest_update := pack_state.get("latest_update"):
            filters.update(modified_at_after=latest_update)

        pack_rules = self.retrieve(
            f"v1/detection-packs/{pack_id}/rules/",
            list_key="results",
            params=filters,
        )
        pack_rules = sorted(pack_rules, key=lambda rule: rule["metadata"]["modified"])
        for rule in pack_rules:
            self.process_rule(pack_id, rule, work_id)
            self.update_pack_state(pack_id, latest_update=rule["metadata"]["modified"])

    def process_rule(self, pack_id, rule: dict, work_id):
        indicator_id = rule["metadata"]["id"]
        rule_name = rule["metadata"]["name"]
        rule_repr = (
            f"Rule(name={rule_name}, id={indicator_id}, type={rule['rule_type']})"
        )
        self.helper.log_info("Processing " + rule_repr)
        path = f"v1/correlation-rules/{indicator_id}/objects/"
        if rule["rule_type"] == "base":
            path = f"v1/base-rules/{indicator_id}/objects/"

        try:
            objects = self.retrieve(path, list_key="objects")
            bundle = dict(
                type="bundle",
                id=f"bundle--{indicator_id}",
                objects=objects,
            )
            self.helper.log_info(
                f"{rule_repr} sending bundle with {len(objects)} items"
            )
            self.helper.send_stix2_bundle(json.dumps(bundle), work_id=work_id)
        except Exception:
            self.helper.log_error("could not process rule " + rule_repr)

    def retrieve(self, path, list_key, params: dict = None):
        params = params or {}
        params.update(page=1, page_size=200)
        objects: list[dict] = []
        total_results_count = 1
        while total_results_count > len(objects):
            resp = self.session.get(urljoin(self.base_url, path), params=params)
            params.update(page=params["page"] + 1)
            self.helper.log_info(f">>> status_code={resp.status_code} url={resp.url}")
            data = resp.json()
            total_results_count = data["total_results_count"]
            objects.extend(data[list_key])
        return objects

    def _run_once(self):
        self.helper.log_info("running as scheduled")
        self.update_state(last_run_start=datetime.now(UTC).isoformat())
        for dpack in self.list_detection_packs():
            pack_id = dpack["id"]
            pack_name = dpack["name"]
            pack_repr = f"DetectionPack(id={pack_id}, name={repr(pack_name)})"
            if pack_id not in (self.detection_packs or [pack_id]):
                self.helper.log_info(
                    f"skipping {pack_repr} not in config.siemrules.detection_packs"
                )
                continue
            with self._run_in_work(f"Pack: {pack_name} ({pack_id})") as work_id:
                last_run = datetime.now(UTC).isoformat()
                self.update_pack_state(pack_id, name=pack_name)
                self.helper.log_info(f"processing {pack_repr}")
                self.process_updated_rules(dpack, work_id)
                self.update_pack_state(pack_id, last_run=last_run)
        self.update_state(last_run_completed=datetime.now(UTC).isoformat())

    @contextmanager
    def _run_in_work(self, work_name: str):
        work_id = self.helper.api.work.initiate_work(self.helper.connect_id, work_name)
        message = "[SIEMRULES] Work done"
        in_error = False
        try:
            yield work_id
        except Exception as e:
            self.helper.log_error(f"work failed: {e}")
            message = "[SIEMRULES] Work failed - " + traceback.format_exc()
            in_error = True
        finally:
            self.helper.api.work.to_processed(
                work_id=work_id, message=message, in_error=in_error
            )

    def run_once(self):
        with self._run_in_work("Siemrules Connector Run"):
            self._run_once()

    def update_pack_state(self, pack_id, **kwargs):
        state = self._get_state()
        pack_state: dict = state["detection-packs"].get(pack_id, {})
        pack_state.update(kwargs)
        state["detection-packs"][pack_id] = pack_state
        self.helper.set_state(state)

    def update_state(self, **kwargs):
        state = self._get_state()
        state.update(kwargs)
        self.helper.set_state(state)

    def _get_state(self) -> dict:
        state = self.helper.get_state()
        if not state or "detection-packs" not in state:
            state = {"detection-packs": {}}
        return state

    def run(self):
        self.helper.log_info("Starting Siemrules")
        self.helper.schedule_process(
            message_callback=self.run_once,
            duration_period=self.duration_period,
        )


if __name__ == "__main__":
    try:
        SiemrulesConnector().run()
    except BaseException:
        traceback.print_exc()
        exit(1)
