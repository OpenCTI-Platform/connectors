"""
SIEMRULES Connector
"""

import json
import os
import time
from datetime import UTC, datetime
from urllib.parse import urljoin

import requests
import schedule
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable


class SiemrulesConnector:
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
        detection_packs = self._get_param("detection_packs")
        self.detection_packs = detection_packs.split(",") if detection_packs else []
        self.interval_hours = self._get_param("interval_hours", is_number=True)

        if not self.detection_packs:
            self.helper.log_error("at least one id is required on detection_packs")
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
            f"SIEMRULES_{param_name.upper()}",
            ["siemrules", param_name.lower()],
            self.helper.config,
            is_number,
            default_value,
        )

    def list_detection_packs(self):
        try:
            return self.retrieve("v1/detection-packs/", list_key="results")
        except:
            self.helper.log_error("failed to fetch detection-packs")
        return []

    def process_updated_rules(self, dpack):
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
            self.process_rule(pack_id, rule)
            self.update_pack_state(pack_id, latest_update=rule["metadata"]["modified"])

    def process_rule(self, pack_id, rule: dict):
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
            self.helper.send_stix2_bundle(json.dumps(bundle), work_id=self.work_id)
        except:
            self.helper.log_error("could not process rule " + rule_repr)

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
            self.update_pack_state(pack_id, name=pack_name)
            self.helper.log_info(f"processing {pack_repr}")
            self.process_updated_rules(dpack)
            self.update_pack_state(last_run=datetime.now(UTC).isoformat())
        self.update_state(last_run_completed=datetime.now(UTC).isoformat())

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

    def _get_state(self) -> dict:
        state = self.helper.get_state()
        if not state or "detection-packs" not in state:
            state = {"detection-packs": {}}
        return state

    def run(self):
        self.helper.log_info("Starting Siemrules")
        schedule.every(self.interval_hours).hours.do(self.run_once)
        self.run_once()
        while True:
            schedule.run_pending()
            time.sleep(1)


if __name__ == "__main__":
    SiemrulesConnector().run()
