# -*- coding: utf-8 -*-
"""OpenCTI valhalla connector core module."""

import os
import yaml
import time

from typing import Any, Dict, Mapping, Optional
from datetime import datetime

from .knowledge import KnowledgeImporter
from .models import Status

from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2 import TLP_WHITE, TLP_AMBER
from valhallaAPI.valhalla import ValhallaAPI


class Valhalla:
    """OpenCTI valhalla main class"""

    _DEMO_API_KEY = "1111111111111111111111111111111111111111111111111111111111111111"
    _STATE_LAST_RUN = "last_run"
    _VALHALLA_LAST_VERSION = "valhalla_last_version"

    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/../config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        # Extra config
        self.confidence_level = get_config_variable(
            "CONNECTOR_CONFIDENCE_LEVEL",
            ["connector", "confidence_level"],
            config,
            isNumber=True,
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )
        self.API_KEY = get_config_variable(
            "VALHALLA_API_KEY", ["valhalla", "api_key"], config
        )
        self.INTERVAL_SEC = get_config_variable(
            "VALHALLA_INTERVAL_SEC", ["valhalla", "interval_sec"], config, isNumber=True
        )

        self.helper = OpenCTIConnectorHelper(config)
        self.helper.log_info(f"loaded valhalla config: {config}")

        # If we run without API key we can assume all data is TLP:WHITE else we
        # default to TLP:AMBER to be safe.
        if self.API_KEY == "" or self.API_KEY is None:
            self.default_marking = self.helper.api.marking_definition.read(
                id=TLP_WHITE["id"]
            )
            self.valhalla_client = ValhallaAPI()
        else:
            self.default_marking = self.helper.api.marking_definition.read(
                id=TLP_AMBER["id"]
            )
            self.valhalla_client = ValhallaAPI(api_key=self.API_KEY)

        self.knowledge_importer = KnowledgeImporter(
            self.helper,
            self.confidence_level,
            self.update_existing_data,
            self.default_marking,
            self.valhalla_client,
        )

    def run(self):
        self.helper.log_info("starting valhalla connector...")
        while True:
            try:
                status_data = self.valhalla_client.get_status()
                api_status = Status.parse_obj(status_data)
                self.helper.log_info(f"current valhalla status: {api_status}")

                current_time = int(datetime.utcnow().timestamp())
                current_state = self._load_state()

                self.helper.log_info(f"loaded state: {current_state}")

                last_run = self._get_state_value(current_state, self._STATE_LAST_RUN)

                last_valhalla_version = self._get_state_value(
                    current_state, self._VALHALLA_LAST_VERSION
                )

                if self._is_scheduled(last_run, current_time) and self._check_version(
                    last_valhalla_version, api_status.version
                ):
                    self.helper.log_info("running importers")

                    knowledge_importer_state = self._run_knowledge_importer(
                        current_state
                    )
                    self.helper.log_info("done with running importers")

                    new_state = current_state.copy()
                    new_state.update(knowledge_importer_state)
                    new_state[self._STATE_LAST_RUN] = int(datetime.utcnow().timestamp())
                    new_state[self._VALHALLA_LAST_VERSION] = api_status.version

                    self.helper.log_info(f"storing new state: {new_state}")

                    self.helper.set_state(new_state)

                    self.helper.log_info(
                        f"state stored, next run in: {self._get_interval()} seconds"
                    )
                else:
                    new_interval = self._get_interval() - (current_time - last_run)
                    self.helper.log_info(
                        f"connector will not run, next run in: {new_interval} seconds"
                    )

                # After a successful run pause at least 60sec
                time.sleep(60)
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("connector stop")
                exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
                exit(0)

    def _run_knowledge_importer(
        self, current_state: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        return self.knowledge_importer.run(current_state)

    def _get_interval(self) -> int:
        return int(self.INTERVAL_SEC)

    def _load_state(self) -> Dict[str, Any]:
        current_state = self.helper.get_state()
        if not current_state:
            return {}
        return current_state

    @staticmethod
    def _get_state_value(
        state: Optional[Mapping[str, Any]], key: str, default: Optional[Any] = None
    ) -> Any:
        if state is not None:
            return state.get(key, default)
        return default

    def _is_scheduled(self, last_run: Optional[int], current_time: int) -> bool:
        if last_run is None:
            return True
        time_diff = current_time - last_run
        return time_diff >= self._get_interval()

    def _check_version(self, last_version: Optional[int], current_version: int) -> bool:
        if last_version is None:
            return True
        return current_version > last_version
