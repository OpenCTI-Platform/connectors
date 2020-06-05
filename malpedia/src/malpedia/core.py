# -*- coding: utf-8 -*-
"""OpenCTI Malpedia connector core module."""

import os
import yaml
import time

from datetime import datetime
from typing import Any, Dict, Mapping, Optional

from .knowledge import KnowledgeImporter
from .client import MalpediaClient

from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2 import TLP_WHITE, TLP_AMBER


class Malpedia:
    """OpenCTI Malpedia main class"""

    _STATE_LAST_RUN = "state_last_run"
    _MALPEDIA_LAST_VERSION = "malpedia_last_version"

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
        self.AUTH_KEY = get_config_variable(
            "MALPEDIA_AUTH_KEY", ["malpedia", "auth_key"], config
        )
        self.INTERVAL_SEC = get_config_variable(
            "MALPEDIA_INTERVAL_SEC", ["malpedia", "interval_sec"], config
        )
        self.import_intrusion_sets = get_config_variable(
            "MALPEDIA_IMPORT_INTRUSION_SETS",
            ["malpedia", "import_intrusion_sets"],
            config,
        )
        self.import_yara = get_config_variable(
            "MALPEDIA_IMPORT_YARA", ["malpedia", "import_yara"], config
        )

        self.helper = OpenCTIConnectorHelper(config)
        self.helper.log_info(f"loaded malpedia config: {config}")

        # Create Malpedia client and importers
        self.client = MalpediaClient(self.AUTH_KEY)
        if not self.client.health_check():
            self.helper.log_error("error in malpedia API health check")

        # If we run without API key we can assume all data is TLP:WHITE else we
        # default to TLP:AMBER to be safe.
        if self.AUTH_KEY == "" or self.AUTH_KEY is None:
            self.default_marking = self.helper.api.marking_definition.read(
                id=TLP_WHITE["id"]
            )
        else:
            self.default_marking = self.helper.api.marking_definition.read(
                id=TLP_AMBER["id"]
            )

        self.knowledge_importer = KnowledgeImporter(
            self.helper,
            self.client,
            self.confidence_level,
            self.update_existing_data,
            self.import_intrusion_sets,
            self.import_yara,
            self.default_marking,
        )

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
        return time_diff >= int(self.INTERVAL_SEC)

    def _check_version(self, last_version: Optional[int], current_version: int) -> bool:
        if last_version is None:
            return True
        return current_version > last_version

    @staticmethod
    def _current_unix_timestamp() -> int:
        return int(datetime.utcnow().timestamp())

    def run(self):
        self.helper.log_info("starting Malpedia connector...")
        while True:
            try:
                current_malpedia_version = self.client.current_version()
                self.helper.log_info(
                    f"current Malpedia version: {current_malpedia_version}"
                )
                timestamp = self._current_unix_timestamp()
                current_state = self._load_state()

                self.helper.log_info(f"loaded state: {current_state}")

                last_run = self._get_state_value(current_state, self._STATE_LAST_RUN)

                last_malpedia_version = self._get_state_value(
                    current_state, self._MALPEDIA_LAST_VERSION
                )

                # Only run the connector if:
                #  1. It is scheduled to run per interval
                #  2. The global Malpedia version from the API is newer than our
                #     last stored version.
                if self._is_scheduled(last_run, timestamp) and self._check_version(
                    last_malpedia_version, current_malpedia_version
                ):
                    self.helper.log_info("running importers")

                    knowledge_importer_state = self._run_knowledge_importer(
                        current_state
                    )
                    self.helper.log_info("done with running importers")

                    new_state = current_state.copy()
                    new_state.update(knowledge_importer_state)
                    new_state[self._STATE_LAST_RUN] = self._current_unix_timestamp()
                    new_state[self._MALPEDIA_LAST_VERSION] = current_malpedia_version

                    self.helper.log_info(f"storing new state: {new_state}")

                    self.helper.set_state(new_state)

                    self.helper.log_info(
                        f"state stored, next run in: {self.get_interval()} seconds"
                    )
                else:
                    new_interval = self.get_interval() - (timestamp - last_run)
                    self.helper.log_info(
                        f"connector will not run, next run in: {new_interval} seconds"
                    )

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
