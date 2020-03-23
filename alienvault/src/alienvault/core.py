# -*- coding: utf-8 -*-
"""OpenCTI AlienVault connector module."""

import os
import time
from typing import Any, Dict, List, Mapping, Optional

import yaml

from pycti.connector.opencti_connector_helper import (
    OpenCTIConnectorHelper,
    get_config_variable,
)
from pycti.utils.constants import CustomProperties

from stix2 import Identity, MarkingDefinition, TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE

from alienvault.client import AlienVaultClient
from alienvault.importer import PulseImporter


class AlienVault:
    """AlienVault connector."""

    _CONFIG_NAMESPACE = "alienvault"

    _CONFIG_BASE_URL = f"{_CONFIG_NAMESPACE}.base_url"
    _CONFIG_API_KEY = f"{_CONFIG_NAMESPACE}.api_key"
    _CONFIG_TLP = f"{_CONFIG_NAMESPACE}.tlp"
    _CONFIG_PULSE_START_TIMESTAMP = f"{_CONFIG_NAMESPACE}.pulse_start_timestamp"
    _CONFIG_REPORT_STATUS = f"{_CONFIG_NAMESPACE}.report_status"
    _CONFIG_REPORT_TYPE = f"{_CONFIG_NAMESPACE}.report_type"
    _CONFIG_INTERVAL_SEC = f"{_CONFIG_NAMESPACE}.interval_sec"

    _CONFIG_UPDATE_EXISTING_DATA = "connector.update_existing_data"

    _CONFIG_TLP_MAPPING = {
        "white": TLP_WHITE,
        "green": TLP_GREEN,
        "amber": TLP_AMBER,
        "red": TLP_RED,
    }

    _CONFIG_REPORT_STATUS_MAPPING = {
        "new": 0,
        "in progress": 1,
        "analyzed": 2,
        "closed": 3,
    }

    _CONNECTOR_RUN_INTERVAL_SEC = 60

    _STATE_LAST_RUN = "last_run"

    def __init__(self) -> None:
        """Initialize AlienVault connector."""
        config = self._read_configuration()

        self.helper = OpenCTIConnectorHelper(config)

        # AlienVault connector configuration
        base_url = self._get_configuration(config, self._CONFIG_BASE_URL)
        api_key = self._get_configuration(config, self._CONFIG_API_KEY)

        tlp = self._get_configuration(config, self._CONFIG_TLP)
        tlp_marking = self._convert_tlp_to_marking_definition(tlp)

        default_latest_pulse_timestamp = self._get_configuration(
            config, self._CONFIG_PULSE_START_TIMESTAMP
        )

        report_status_str = self._get_configuration(config, self._CONFIG_REPORT_STATUS)
        report_type = self._get_configuration(config, self._CONFIG_REPORT_TYPE)
        report_status = self._convert_report_status_str_to_report_status_int(
            report_status_str
        )

        self.interval_sec = self._get_configuration(
            config, self._CONFIG_INTERVAL_SEC, is_number=True
        )

        update_existing_data = self._get_configuration(
            config, self._CONFIG_UPDATE_EXISTING_DATA
        )

        author = self._create_author()

        # Create AlienVault client
        client = AlienVaultClient(base_url, api_key)

        # Create pulse importer
        self.pulse_importer = PulseImporter(
            self.helper,
            client,
            author,
            tlp_marking,
            update_existing_data,
            default_latest_pulse_timestamp,
            report_status,
            report_type,
        )

    @staticmethod
    def _create_author() -> Identity:
        return Identity(
            name="AlienVault",
            identity_class="organization",
            custom_properties={CustomProperties.IDENTITY_TYPE: "organization"},
        )

    @staticmethod
    def _read_configuration() -> Dict[str, str]:
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/../config.yml"
        if not os.path.isfile(config_file_path):
            return {}
        return yaml.load(open(config_file_path), Loader=yaml.FullLoader)

    @classmethod
    def _get_configuration(
        cls, config: Dict[str, Any], config_name: str, is_number: bool = False
    ) -> Any:
        yaml_path = cls._get_yaml_path(config_name)
        env_var_name = cls._get_environment_variable_name(yaml_path)
        config_value = get_config_variable(
            env_var_name, yaml_path, config, isNumber=is_number
        )
        return config_value

    @staticmethod
    def _get_yaml_path(config_name: str) -> List[str]:
        return config_name.split(".")

    @staticmethod
    def _get_environment_variable_name(yaml_path: List[str]) -> str:
        return "_".join(yaml_path).upper()

    @classmethod
    def _convert_tlp_to_marking_definition(
        cls, tlp_value: Optional[str]
    ) -> MarkingDefinition:
        if tlp_value is None:
            return TLP_WHITE
        return cls._CONFIG_TLP_MAPPING[tlp_value.lower()]

    @classmethod
    def _convert_report_status_str_to_report_status_int(cls, report_status: str) -> int:
        return cls._CONFIG_REPORT_STATUS_MAPPING[report_status.lower()]

    def run(self):
        self._info("Starting AlienVault connector...")
        while True:
            self._info("Running AlienVault connector...")
            try:
                timestamp = self._current_unix_timestamp()
                current_state = self._load_state()

                self._info("Loaded state: {0}", current_state)

                last_run = self._get_state_value(current_state, self._STATE_LAST_RUN)
                if self._is_scheduled(last_run, timestamp):
                    pulse_import_state = self.pulse_importer.run(current_state)

                    new_state = current_state.copy()
                    new_state.update(pulse_import_state)
                    new_state[self._STATE_LAST_RUN] = self._current_unix_timestamp()

                    self._info("Storing new state: {0}", new_state)

                    self.helper.set_state(new_state)

                    self._info(
                        "State stored, next run in: {0} seconds", self._get_interval()
                    )
                else:
                    next_run = self._get_interval() - (timestamp - last_run)
                    self._info(
                        "Connector will not run, next run in: {0} seconds", next_run
                    )

                self._sleep()
            except (KeyboardInterrupt, SystemExit):
                self._info("Connector stop")
                exit(0)
            except Exception as e:
                self._error(str(e))
                self._sleep()

    @classmethod
    def _sleep(cls) -> None:
        time.sleep(cls._CONNECTOR_RUN_INTERVAL_SEC)

    @staticmethod
    def _current_unix_timestamp() -> int:
        return int(time.time())

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
            self._info("Connector first run")
            return True
        time_diff = current_time - last_run
        return time_diff >= self._get_interval()

    def _get_interval(self) -> int:
        return int(self.interval_sec)

    def _info(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_info(fmt_msg)

    def _error(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_error(fmt_msg)
