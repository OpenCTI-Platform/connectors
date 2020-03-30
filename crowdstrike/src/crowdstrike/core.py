# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike connector core module."""

import os
import time
from typing import Dict, Any, Optional, List, Mapping

import yaml
from crowdstrike_client.client import CrowdStrikeClient
from pycti import OpenCTIConnectorHelper
from pycti.connector.opencti_connector_helper import get_config_variable
from stix2 import (
    Identity,
    TLP_RED,
    MarkingDefinition,
    TLP_WHITE,
    TLP_GREEN,
    TLP_AMBER,
)

from crowdstrike.actors import ActorImporter
from crowdstrike.indicators import IndicatorImporter
from crowdstrike.reports import ReportImporter
from crowdstrike.utils import create_organization, convert_comma_separated_str_to_list


class CrowdStrike:
    """CrowdStrike connector."""

    _CONFIG_NAMESPACE = "crowdstrike"

    _CONFIG_BASE_URL = f"{_CONFIG_NAMESPACE}.base_url"
    _CONFIG_CLIENT_ID = f"{_CONFIG_NAMESPACE}.client_id"
    _CONFIG_CLIENT_SECRET = f"{_CONFIG_NAMESPACE}.client_secret"
    _CONFIG_INTERVAL_SEC = f"{_CONFIG_NAMESPACE}.interval_sec"
    _CONFIG_SCOPES = f"{_CONFIG_NAMESPACE}.scopes"
    _CONFIG_TLP = f"{_CONFIG_NAMESPACE}.tlp"
    _CONFIG_ACTOR_START_TIMESTAMP = f"{_CONFIG_NAMESPACE}.actor_start_timestamp"
    _CONFIG_REPORT_START_TIMESTAMP = f"{_CONFIG_NAMESPACE}.report_start_timestamp"
    _CONFIG_REPORT_INCLUDE_TYPES = f"{_CONFIG_NAMESPACE}.report_include_types"
    _CONFIG_REPORT_STATUS = f"{_CONFIG_NAMESPACE}.report_status"
    _CONFIG_REPORT_TYPE = f"{_CONFIG_NAMESPACE}.report_type"
    _CONFIG_INDICATOR_START_TIMESTAMP = f"{_CONFIG_NAMESPACE}.indicator_start_timestamp"
    _CONFIG_INDICATOR_EXCLUDE_TYPES = f"{_CONFIG_NAMESPACE}.indicator_exclude_types"

    _CONFIG_UPDATE_EXISTING_DATA = "connector.update_existing_data"

    _CONFIG_SCOPE_ACTOR = "actor"
    _CONFIG_SCOPE_REPORT = "report"
    _CONFIG_SCOPE_INDICATOR = "indicator"

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

    _DEFAULT_REPORT_TYPE = "Threat Report"

    _STATE_LAST_RUN = "last_run"

    def __init__(self) -> None:
        """Initialize CrowdStrike connector."""
        config = self._read_configuration()

        self.helper = OpenCTIConnectorHelper(config)

        # CrowdStrike connector configuration
        base_url = self._get_configuration(config, self._CONFIG_BASE_URL)
        client_id = self._get_configuration(config, self._CONFIG_CLIENT_ID)
        client_secret = self._get_configuration(config, self._CONFIG_CLIENT_SECRET)

        self.interval_sec = self._get_configuration(
            config, self._CONFIG_INTERVAL_SEC, is_number=True
        )

        scopes_str = self._get_configuration(config, self._CONFIG_SCOPES)
        scopes = set()
        if scopes_str is not None:
            scopes = set(convert_comma_separated_str_to_list(scopes_str))
        self.scopes = scopes

        tlp = self._get_configuration(config, self._CONFIG_TLP)
        self.tlp_marking = self._convert_tlp_to_marking_definition(tlp)

        actor_start_timestamp = self._get_configuration(
            config, self._CONFIG_ACTOR_START_TIMESTAMP, is_number=True
        )

        report_start_timestamp = self._get_configuration(
            config, self._CONFIG_REPORT_START_TIMESTAMP, is_number=True
        )

        report_status_str = self._get_configuration(config, self._CONFIG_REPORT_STATUS)
        self.report_status = self._convert_report_status_str_to_report_status_int(
            report_status_str
        )

        report_type = self._get_configuration(config, self._CONFIG_REPORT_TYPE)
        if not report_type:
            report_type = self._DEFAULT_REPORT_TYPE

        report_include_types_str = self._get_configuration(
            config, self._CONFIG_REPORT_INCLUDE_TYPES
        )
        report_include_types = []
        if report_include_types_str is not None:
            report_include_types = convert_comma_separated_str_to_list(
                report_include_types_str
            )

        indicator_start_timestamp = self._get_configuration(
            config, self._CONFIG_INDICATOR_START_TIMESTAMP, is_number=True
        )

        indicator_exclude_types_str = self._get_configuration(
            config, self._CONFIG_INDICATOR_EXCLUDE_TYPES
        )
        indicator_exclude_types = []
        if indicator_exclude_types_str is not None:
            indicator_exclude_types = convert_comma_separated_str_to_list(
                indicator_exclude_types_str
            )

        update_existing_data = self._get_configuration(
            config, self._CONFIG_UPDATE_EXISTING_DATA
        )

        # Create CrowdStrike client and importers
        self.client = CrowdStrikeClient(base_url, client_id, client_secret)

        self.author = self._create_author()

        self.actor_importer = ActorImporter(
            self.helper,
            self.client.intel_api.actors,
            update_existing_data,
            self.author,
            actor_start_timestamp,
            self.tlp_marking,
        )

        self.report_importer = ReportImporter(
            self.helper,
            self.client.intel_api.reports,
            update_existing_data,
            self.author,
            report_start_timestamp,
            self.tlp_marking,
            report_include_types,
            self.report_status,
            report_type,
        )

        self.indicator_importer = IndicatorImporter(
            self.helper,
            self.client.intel_api.indicators,
            self.client.intel_api.reports,
            update_existing_data,
            self.author,
            indicator_start_timestamp,
            self.tlp_marking,
            indicator_exclude_types,
            self.report_status,
            report_type,
        )

    @staticmethod
    def _read_configuration() -> Dict[str, str]:
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/../config.yml"
        if not os.path.isfile(config_file_path):
            return {}
        return yaml.load(open(config_file_path), Loader=yaml.FullLoader)

    @staticmethod
    def _create_author() -> Identity:
        return create_organization("CrowdStrike")

    @staticmethod
    def _get_yaml_path(config_name: str) -> List[str]:
        return config_name.split(".")

    @staticmethod
    def _get_environment_variable_name(yaml_path: List[str]) -> str:
        return "_".join(yaml_path).upper()

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

    @classmethod
    def _convert_tlp_to_marking_definition(cls, tlp_value: str) -> MarkingDefinition:
        return cls._CONFIG_TLP_MAPPING[tlp_value.lower()]

    @classmethod
    def _convert_report_status_str_to_report_status_int(cls, report_status: str) -> int:
        return cls._CONFIG_REPORT_STATUS_MAPPING[report_status.lower()]

    def get_interval(self) -> int:
        return int(self.interval_sec)

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
        return time_diff >= self.get_interval()

    @staticmethod
    def _current_unix_timestamp() -> int:
        return int(time.time())

    def run(self):
        self.helper.log_info("Starting CrowdStrike connector...")
        while True:
            try:
                timestamp = self._current_unix_timestamp()
                current_state = self._load_state()

                self.helper.log_info(f"Loaded state: {current_state}")

                last_run = self._get_state_value(current_state, self._STATE_LAST_RUN)
                if self._is_scheduled(last_run, timestamp):
                    actor_importer_state = self._run_actor_importer(current_state)
                    report_importer_state = self._run_report_importer(current_state)
                    indicator_importer_state = self._run_indicator_importer(
                        current_state
                    )

                    new_state = current_state.copy()
                    new_state.update(actor_importer_state)
                    new_state.update(report_importer_state)
                    new_state.update(indicator_importer_state)
                    new_state[self._STATE_LAST_RUN] = self._current_unix_timestamp()

                    self.helper.log_info(f"Storing new state: {new_state}")

                    self.helper.set_state(new_state)

                    self.helper.log_info(
                        f"State stored, next run in: {self.get_interval()} seconds"
                    )
                else:
                    new_interval = self.get_interval() - (timestamp - last_run)
                    self.helper.log_info(
                        f"Connector will not run, next run in: {new_interval} seconds"
                    )

                time.sleep(60)
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
                time.sleep(60)

    def _run_actor_importer(
        self, current_state: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        if self._is_scope_enabled(self._CONFIG_SCOPE_ACTOR):
            return self.actor_importer.run(current_state)
        return {}

    def _run_report_importer(
        self, current_state: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        if self._is_scope_enabled(self._CONFIG_SCOPE_REPORT):
            return self.report_importer.run(current_state)
        return {}

    def _run_indicator_importer(
        self, current_state: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        if self._is_scope_enabled(self._CONFIG_SCOPE_INDICATOR):
            return self.indicator_importer.run(current_state)
        return {}

    def _is_scope_enabled(self, scope: str) -> bool:
        result = scope in self.scopes
        if not result:
            self.helper.log_info(f"Scope '{scope}' is not enabled")
        return result
