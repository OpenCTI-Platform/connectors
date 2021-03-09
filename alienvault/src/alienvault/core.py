# -*- coding: utf-8 -*-
"""OpenCTI AlienVault connector module."""

import os
import time
import datetime
from typing import Any, Dict, List, Mapping, Optional

import yaml

from pycti.connector.opencti_connector_helper import (  # type: ignore
    OpenCTIConnectorHelper,
    get_config_variable,
)

from stix2 import Identity, MarkingDefinition  # type: ignore

from alienvault.client import AlienVaultClient
from alienvault.importer import PulseImporter
from alienvault.utils import (
    convert_comma_separated_str_to_list,
    create_organization,
    get_tlp_string_marking_definition,
)
from alienvault.utils.constants import DEFAULT_TLP_MARKING_DEFINITION


class AlienVault:
    """AlienVault connector."""

    _CONFIG_NAMESPACE = "alienvault"

    _CONFIG_BASE_URL = f"{_CONFIG_NAMESPACE}.base_url"
    _CONFIG_API_KEY = f"{_CONFIG_NAMESPACE}.api_key"
    _CONFIG_TLP = f"{_CONFIG_NAMESPACE}.tlp"
    _CONFIG_CREATE_OBSERVABLES = f"{_CONFIG_NAMESPACE}.create_observables"
    _CONFIG_CREATE_INDICATORS = f"{_CONFIG_NAMESPACE}.create_indicators"
    _CONFIG_PULSE_START_TIMESTAMP = f"{_CONFIG_NAMESPACE}.pulse_start_timestamp"
    _CONFIG_REPORT_STATUS = f"{_CONFIG_NAMESPACE}.report_status"
    _CONFIG_REPORT_TYPE = f"{_CONFIG_NAMESPACE}.report_type"
    _CONFIG_GUESS_MALWARE = f"{_CONFIG_NAMESPACE}.guess_malware"
    _CONFIG_GUESS_CVE = f"{_CONFIG_NAMESPACE}.guess_cve"
    _CONFIG_EXCLUDED_PULSE_INDICATOR_TYPES = (
        f"{_CONFIG_NAMESPACE}.excluded_pulse_indicator_types"
    )
    _CONFIG_INTERVAL_SEC = f"{_CONFIG_NAMESPACE}.interval_sec"

    _CONFIG_UPDATE_EXISTING_DATA = "connector.update_existing_data"

    _CONFIG_REPORT_STATUS_MAPPING = {
        "new": 0,
        "in progress": 1,
        "analyzed": 2,
        "closed": 3,
    }

    _DEFAULT_CREATE_OBSERVABLES = True
    _DEFAULT_CREATE_INDICATORS = True
    _DEFAULT_REPORT_TYPE = "threat-report"

    _CONNECTOR_RUN_INTERVAL_SEC = 60

    _STATE_LAST_RUN = "last_run"

    def __init__(self) -> None:
        """Initialize AlienVault connector."""
        config = self._read_configuration()

        # AlienVault connector configuration
        base_url = self._get_configuration(config, self._CONFIG_BASE_URL)
        api_key = self._get_configuration(config, self._CONFIG_API_KEY)

        tlp = self._get_configuration(config, self._CONFIG_TLP)
        tlp_marking = self._convert_tlp_to_marking_definition(tlp)

        create_observables = self._get_configuration(
            config, self._CONFIG_CREATE_OBSERVABLES
        )
        if create_observables is None:
            create_observables = self._DEFAULT_CREATE_OBSERVABLES
        else:
            create_observables = bool(create_observables)

        create_indicators = self._get_configuration(
            config, self._CONFIG_CREATE_INDICATORS
        )
        if create_indicators is None:
            create_indicators = self._DEFAULT_CREATE_INDICATORS
        else:
            create_indicators = bool(create_indicators)

        default_latest_pulse_timestamp = self._get_configuration(
            config, self._CONFIG_PULSE_START_TIMESTAMP
        )

        report_status_str = self._get_configuration(config, self._CONFIG_REPORT_STATUS)
        report_status = self._convert_report_status_str_to_report_status_int(
            report_status_str
        )

        report_type = self._get_configuration(config, self._CONFIG_REPORT_TYPE)
        if not report_type:
            report_type = self._DEFAULT_REPORT_TYPE

        guess_malware = bool(
            self._get_configuration(config, self._CONFIG_GUESS_MALWARE)
        )

        guess_cve = bool(self._get_configuration(config, self._CONFIG_GUESS_CVE))

        excluded_pulse_indicator_types_str = self._get_configuration(
            config, self._CONFIG_EXCLUDED_PULSE_INDICATOR_TYPES
        )
        excluded_pulse_indicator_types = set()
        if excluded_pulse_indicator_types_str is not None:
            excluded_pulse_indicator_types_list = convert_comma_separated_str_to_list(
                excluded_pulse_indicator_types_str
            )
            excluded_pulse_indicator_types = set(excluded_pulse_indicator_types_list)

        self.interval_sec = self._get_configuration(
            config, self._CONFIG_INTERVAL_SEC, is_number=True
        )

        update_existing_data = bool(
            self._get_configuration(config, self._CONFIG_UPDATE_EXISTING_DATA)
        )

        # Create OpenCTI connector helper
        self.helper = OpenCTIConnectorHelper(config)

        # Create AlienVault author
        author = self._create_author()

        # Create AlienVault client
        client = AlienVaultClient(base_url, api_key)

        # Create pulse importer
        self.pulse_importer = PulseImporter(
            self.helper,
            client,
            author,
            tlp_marking,
            create_observables,
            create_indicators,
            update_existing_data,
            default_latest_pulse_timestamp,
            report_status,
            report_type,
            guess_malware,
            guess_cve,
            excluded_pulse_indicator_types,
        )

    @staticmethod
    def _create_author() -> Identity:
        return create_organization("AlienVault")

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
            return DEFAULT_TLP_MARKING_DEFINITION
        return get_tlp_string_marking_definition(tlp_value)

    @classmethod
    def _convert_report_status_str_to_report_status_int(cls, report_status: str) -> int:
        return cls._CONFIG_REPORT_STATUS_MAPPING[report_status.lower()]

    def run(self):
        """Run AlienVault connector."""
        self._info("Starting AlienVault connector...")
        while True:
            self._info("Running AlienVault connector...")
            run_interval = self._CONNECTOR_RUN_INTERVAL_SEC

            try:
                timestamp = self._current_unix_timestamp()
                current_state = self._load_state()

                self._info("Loaded state: {0}", current_state)

                last_run = self._get_state_value(current_state, self._STATE_LAST_RUN)
                if self._is_scheduled(last_run, timestamp):
                    now = datetime.datetime.utcfromtimestamp(timestamp)
                    friendly_name = "AlienVault run @ " + now.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )
                    pulse_import_state = self.pulse_importer.run(current_state, work_id)
                    new_state = current_state.copy()
                    new_state.update(pulse_import_state)
                    new_state[self._STATE_LAST_RUN] = self._current_unix_timestamp()

                    self._info("Storing new state: {0}", new_state)
                    self.helper.set_state(new_state)
                    message = (
                        "State stored, next run in: "
                        + str(self._get_interval())
                        + " seconds"
                    )
                    self.helper.api.work.to_processed(work_id, message)
                    self._info(message)
                else:
                    next_run = self._get_interval() - (timestamp - last_run)
                    run_interval = min(run_interval, next_run)

                    self._info(
                        "Connector will not run, next run in: {0} seconds", next_run
                    )

                self._sleep(delay_sec=run_interval)
            except (KeyboardInterrupt, SystemExit):
                self._info("Connector stop")
                exit(0)
            except Exception as e:  # noqa: B902
                self._error("Internal error: {0}", str(e))
                self._sleep()

    @classmethod
    def _sleep(cls, delay_sec: Optional[int] = None) -> None:
        sleep_delay = (
            delay_sec if delay_sec is not None else cls._CONNECTOR_RUN_INTERVAL_SEC
        )
        time.sleep(sleep_delay)

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
