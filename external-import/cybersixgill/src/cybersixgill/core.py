"""OpenCTI Cybersixgill Darkfeed connector core module."""

import os
import sys
import time
from typing import Any, Dict, List, Mapping, Optional

import stix2
import yaml
from pycti import OpenCTIConnectorHelper  # type: ignore
from pycti.connector.opencti_connector_helper import get_config_variable  # type: ignore

from cybersixgill.client import CybersixgillClient
from cybersixgill.importer import IndicatorImporter, IndicatorImporterConfig
from cybersixgill.utils import create_organization, timestamp_to_datetime


class Cybersixgill:
    """Cybersixgill Darkfeed connector."""

    _CONFIG_NAMESPACE = "cybersixgill"

    _CONFIG_CLIENT_ID = f"{_CONFIG_NAMESPACE}.client_id"
    _CONFIG_CLIENT_SECRET = f"{_CONFIG_NAMESPACE}.client_secret"
    _CONFIG_CREATE_OBSERVABLES = f"{_CONFIG_NAMESPACE}.create_observables"
    _CONFIG_CREATE_INDICATORS = f"{_CONFIG_NAMESPACE}.create_indicators"
    _CONFIG_FETCH_SIZE = f"{_CONFIG_NAMESPACE}.fetch_size"
    _CONFIG_INTERVAL_SEC = f"{_CONFIG_NAMESPACE}.interval_sec"
    _CONFIG_ENABLE_RELATIONSHIPS = f"{_CONFIG_NAMESPACE}.enable_relationships"

    _CONFIG_UPDATE_EXISTING_DATA = "connector.update_existing_data"

    _DEFAULT_CREATE_OBSERVABLES = True
    _DEFAULT_CREATE_INDICATORS = True
    _DEFAULT_ENABLE_RELATIONSHIPS = True

    _CONNECTOR_RUN_INTERVAL_SEC = 60

    _STATE_LAST_RUN = "last_run"

    def __init__(self) -> None:
        """Initialize Cybersixgill Darkfeed connector."""
        config = self._read_configuration()

        # Cybersixgill connector configuration
        client_id = self._get_configuration(config, self._CONFIG_CLIENT_ID)
        client_secret = self._get_configuration(config, self._CONFIG_CLIENT_SECRET)

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

        enable_relationships = self._get_configuration(
            config, self._CONFIG_ENABLE_RELATIONSHIPS
        )
        if enable_relationships is None:
            enable_relationships = self._DEFAULT_ENABLE_RELATIONSHIPS
        else:
            enable_relationships = bool(enable_relationships)

        fetch_size = self._get_configuration(config, self._CONFIG_FETCH_SIZE)

        self.interval_sec = self._get_configuration(
            config, self._CONFIG_INTERVAL_SEC, is_number=True
        )

        update_existing_data = bool(
            self._get_configuration(config, self._CONFIG_UPDATE_EXISTING_DATA)
        )

        # Create OpenCTI connector helper
        self.helper = OpenCTIConnectorHelper(config)

        # Create Cybersixgill author
        author = self._create_author()

        # Create Cybersixgill client
        client = CybersixgillClient(client_id, client_secret, fetch_size)

        # Create indicator importer
        indicator_importer_config = IndicatorImporterConfig(
            helper=self.helper,
            client=client,
            author=author,
            create_observables=create_observables,
            create_indicators=create_indicators,
            update_existing_data=update_existing_data,
            enable_relationships=enable_relationships,
            fetch_size=fetch_size,
        )

        self.indicator_importer = IndicatorImporter(indicator_importer_config)

    @staticmethod
    def _create_author() -> stix2.Identity:
        return create_organization("Cybersixgill")

    @staticmethod
    def _read_configuration() -> Dict[str, str]:
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "\..\config.yml"

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

    def run(self):
        """Run Cybersixgill Darkfeed connector."""
        self._info("Starting Cybersixgill Darkfeed connector...")
        while True:
            self._info("Running Cybersixgill Darkfeed connector...")
            run_interval = self._CONNECTOR_RUN_INTERVAL_SEC

            try:
                timestamp = self._current_unix_timestamp()
                current_state = self._load_state()

                self._info("Loaded state: {0}", current_state)

                last_run = self._get_state_value(current_state, self._STATE_LAST_RUN)

                if self._is_scheduled(last_run, timestamp):
                    work_id = self._initiate_work(timestamp)

                    importer_state = self.indicator_importer.run(current_state, work_id)
                    new_state = current_state.copy()

                    new_state.update(importer_state)

                    new_state[self._STATE_LAST_RUN] = self._current_unix_timestamp()

                    self._info("Storing new state: {0}", new_state)
                    self.helper.set_state(new_state)

                    message = (
                        f"State stored, next run in: {self._get_interval()} seconds"
                    )

                    self._info(message)

                    self._complete_work(work_id, message)
                else:
                    next_run = self._get_interval() - (timestamp - last_run)
                    run_interval = min(run_interval, next_run)

                    self._info(
                        "Connector will not run, next run in: {0} seconds", next_run
                    )
            except (KeyboardInterrupt, SystemExit):
                self._info("Cybersixgill Darkfeed connector stopping...")
                sys.exit(0)

            except Exception as e:  # noqa: B902
                self._error(
                    "Cybersixgill Darkfeed connector internal error: {0}", str(e)
                )

                if self.helper.connect_run_and_terminate:
                    self.helper.log_info("Connector stop")
                    sys.exit(0)

                self._sleep(delay_sec=run_interval)

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
            self._info("Cybersixgill Darkfeed connector clean run")
            return True

        time_diff = current_time - last_run
        return time_diff >= self._get_interval()

    def _initiate_work(self, timestamp: int) -> str:
        datetime_str = timestamp_to_datetime(timestamp)

        friendly_name = f"{self.helper.connect_name} @ {datetime_str}"

        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )

        self._info("New work '{0}' initiated", work_id)

        return work_id

    def _complete_work(self, work_id: str, message: str) -> None:
        self.helper.api.work.to_processed(work_id, message)

    def _get_interval(self) -> int:
        return int(self.interval_sec)

    def _info(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_info(fmt_msg)

    def _error(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_error(fmt_msg)
