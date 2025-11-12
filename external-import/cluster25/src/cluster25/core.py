import datetime
import json
import os
import sys
import time
from typing import Any, Dict, List, Mapping, Optional

import requests
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable


class Cluster25:
    _CONFIG_NAMESPACE = "cluster25"

    _CONFIG_BASE_URL = f"{_CONFIG_NAMESPACE}.base_url"
    _CONFIG_CLIENT_ID = f"{_CONFIG_NAMESPACE}.client_id"
    _CONFIG_CLIENT_SECRET = f"{_CONFIG_NAMESPACE}.client_secret"

    _CONFIG_INDICATOR_TYPES = f"{_CONFIG_NAMESPACE}.indicator_types"
    _CONFIG_INTERVAL_SEC = f"{_CONFIG_NAMESPACE}.interval_sec"

    _CONNECTOR_RUN_INTERVAL_SEC = 600
    _TZ_INFO = datetime.datetime.now().astimezone().tzinfo

    _STATE_LAST_RUN = "last_run"
    _ALLOWED_INDICATOR_TYPES = [
        "ipv4",
        "domain",
        "md5",
        "sha1",
        "sha256",
        "url",
        "email",
        "ipv6",
        "filename",
    ]

    def __init__(self) -> None:
        # Instantiate the connector helper from config
        config = self._read_configuration()

        # Create OpenCTI connector helper
        self.helper = OpenCTIConnectorHelper(config)

        # Cluster25 connector configuration
        self.base_url = self._get_configuration(config, self._CONFIG_BASE_URL)
        self.client_id = self._get_configuration(config, self._CONFIG_CLIENT_ID)
        self.client_secret = self._get_configuration(config, self._CONFIG_CLIENT_SECRET)

        self.interval_sec = (
            self._get_configuration(config, self._CONFIG_INTERVAL_SEC, is_number=True)
            or self._CONNECTOR_RUN_INTERVAL_SEC
        )

        self.current_token = None
        self.last_token_timestamp = None

        self.indicator_types = (
            self._get_configuration(config, self._CONFIG_INDICATOR_TYPES, is_list=True)
            or self._ALLOWED_INDICATOR_TYPES
        )

    @staticmethod
    def _get_yaml_path(config_name: str) -> List[str]:
        return config_name.split(".")

    @staticmethod
    def _get_environment_variable_name(yaml_path: List[str]) -> str:
        return "_".join(yaml_path).upper()

    @staticmethod
    def _read_configuration() -> Dict[str, str]:
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/../config.yml"
        if not os.path.isfile(config_file_path):
            return {}
        return yaml.load(open(config_file_path), Loader=yaml.FullLoader)

    @classmethod
    def _get_configuration(
        cls,
        config: Dict[str, Any],
        config_name: str,
        is_number: bool = False,
        is_list: bool = False,
    ) -> Any:
        yaml_path = cls._get_yaml_path(config_name)
        env_var_name = cls._get_environment_variable_name(yaml_path)

        if is_list:
            values = get_config_variable(env_var_name, yaml_path, config)
            return values.split(",") if not isinstance(values, list) else values

        return get_config_variable(env_var_name, yaml_path, config, isNumber=is_number)

    def _get_interval(self) -> int:
        return int(self.interval_sec)

    @classmethod
    def _sleep(cls, delay_sec: Optional[int] = None) -> None:
        time.sleep(
            delay_sec if delay_sec is not None else cls._CONNECTOR_RUN_INTERVAL_SEC
        )

    @staticmethod
    def _current_unix_timestamp() -> int:
        return int(time.time())

    @staticmethod
    def _get_state_value(
        state: Optional[Mapping[str, Any]], key: str, default: Optional[Any] = None
    ) -> Any:
        if state is not None:
            return state.get(key, default)
        return default

    def _is_scheduled(self, last_run: Optional[int], current_time: int) -> bool:
        if last_run is None:
            self.helper.log_info("Connector first run")
            return True
        time_diff = current_time - last_run
        return time_diff >= self._get_interval()

    def _load_state(self) -> Dict[str, Any]:
        return self.helper.get_state() or {}

    def _get_cluster25_token(self) -> str:
        payload = {"client_id": self.client_id, "client_secret": self.client_secret}
        r = requests.post(url=f"{self.base_url}/token", json=payload)

        if r.status_code != 200:
            self.helper.log_error(
                f"Unable to retrieve the token from C25 platform, status {r.status_code}"
            )
            self.helper.log_info("Connector stop")
            sys.exit(0)

        return r.json()["data"]["token"]

    def _get_c25_observables(self, timestamp: int) -> Dict[str, Any]:
        params = {
            "export_format": "stix2",
            "types": self.indicator_types,
            "start": datetime.datetime.fromtimestamp(timestamp)
            .replace(tzinfo=self._TZ_INFO)
            .isoformat(),
            "include_info": True,
        }
        headers = {"Authorization": f"Bearer {self.current_token}"}

        self.helper.log_debug(
            f"IOC from {datetime.datetime.fromtimestamp(timestamp).isoformat()} to {datetime.datetime.now().isoformat()}"
        )

        r = requests.get(
            url=f"{self.base_url}/export/indicators", params=params, headers=headers
        )

        if r.status_code != 200:
            self.helper.log_error(
                f"Unable to retrieve observables from C25 platform, status {r.status_code}"
            )
            self.helper.log_info("Connector stop")
            sys.exit(0)

        return r.json()

    def run(self):
        """Run Cluster25 connector."""
        self.helper.log_info("Starting Cluster25 connector...")

        # Get a new C25 token
        self.current_token = self._get_cluster25_token()
        self.last_token_timestamp = self._current_unix_timestamp()

        while True:
            self.helper.log_info("Running Cluster25 connector...")
            run_interval = self._CONNECTOR_RUN_INTERVAL_SEC
            timestamp = self._current_unix_timestamp()

            # Refresh C25 token
            if timestamp > self.last_token_timestamp:
                self.current_token = self._get_cluster25_token()
                self.last_token_timestamp = self._current_unix_timestamp()

            try:
                current_state = self._load_state()

                self.helper.log_info(f"Loaded state: {current_state}")

                last_run = self._get_state_value(current_state, self._STATE_LAST_RUN)
                if self._is_scheduled(last_run, timestamp):
                    now = datetime.datetime.utcfromtimestamp(timestamp)
                    friendly_name = (
                        f"Cluster25 run @ {now.strftime('%Y-%m-%d %H:%M:%S')}"
                    )
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )

                    bundle = self._get_c25_observables(timestamp - self._get_interval())

                    if "objects" in bundle:
                        self.helper.log_info(
                            f"Uploading: {len(bundle['objects'])} observables"
                        )
                        self.helper.send_stix2_bundle(
                            json.dumps(bundle),
                            entities_types=self.helper.connect_scope,
                            work_id=work_id,
                        )

                    new_state = current_state.copy()
                    new_state[self._STATE_LAST_RUN] = self._current_unix_timestamp()

                    self.helper.log_info(f"Storing new state: {new_state}")
                    self.helper.set_state(new_state)
                    message = (
                        f"State stored, next run in: {self._get_interval()} seconds"
                    )
                    self.helper.api.work.to_processed(work_id, message)
                    self.helper.log_info(message)
                else:
                    next_run = self._get_interval() - (timestamp - last_run)
                    run_interval = min(run_interval, next_run)

                    self.helper.log_info(
                        f"Connector will not run, next run in: {next_run} seconds"
                    )

            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                sys.exit(0)

            if self.helper.connect_run_and_terminate:
                self.helper.log_info("Connector stop")
                self.helper.force_ping()
                sys.exit(0)

            self._sleep(delay_sec=run_interval)
