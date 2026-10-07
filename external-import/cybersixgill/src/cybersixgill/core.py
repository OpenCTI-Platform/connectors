"""OpenCTI Cybersixgill Darkfeed connector core module."""

import sys
import time
from typing import Any, Dict, Mapping, Optional

import stix2
from cybersixgill.client import CybersixgillClient
from cybersixgill.importer import IndicatorImporter, IndicatorImporterConfig
from cybersixgill.settings import ConnectorSettings
from cybersixgill.utils import create_organization, timestamp_to_datetime
from pycti import OpenCTIConnectorHelper  # type: ignore


class Cybersixgill:
    """Cybersixgill Darkfeed connector."""

    _CONNECTOR_RUN_INTERVAL_SEC = 60

    _STATE_LAST_RUN = "last_run"

    def __init__(self) -> None:
        """Initialize Cybersixgill Darkfeed connector."""
        self.config = ConnectorSettings()

        # Cybersixgill connector configuration
        client_id = self.config.cybersixgill.client_id
        client_secret = self.config.cybersixgill.client_secret.get_secret_value()
        create_observables = self.config.cybersixgill.create_observables
        create_indicators = self.config.cybersixgill.create_indicators
        enable_relationships = self.config.cybersixgill.enable_relationships
        fetch_size = self.config.cybersixgill.fetch_size

        self.interval_sec = int(self.config.connector.duration_period.total_seconds())

        update_existing_data = self.config.connector.update_existing_data

        # Create OpenCTI connector helper
        self.helper = OpenCTIConnectorHelper(config=self.config.to_helper_config())

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
                    self.helper.force_ping()
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
