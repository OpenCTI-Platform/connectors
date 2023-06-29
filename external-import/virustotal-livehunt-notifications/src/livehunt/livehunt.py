# -*- coding: utf-8 -*-
"""Virustotal Livehunt Notifications module."""
import os
import sys
import time
from datetime import datetime, timedelta
from typing import Any, Mapping, Optional

import stix2
import vt
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

from .builder import LivehuntBuilder


class VirustotalLivehuntNotifications:
    """
    Process Virustotal Livehunt Notifications.
    """

    _DEFAULT_AUTHOR = "Virustotal Livehunt Notifications"

    # Default run interval
    _CONNECTOR_RUN_INTERVAL_SEC = 60
    _STATE_LATEST_RUN_TIMESTAMP = "latest_run_timestamp"
    # Number of days to load if no state
    _LAST_DAYS_TO_LOAD = 1

    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path, encoding="utf-8"), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        author = stix2.Identity(
            name=self._DEFAULT_AUTHOR,
            identity_class="Organization",
            description="Download/upload files from Virustotal Livehunt Notifications.",
            confidence=self.helper.connect_confidence_level,
        )

        # Instantiate vt client from config settings
        api_key = get_config_variable(
            "VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_API_KEY",
            ["virustotal_livehunt_notifications", "api_key"],
            config,
        )
        client = vt.Client(api_key)

        self.interval_sec = get_config_variable(
            "VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_INTERVAL_SEC",
            ["virustotal_livehunt_notifications", "interval_sec"],
            config,
        )

        tag = get_config_variable(
            "VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_FILTER_WITH_TAG",
            ["virustotal_livehunt_notifications", "filter_with_tag"],
            config,
        )

        create_alert = get_config_variable(
            "VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_CREATE_ALERT",
            ["virustotal_livehunt_notifications", "create_alert"],
            config,
        )

        create_file = get_config_variable(
            "VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_CREATE_FILE",
            ["virustotal_livehunt_notifications", "create_file"],
            config,
        )

        create_ruleset = get_config_variable(
            "VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_CREATE_RULESET",
            ["virustotal_livehunt_notifications", "create_file"],
            config,
        )

        delete_notification = get_config_variable(
            "VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_DELETE_NOTIFICATION",
            ["virustotal_livehunt_notifications", "delete_notification"],
            config,
        )

        self.builder = LivehuntBuilder(
            client,
            self.helper,
            author,
            tag,
            create_alert,
            create_file,
            create_ruleset,
            delete_notification,
        )

    @staticmethod
    def _current_unix_timestamp() -> int:
        return int(time.time())

    def _get_interval(self) -> int:
        return int(self.interval_sec)

    @staticmethod
    def _get_state_value(
        state: Optional[Mapping[str, Any]], key: str, default: Optional[Any] = None
    ) -> Any:
        if state is not None:
            return state.get(key, default)
        return default

    def _initiate_work(self, timestamp: int) -> str:
        now = datetime.utcfromtimestamp(timestamp)
        friendly_name = "Virustotal Livehunt Notifications run @ " + now.strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )
        self.helper.log_info(
            f"[Virustotal Livehunt Notifications] workid {work_id} initiated"
        )
        return work_id

    def _is_scheduled(self, last_run: Optional[int], current_time: int) -> bool:
        if last_run is None:
            self.helper.log_info(
                "Virustotal Livehunt Notifications connector clean run"
            )
            return True

        time_diff = current_time - last_run
        return time_diff >= self._get_interval()

    def _get_next_interval(
        self, run_interval: int, timestamp: int, last_run: int
    ) -> int:
        """Get the delay for the next interval."""
        next_run = self._get_interval() - (timestamp - last_run)
        return min(run_interval, next_run)

    def _load_state(self) -> dict[str, Any]:
        current_state = self.helper.get_state()
        if not current_state:
            return {}
        return current_state

    @classmethod
    def _sleep(cls, delay_sec: Optional[int] = None) -> None:
        sleep_delay = (
            delay_sec if delay_sec is not None else cls._CONNECTOR_RUN_INTERVAL_SEC
        )
        time.sleep(sleep_delay)

    def run(self):
        """Run VirustotalLivehuntNotifications."""
        self.helper.log_info("Starting Virustotal Livehunt Notifications Connector...")

        while True:
            self.helper.log_info(
                "Running Virustotal Livehunt Notifications connector..."
            )
            run_interval = self._CONNECTOR_RUN_INTERVAL_SEC

            try:
                self.helper.log_info(f"Connector interval sec: {run_interval}")
                timestamp = self._current_unix_timestamp()
                current_state = self._load_state()
                self.helper.log_info(
                    f"[Virustotal Livehunt Notifications] loaded state: {current_state}"
                )

                last_run = self._get_state_value(
                    current_state,
                    self._STATE_LATEST_RUN_TIMESTAMP,
                    int(
                        datetime.timestamp(
                            datetime.fromtimestamp(timestamp)
                            - timedelta(days=self._LAST_DAYS_TO_LOAD)
                        )
                    ),
                )
                if self._is_scheduled(last_run, timestamp):
                    work_id = self._initiate_work(timestamp)
                    new_state = current_state.copy()

                    self.builder.process(last_run)
                    self.builder.send_bundle(work_id)

                    # Set the new state
                    new_state[
                        self._STATE_LATEST_RUN_TIMESTAMP
                    ] = self._current_unix_timestamp()
                    self.helper.log_info(
                        f"[Virustotal Livehunt Notifications] Storing new state: {new_state}"
                    )
                    self.helper.set_state(new_state)

                    self.helper.log_info("No new Livehunt Notifications found...")
                else:
                    run_interval = self._get_next_interval(
                        run_interval, timestamp, last_run
                    )
                    self.helper.log_info(
                        f"[Virustotal Livehunt Notifications] Connector will not run, next run in {run_interval} seconds"
                    )

            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Virustotal Livehunt Notifications connector stop")
                sys.exit(0)

            except Exception as e:
                self.helper.log_error(str(e))
                sys.exit(0)

            if self.helper.connect_run_and_terminate:
                self.helper.log_info("Connector stop")
                sys.exit(0)

            self._sleep(delay_sec=run_interval)


if __name__ == "__main__":
    try:
        vt_livehunt_notifications = VirustotalLivehuntNotifications()
        vt_livehunt_notifications.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
