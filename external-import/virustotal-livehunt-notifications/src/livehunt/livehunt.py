"""Virustotal Livehunt Notifications module."""

import sys
import time
from datetime import datetime, timedelta
from typing import Any, Mapping, Optional

import vt
from livehunt.builder import LivehuntBuilder
from livehunt.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper


class VirustotalLivehuntNotifications:
    """
    Process Virustotal Livehunt Notifications.
    """

    _DEFAULT_AUTHOR = "Virustotal Livehunt Notifications"

    # Default run interval
    _CONNECTOR_RUN_INTERVAL_SEC = 60
    _STATE_LATEST_RUN_TIMESTAMP = "latest_run_timestamp"
    # Number of days to load if no state
    _LAST_DAYS_TO_LOAD = 3

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        author = self.helper.api.identity.create(
            name=self._DEFAULT_AUTHOR,
            type="Organization",
            description="Download/upload files from Virustotal Livehunt Notifications.",
        )

        client = vt.Client(apikey=self.config.virustotal_livehunt_notifications.api_key)

        # TODO: to remove - for dev purpose only
        self.interval_sec = self.config.connector.duration_period.total_seconds()

        self.builder = LivehuntBuilder(
            client,
            self.helper,
            author,
            self._DEFAULT_AUTHOR,
            self.config.virustotal_livehunt_notifications.filter_with_tag,
            self.config.virustotal_livehunt_notifications.create_alert,
            self.config.virustotal_livehunt_notifications.max_age_days,
            self.config.virustotal_livehunt_notifications.create_file,
            self.config.virustotal_livehunt_notifications.upload_artifact,
            self.config.virustotal_livehunt_notifications.create_yara_rule,
            self.config.virustotal_livehunt_notifications.delete_notification,
            self.config.virustotal_livehunt_notifications.extensions,
            self.config.virustotal_livehunt_notifications.min_file_size,
            self.config.virustotal_livehunt_notifications.max_file_size,
            self.config.virustotal_livehunt_notifications.min_positives,
            self.config.virustotal_livehunt_notifications.alert_prefix,
            self.config.virustotal_livehunt_notifications.av_list,
            self.config.virustotal_livehunt_notifications.yara_label_prefix,
            self.config.virustotal_livehunt_notifications.livehunt_label_prefix,
            self.config.virustotal_livehunt_notifications.livehunt_tag_prefix,
            self.config.virustotal_livehunt_notifications.enable_label_enrichment,
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

    def _is_scheduled(self, last_run: Optional[int], current_time: int) -> bool:
        if last_run is None:
            self.helper.connector_logger.info(
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
        self.helper.connector_logger.info(
            "Starting Virustotal Livehunt Notifications Connector..."
        )
        self.helper.metric.state("idle")

        while True:
            self.helper.connector_logger.info(
                "Running Virustotal Livehunt Notifications connector..."
            )
            run_interval = self._CONNECTOR_RUN_INTERVAL_SEC

            try:
                self.helper.connector_logger.info(
                    f"Connector interval sec: {run_interval}"
                )
                timestamp = self._current_unix_timestamp()
                current_state = self._load_state()
                self.helper.connector_logger.info(
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
                    self.helper.metric.inc("run_count")
                    self.helper.metric.state("running")
                    self.helper.connector_logger.info(
                        f"[Virustotal Livehunt Notifications] starting run at: {current_state}"
                    )
                    new_state = current_state.copy()

                    self.builder.process(last_run, timestamp)

                    # Set the new state
                    new_state[self._STATE_LATEST_RUN_TIMESTAMP] = (
                        self._current_unix_timestamp()
                    )
                    self.helper.connector_logger.info(
                        f"[Virustotal Livehunt Notifications] Storing new state: {new_state}"
                    )
                    self.helper.set_state(new_state)

                    self.helper.connector_logger.info(
                        "No new Livehunt Notifications found..."
                    )
                    self.helper.metric.state("idle")
                else:
                    run_interval = self._get_next_interval(
                        run_interval, timestamp, last_run
                    )
                    self.helper.connector_logger.info(
                        f"[Virustotal Livehunt Notifications] Connector will not run, next run in {run_interval} seconds"
                    )

            except (KeyboardInterrupt, SystemExit):
                self.helper.connector_logger.info(
                    "Virustotal Livehunt Notifications connector stop"
                )
                sys.exit(0)

            except Exception as e:
                self.helper.metric.inc("error_count")
                self.helper.connector_logger.error(str(e))

            if self.helper.connect_run_and_terminate:
                self.helper.metric.state("stopped")
                self.helper.connector_logger.info("Connector stop")
                self.helper.force_ping()
                sys.exit(0)

            self._sleep(delay_sec=run_interval)
