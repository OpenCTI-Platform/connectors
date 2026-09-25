"""Virustotal Livehunt Notifications module."""

import sys
import time
from datetime import timedelta
from typing import Any, Mapping, Optional

import vt
from connectors_sdk.models import OrganizationAuthor, TLPMarking
from livehunt.builder import LivehuntBuilder
from livehunt.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper


class VirustotalLivehuntNotifications:
    """
    Process Virustotal Livehunt Notifications.
    """

    _STATE_LATEST_RUN_TIMESTAMP = "latest_run_timestamp"
    # Number of days to load if no state
    _LAST_DAYS_TO_LOAD = 3

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        tlp_marking = TLPMarking(
            level=config.virustotal_livehunt_notifications.tlp_level
        )
        author = OrganizationAuthor(
            name="Virustotal Livehunt Notifications",
            description="Download/upload files from Virustotal Livehunt Notifications.",
            contact_information="https://www.virustotal.com",
        )

        client = vt.Client(
            apikey=self.config.virustotal_livehunt_notifications.api_key.get_secret_value()
        )

        self.builder = LivehuntBuilder(
            client,
            self.helper,
            author,
            tlp_marking,
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
            get_malware_config=self.config.virustotal_livehunt_notifications.get_malware_config,
            create_file_indicators=self.config.virustotal_livehunt_notifications.create_file_indicators,
            create_domain_name_indicators=self.config.virustotal_livehunt_notifications.create_domain_name_indicators,
            create_ip_indicators=self.config.virustotal_livehunt_notifications.create_ip_indicators,
            create_url_indicators=self.config.virustotal_livehunt_notifications.create_url_indicators,
            limit=self.config.virustotal_livehunt_notifications.limit,
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

    def _load_state(self) -> dict[str, Any]:
        current_state = self.helper.get_state()
        if not current_state:
            return {}
        return current_state

    def process(self):
        """VirustotalLivehuntNotifications main process."""

        self.helper.connector_logger.info(
            "Running Virustotal Livehunt Notifications connector..."
        )

        try:
            timestamp = self._current_unix_timestamp()
            current_state = self._load_state()
            self.helper.connector_logger.info(
                f"[Virustotal Livehunt Notifications] loaded state: {current_state}"
            )

            last_run = self._get_state_value(
                current_state,
                self._STATE_LATEST_RUN_TIMESTAMP,
                timestamp
                - int(timedelta(days=self._LAST_DAYS_TO_LOAD).total_seconds()),
            )

            self.helper.metric.inc("run_count")
            self.helper.metric.state("running")
            self.helper.connector_logger.info(
                f"[Virustotal Livehunt Notifications] starting run at: {current_state}"
            )
            new_state = current_state.copy()

            self.builder.process(last_run, timestamp)

            # Set the new state
            new_state[self._STATE_LATEST_RUN_TIMESTAMP] = self._current_unix_timestamp()
            self.helper.connector_logger.info(
                f"[Virustotal Livehunt Notifications] Storing new state: {new_state}"
            )
            self.helper.set_state(new_state)

            self.helper.connector_logger.info("No new Livehunt Notifications found...")
            self.helper.metric.state("idle")

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as e:
            self.helper.metric.inc("error_count")
            self.helper.connector_logger.error(str(e))

    def run(self) -> None:
        """
        Start the connector, schedule its runs and trigger the first run.
        It allows you to schedule the process to run at a certain interval.
        This specific scheduler from the `OpenCTIConnectorHelper` will also check the queue size of a connector.
        If `CONNECTOR_QUEUE_THRESHOLD` is set, and if the connector's queue size exceeds the queue threshold,
        the connector's main process will not run until the queue is ingested and reduced sufficiently,
        allowing it to restart during the next scheduler check. (default is 500MB)

        Example:
            - If `CONNECTOR_DURATION_PERIOD=PT5M`, then the connector is running every 5 minutes.
        """
        self.helper.connector_logger.info(
            "Starting Virustotal Livehunt Notifications Connector..."
        )
        self.helper.metric.state("idle")

        self.helper.schedule_process(
            message_callback=self.process,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
