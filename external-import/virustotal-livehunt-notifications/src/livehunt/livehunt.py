"""Virustotal Livehunt Notifications module."""

import sys
import time
from datetime import timedelta
from typing import Any, Mapping, Optional

import stix2
import vt
from livehunt.builder import LivehuntBuilder
from livehunt.settings import ConnectorSettings
from pycti import Identity, MarkingDefinition, OpenCTIConnectorHelper


class VirustotalLivehuntNotifications:
    """
    Process Virustotal Livehunt Notifications.
    """

    _STATE_LATEST_RUN_TIMESTAMP = "latest_run_timestamp"
    # Number of days to load if no state
    _LAST_DAYS_TO_LOAD = 3

    TLP_LEVELS = mapping = {
        "white": stix2.TLP_WHITE,
        "clear": stix2.TLP_WHITE,
        "green": stix2.TLP_GREEN,
        "amber": stix2.TLP_AMBER,
        "amber+strict": stix2.MarkingDefinition(
            id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
            definition_type="statement",
            definition={"statement": "custom"},
            custom_properties={
                "x_opencti_definition_type": "TLP",
                "x_opencti_definition": "TLP:AMBER+STRICT",
            },
        ),
        "red": stix2.TLP_RED,
    }

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        tlp_marking = self.TLP_LEVELS[
            self.config.virustotal_livehunt_notifications.tlp_level
        ]

        author = stix2.Identity(
            id=Identity.generate_id(
                name="Virustotal Livehunt Notifications", identity_class="organization"
            ),
            name="Virustotal Livehunt Notifications",
            identity_class="organization",
            description="Download/upload files from Virustotal Livehunt Notifications.",
            external_references=[
                stix2.ExternalReference(
                    source_name="Virustotal Livehunt Notifications",
                    url="https://www.virustotal.com",
                    description="Virustotal Livehunt Notifications.",
                )
            ],
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
