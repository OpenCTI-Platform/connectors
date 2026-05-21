import sys
from datetime import datetime, timedelta, timezone

from doppel.client_api import ConnectorClient
from doppel.converter_to_stix import ConverterToStix
from doppel.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper


class DoppelConnector:
    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """
        Initialize the Connector with necessary configurations
        """
        self.helper = helper
        self.config = config
        self.client = ConnectorClient(self.helper, self.config)
        self.converter = ConverterToStix(
            self.helper, tlp_level=self.config.doppel.tlp_level
        )

    def _get_last_run(self, current_state, start_datetime: datetime) -> datetime:
        """
        Retrieve previous run from current state or the
        start date depending on historical_polling_days from config
        :params:
            start_datetime (datetime): datetime when process started
        :return: datetime
        """
        if current_state and "last_run" in current_state:
            self.helper.connector_logger.info(
                "Resuming from last run timestamp",
                {"last_run": current_state["last_run"]},
            )
            previous_run = current_state["last_run"]
        else:
            default_start = start_datetime - timedelta(
                days=self.config.doppel.historical_polling_days
            )
            previous_run = default_start.strftime("%Y-%m-%d %H:%M:%S")
            self.helper.connector_logger.info(
                "No previous state found. Using historical polling window",
                {"start_date": previous_run},
            )

        return previous_run

    def process_message(self) -> None:
        """
        Connector main process to collect alerts
        :return: None
        """
        self.helper.connector_logger.info("[DoppelConnector] Running scheduled fetch")
        work_id = None
        start_datetime = datetime.now(tz=timezone.utc)
        current_timestamp = int(datetime.timestamp(start_datetime))
        current_state = self.helper.get_state()

        try:
            # Perform collection of intelligence

            previous_run = self._get_last_run(current_state, start_datetime)
            # Format previous_run for api call (format: 'yyyy-mm-ddThh:mm:ss')
            formatted_previous_run = datetime.fromisoformat(previous_run).isoformat(
                timespec="seconds"
            )
            alerts = self.client.get_alerts(
                formatted_previous_run, page_size=self.config.doppel.page_size
            )

            if alerts:
                friendly_name = (
                    f"Doppel run @ {start_datetime.strftime('%Y-%m-%d %H:%M:%S')}"
                )
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )

                bundle = self.converter.convert_alerts_to_stix(alerts)

                bundle_sent = self.helper.send_stix2_bundle(
                    bundle, work_id=work_id, cleanup_inconsistent_bundle=True
                )

                self.helper.connector_logger.info(
                    "STIX bundle sent", {"len_bundle_sent": len(bundle_sent)}
                )

            # Store the current timestamp as a last run of the connector
            self.helper.connector_logger.debug(
                "Getting current state and update it with last run of the connector",
                {"current_timestamp": current_timestamp},
            )
            current_state_datetime = start_datetime.strftime("%Y-%m-%d %H:%M:%S")
            if current_state:
                current_state["last_run"] = current_state_datetime
            else:
                current_state = {"last_run": current_state_datetime}
            self.helper.set_state(current_state)

            self.helper.connector_logger.info(
                "Updated last run state", {"last_run": current_state_datetime}
            )

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(
                "[DoppelConnector] Error in process_message", {"error": err}
            )
        finally:
            if work_id:
                message = f"{self.helper.connect_name} connector successfully run"
                self.helper.api.work.to_processed(work_id, message)

    def run(self) -> None:
        """
        Run the main process encapsulated in a scheduler
        It allows you to schedule the process to run at a certain intervals
        This specific scheduler from the pycti connector helper will also check the queue size of a connector
        If `CONNECTOR_QUEUE_THRESHOLD` is set, if the connector's queue size exceeds the queue threshold,
        the connector's main process will not run until the queue is ingested and reduced sufficiently,
        allowing it to restart during the next scheduler check. (default is 500MB)
        It requires the `duration_period` connector variable in ISO-8601 standard format
        Example: `CONNECTOR_DURATION_PERIOD=PT5M` => Will run the process every 5 minutes
        :return: None
        """
        self.helper.connector_logger.info("[DoppelConnector] Starting scheduler")
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period,
        )
