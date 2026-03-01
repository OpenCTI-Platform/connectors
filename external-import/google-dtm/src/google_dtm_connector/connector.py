import sys
from datetime import datetime, timezone
from typing import Any

from pycti import OpenCTIConnectorHelper
from src import ConfigLoader

from .client_api import GoogleDTMAPIClient
from .converter_to_stix import ConverterToStix


class GoogleDTMConnector:
    """
    Specifications of the external import connector

    This class encapsulates the main actions, expected to be run by any external import connector.
    Note that the attributes defined below will be complemented per each connector type.
    This type of connector aim to fetch external data to create STIX bundle and send it in a RabbitMQ queue.
    The STIX bundle in the queue will be processed by the workers.
    This type of connector uses the basic methods of the helper.

    ---

    Attributes
        - `config (ConfigConnector())`:
            Initialize the connector with necessary configuration environment variables

        - `helper (OpenCTIConnectorHelper(config))`:
            This is the helper to use.
            ALL connectors have to instantiate the connector helper with configurations.
            Doing this will do a lot of operations behind the scene.

        - `converter_to_stix (ConnectorConverter(helper))`:
            Provide methods for converting various types of input data into STIX 2.1 objects.

    ---

    Best practices
        - `self.helper.api.work.initiate_work(...)` is used to initiate a new work
        - `self.helper.schedule_iso()` is used to encapsulate the main process in a scheduler
        - `self.helper.connector_logger.[info/debug/warning/error]` is used when logging a message
        - `self.helper.stix2_create_bundle(stix_objects)` is used when creating a bundle
        - `self.helper.send_stix2_bundle(stix_objects_bundle)` is used to send the bundle to RabbitMQ
        - `self.helper.set_state()` is used to set state

    """

    def __init__(self):
        """
        Initialize the Connector with necessary configurations
        """
        self.config = ConfigLoader()
        self.helper = OpenCTIConnectorHelper(config=self.config.model_dump_pycti())

        # Load configuration file and connection helper
        self.client = GoogleDTMAPIClient(
            helper=self.helper,
            api_key=self.config.google_dtm.api_key.get_secret_value(),
        )
        self.converter_to_stix = ConverterToStix(
            self.helper, tlp=self.config.google_dtm.tlp
        )

    def _collect_intelligence(self, since_date) -> tuple[list[Any], Any | None]:
        """
        Collect intelligence from the source and convert into STIX object
        :return: List of STIX objects
        """
        stix_objects = []

        dtm_alerts = self.client.get_dtm_alerts(
            since_date=since_date,
            alert_severity=self.config.google_dtm.alert_severity,
            alert_type=self.config.google_dtm.alert_type,
        )

        self.helper.connector_logger.info(
            f"Going to convert and ingest {len(dtm_alerts)} alerts"
        )

        # Convert into STIX2 object and add it on a list
        most_recent_alert_date = None
        for alert in dtm_alerts:
            most_recent_alert_date = alert.get("updated_at")
            entity_to_stix = self.converter_to_stix.create_incident(alert)
            stix_objects.extend(entity_to_stix)

        # Ensure consistent bundle by adding the author and TLP marking
        if stix_objects:
            stix_objects.append(self.converter_to_stix.author)
            stix_objects.append(self.converter_to_stix.tlp_marking)

        return stix_objects, most_recent_alert_date

    def process_message(self) -> None:
        """
        Connector main process to collect intelligence
        :return: None
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting connector...",
            {"connector_name": self.helper.connect_name},
        )

        try:
            # Get the current state
            now = datetime.now(tz=timezone.utc)
            current_timestamp = int(datetime.timestamp(now))
            current_state = self.helper.get_state()

            if current_state is not None and "last_alert_date" in current_state:
                last_alert_date = current_state["last_alert_date"]

                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector last alert ingested",
                    {"last_alert_date": last_alert_date},
                )
            else:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector has never run..."
                )
                first_fetch_delta = self.config.google_dtm.import_start_date
                first_fetch_time = datetime.now(timezone.utc) - first_fetch_delta
                last_alert_date = first_fetch_time.strftime("%Y-%m-%dT%H:%M:%SZ")

            self.helper.connector_logger.info(
                f"Going to fetch alerts since: {last_alert_date}"
            )

            # Friendly name will be displayed on OpenCTI platform
            now_utc_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")
            friendly_name = f"Google DTM Connector run @ {now_utc_str}"

            # Initiate a new work
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Running connector...",
                {"connector_name": self.helper.connect_name},
            )

            # Performing the collection of intelligence
            stix_objects, most_recent_alert = self._collect_intelligence(
                since_date=last_alert_date
            )

            if len(stix_objects):
                stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
                bundles_sent = self.helper.send_stix2_bundle(
                    stix_objects_bundle,
                    work_id=work_id,
                    cleanup_inconsistent_bundle=True,
                )

                self.helper.connector_logger.info(
                    "Sending STIX objects to OpenCTI...",
                    {"bundles_sent": {str(len(bundles_sent))}},
                )

            # Store the current timestamp as a last run of the connector
            self.helper.connector_logger.debug(
                "Getting current state and update it with last run of the connector",
                {"current_timestamp": current_timestamp},
            )
            current_state = self.helper.get_state()
            if current_state:
                current_state["last_run"] = now_utc_str
            else:
                current_state = {"last_run": now_utc_str}
            if most_recent_alert:
                current_state["last_alert_date"] = most_recent_alert

            self.helper.set_state(current_state)

            message = (
                f"{self.helper.connect_name} connector successfully run, storing last_run as "
                + str(now_utc_str)
            )

            self.helper.api.work.to_processed(work_id, message)
            self.helper.connector_logger.info(message)

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(str(err))

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
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period,
        )
