import sys
from datetime import datetime, timezone

from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from crowdstrike_client import CrowdstrikeReconClient
from dateutil.parser import parse
from pycti import OpenCTIConnectorHelper


class CrowdstrikeReconConnector:
    """
    Specifications of the external import connector:

    This class encapsulates the main actions, expected to be run by any connector of type `EXTERNAL_IMPORT`.
    This type of connector aim to fetch external data to create STIX bundle and send it to OpenCTI.
    The STIX bundle in the queue will be processed by OpenCTI workers.
    This type of connector uses the basic methods of the helper.

    ---

    Attributes:
        config (ConnectorSettings):
            Store the connector's configuration. It defines how to connector will behave.
        helper (OpenCTIConnectorHelper):
            Handle the connection and the requests between the connector, OpenCTI and the workers.
            _All connectors MUST use the connector helper with connector's configuration._
        client (CrowdstrikeReconClient):
            Provide methods to request the external API.
        converter_to_stix (ConverterToStix):
            Provide methods for converting various types of input data into STIX 2.1 objects.

    ---

    Best practices:
        - `self.helper.api.work.initiate_work(...)` is used to initiate a new work
        - `self.helper.schedule_iso()` is used to schedule connector's runs frequency
        - `self.helper.connector_logger.[info/debug/warning/error]` is used when logging a message
        - `self.helper.stix2_create_bundle(stix_objects)` is used when creating a bundle
        - `self.helper.send_stix2_bundle(stix_objects_bundle)` is used to send the bundle to OpenCTI
        - `self.helper.set_state()` is used to store persistent data in connector's state

    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """
        Initialize `CrowdStrikeReconConnector` with its configuration.

        Args:
            config (ConnectorSettings): Configuration of the connector
            helper (OpenCTIConnectorHelper): Helper to manage connection and requests to OpenCTI
        """
        self.config = config
        self.helper = helper

        self.client = CrowdstrikeReconClient(
            self.helper,
            base_url=self.config.crowdstrike_recon.api_base_url,
            client_id=self.config.crowdstrike_recon.client_id,
            client_secret=self.config.crowdstrike_recon.client_secret,
            filter_topic=self.config.crowdstrike_recon.filter_topic,
            filter_type=self.config.crowdstrike_recon.filter_type,
            filter_priority=self.config.crowdstrike_recon.filter_priority,
        )
        self.converter_to_stix = ConverterToStix(
            self.helper,
            tlp_level=self.config.crowdstrike_recon.tlp_level,
        )

    def _collect_intelligence(self, from_date) -> tuple[list, str | None]:
        """
        Collect intelligence from the source and convert into STIX object
        :return: Tuple of (list of STIX objects, most recent alert date or None)
        """
        stix_objects = []
        most_recent_alert_date = None
        most_recent_alert_dt = None
        # Get notifications
        notification_ids = self.client.query_notifications(from_date)

        self.helper.connector_logger.info(
            "[CONNECTOR] Notifications retrieved from CrowdStrike Recon",
            meta={"notifications": len(notification_ids)},
        )

        # Fetch notification details in batches (avoids one HTTP call per id)
        notification_details = self.client.get_notifications_details(notification_ids)

        for notification_detail in notification_details:
            created_date = (notification_detail.get("notification") or {}).get(
                "created_date"
            )
            # Track the maximum created_date so the saved state never regresses,
            # regardless of the order the details are returned in. Parse to a
            # datetime for the comparison (lexicographic string comparison is
            # unsafe with fractional seconds / timezone offsets) but persist the
            # original string.
            if created_date:
                try:
                    created_dt = parse(created_date)
                except (ValueError, OverflowError, TypeError):
                    created_dt = None
                if created_dt is not None and (
                    most_recent_alert_dt is None or created_dt > most_recent_alert_dt
                ):
                    most_recent_alert_dt = created_dt
                    most_recent_alert_date = created_date

            # convert notification into an OpenCTI Incident
            stix_entities = self.converter_to_stix.create_incident(
                notification_detail=notification_detail
            )
            stix_objects.extend(stix_entities)

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
            meta={"connector_name": self.helper.connect_name},
        )

        work_id = None
        in_error = False
        # Fallback message; overwritten by the success / error / interrupt paths
        message = "Connector run interrupted"
        try:
            # Get the current state
            now = datetime.now(tz=timezone.utc)
            now_utc_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")
            current_state = self.helper.get_state()

            if current_state is not None and "last_alert_date" in current_state:
                last_alert_date = current_state["last_alert_date"]

                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector last alert ingested",
                    meta={"last_alert_date": last_alert_date},
                )
            else:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector has never run..."
                )
                first_fetch_delta = self.config.crowdstrike_recon.import_start_date
                first_fetch_time = datetime.now(timezone.utc) - first_fetch_delta
                last_alert_date = first_fetch_time.strftime("%Y-%m-%dT%H:%M:%SZ")

            self.helper.connector_logger.info(
                f"Going to fetch alerts since: {last_alert_date}"
            )

            # Friendly name will be displayed on OpenCTI platform
            friendly_name = f"CrowdStrike Recon Connector run @ {now_utc_str}"

            # Initiate a new work. is_multipart=True so the work only completes on
            # the to_processed call in the finally block: send_stix2_bundle may
            # split a large bundle into several expectations, which would
            # otherwise let the work complete before every bundle is processed.
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name, is_multipart=True
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Running connector...",
                meta={"connector_name": self.helper.connect_name},
            )

            # Performing the collection of intelligence
            stix_objects, most_recent_alert_date = self._collect_intelligence(
                last_alert_date
            )

            if stix_objects:
                stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
                bundles_sent = self.helper.send_stix2_bundle(
                    stix_objects_bundle,
                    work_id=work_id,
                    cleanup_inconsistent_bundle=True,
                )

                self.helper.connector_logger.info(
                    "Sending STIX objects to OpenCTI...",
                    meta={"bundles_sent": str(len(bundles_sent))},
                )

            current_state = self.helper.get_state()
            if current_state:
                current_state["last_run"] = now_utc_str
            else:
                current_state = {"last_run": now_utc_str}
            if most_recent_alert_date:
                current_state["last_alert_date"] = most_recent_alert_date

            self.helper.set_state(current_state)

            message = (
                f"{self.helper.connect_name} connector successfully run, storing last_alert_date as "
                + str(most_recent_alert_date)
            )

            self.helper.connector_logger.info(message)

        except (KeyboardInterrupt, SystemExit):
            in_error = True
            message = "Connector stopped..."
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                meta={"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            in_error = True
            message = str(err)
            self.helper.connector_logger.error(message)
        finally:
            # Always close the work so a multipart work is never left stuck
            # "in-progress" when the run fails or is interrupted before
            # to_processed would otherwise be reached.
            if work_id is not None:
                self.helper.api.work.to_processed(work_id, message, in_error=in_error)

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
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
