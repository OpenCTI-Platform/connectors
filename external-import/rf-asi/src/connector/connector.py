import sys
from datetime import datetime, timezone

from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper
from rf_asi_client import RfAsiClient
from rf_asi_client.api_client import HttpRetrySettings


class RfAsiConnector:
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
        client (RfAsiClient):
            Provide methods to request the external API.
        converter_to_stix (ConnectorConverter):
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
        Initialize `RfAsiConnector` with its configuration.

        Args:
            config (ConnectorSettings): Configuration of the connector
            helper (OpenCTIConnectorHelper): Helper to manage connection and requests to OpenCTI
        """
        self.config = config
        self.helper = helper

        self.client = RfAsiClient(
            self.helper,
            base_url=self.config.rf_asi.api_base_url,
            api_key=self.config.rf_asi.api_key.get_secret_value(),
            retry=HttpRetrySettings(
                max_attempts=self.config.rf_asi.retry_max_attempts,
                initial_seconds=self.config.rf_asi.retry_initial_seconds,
                max_seconds=self.config.rf_asi.retry_max_seconds,
            ),
        )
        self.converter_to_stix = ConverterToStix(
            self.helper,
            tlp_level=self.config.rf_asi.tlp_level,
            project_id=self.config.rf_asi.project_id,
            portal_base_url=self.config.rf_asi.portal_base_url,
        )

    def _exposure_filters(self) -> dict[str, str]:
        rf = self.config.rf_asi
        if rf.filter_severity_min is not None:
            return {"filter_severity_min": rf.filter_severity_min}
        if rf.filter_severity_exact is not None:
            return {"filter_severity_exact": rf.filter_severity_exact}
        return {}

    def _collect_intelligence(
        self, exposures_cursor: str | None = None
    ) -> tuple[list, str | None]:
        """
        Collect intelligence from the source and convert into STIX object.

        :param exposures_cursor: Optional pagination cursor when run_limit is set.
        :return: Tuple of STIX objects and optional next cursor for the next batch.
        """
        stix_objects = []
        next_cursor: str | None = None

        filters = self._exposure_filters()

        if self.config.rf_asi.run_limit is None:
            exposures = self.client.list_exposures(
                project_id=self.config.rf_asi.project_id,
                limit=self.config.rf_asi.page_limit,
                **filters,
            )
        else:
            exposures, next_cursor = self.client.list_exposures_batch(
                project_id=self.config.rf_asi.project_id,
                page_limit=self.config.rf_asi.page_limit,
                run_limit=self.config.rf_asi.run_limit,
                cursor=exposures_cursor,
                **filters,
            )
            self.helper.connector_logger.info(
                "[CONNECTOR] Fetched exposure batch from ASI API",
                {
                    "run_limit": self.config.rf_asi.run_limit,
                    "imported_count": len(exposures),
                    "has_next_cursor": next_cursor is not None,
                },
            )

        self.helper.connector_logger.info(
            "[CONNECTOR] Fetched exposures from ASI API",
            {"exposure_count": len(exposures)},
        )

        for exposure in exposures:
            signature_id = exposure["signature"]["id"]
            assets_data = self.client.get_exposure_assets(
                project_id=self.config.rf_asi.project_id,
                signature_id=signature_id,
                limit=self.config.rf_asi.page_limit,
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Fetched exposure assets from ASI API",
                {
                    "signature_id": signature_id,
                    "asset_count": len(assets_data.get("asset_exposures") or []),
                },
            )

            sdk_objects = self.converter_to_stix.build_exposure_objects(
                exposure,
                assets_data,
            )
            stix_objects.extend(obj.to_stix2_object() for obj in sdk_objects)

        if stix_objects:
            stix_objects.append(self.converter_to_stix.author)
            stix_objects.append(self.converter_to_stix.tlp_marking)

        return stix_objects, next_cursor if self.config.rf_asi.run_limit else None

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
            now = datetime.now(timezone.utc)
            current_timestamp = int(datetime.timestamp(now))
            current_state = self.helper.get_state()

            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]

                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector last run",
                    {"last_run_datetime": last_run},
                )
            else:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector has never run..."
                )

            # Friendly name will be displayed on OpenCTI platform
            friendly_name = "Recorded Future ASI Exposures Import"

            # Initiate a new work
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Running connector...",
                {"connector_name": self.helper.connect_name},
            )

            # Performing the collection of intelligence
            # ===========================
            # === Add your code below ===
            # ===========================
            exposures_cursor = None
            if self.config.rf_asi.run_limit is not None:
                if current_state is not None:
                    exposures_cursor = current_state.get("exposures_cursor")

            stix_objects, next_cursor = self._collect_intelligence(exposures_cursor)

            if stix_objects:
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
            # ===========================
            # === Add your code above ===
            # ===========================

            # Store the current timestamp as a last run of the connector
            self.helper.connector_logger.debug(
                "Getting current state and update it with last run of the connector",
                {"current_timestamp": current_timestamp},
            )
            current_state = self.helper.get_state()
            current_state_datetime = now.strftime("%Y-%m-%d %H:%M:%S")
            last_run_datetime = datetime.fromtimestamp(
                current_timestamp, tz=timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S")
            if current_state:
                current_state["last_run"] = current_state_datetime
            else:
                current_state = {"last_run": current_state_datetime}

            if self.config.rf_asi.run_limit is not None:
                if next_cursor:
                    current_state["exposures_cursor"] = next_cursor
                else:
                    current_state.pop("exposures_cursor", None)

            self.helper.set_state(current_state)

            message = (
                f"{self.helper.connect_name} connector successfully run, storing last_run as "
                + str(last_run_datetime)
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
