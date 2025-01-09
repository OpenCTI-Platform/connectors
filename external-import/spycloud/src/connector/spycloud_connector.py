import sys
from datetime import datetime

from pycti import OpenCTIConnectorHelper

from .services.config_loader import ConfigLoader
from .services.converter_to_stix import ConverterToStix
from .services.spycloud_client import SpyCloudClient
from .models.opencti import OCTIBaseModel


class SpyCloudConnector:
    """
    Specifications of the external import connector

    This class encapsulates the main actions, expected to be run by any external import connector.
    Note that the attributes defined below will be complemented per each connector type.
    This type of connector aim to fetch external data to create STIX bundle and send it in a RabbitMQ queue.
    The STIX bundle in the queue will be processed by the workers.
    This type of connector uses the basic methods of the helper.
    """

    def __init__(self):
        """
        Initialize the Connector with necessary configurations
        """
        self.config = ConfigLoader()
        self.helper = OpenCTIConnectorHelper(self.config.to_dict())
        self.client = SpyCloudClient(self.helper, self.config)
        self.converter_to_stix = ConverterToStix(self.helper, self.config)

    def _collect_intelligence(self) -> list[OCTIBaseModel]:
        """
        Collect intelligence from the source and convert into OCTI objects
        :return: List of OCTI objects
        """
        octi_objects = []

        breach_records = self.client.get_breach_records(
            watchlist_types=self.config.spycloud.watchlist_types,
            breach_severities=self.config.spycloud.breach_severities,
            since=self.config.spycloud.import_start_date,
        )
        for breach_record in breach_records:
            breach_catalog = self.client.get_breach_catalog(breach_record.source_id)
            octi_indicent = self.converter_to_stix.create_incident(
                breach_record=breach_record, breach_catalog=breach_catalog
            )
            octi_objects.append(octi_indicent)

        if octi_objects:
            octi_objects.append(self.converter_to_stix.author)

        return octi_objects

    def _create_stix_bundle(self, octi_objects: list[OCTIBaseModel] = []) -> str:
        """
        Create a consistent STIX bundle from OCTI objects.
        :return: STIX bundle string
        """
        if not octi_objects:
            return None

        octi_objects.append(self.converter_to_stix.author)
        stix_objects = [octi_object.to_stix2_object() for octi_object in octi_objects]

        stix_bundle = self.helper.stix2_create_bundle(stix_objects)

        return stix_bundle

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
            now = datetime.now()
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

            # Initiate a new work
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, self.helper.connect_name
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Running connector...",
                {"connector_name": self.helper.connect_name},
            )

            octi_objects = self._collect_intelligence()
            if octi_objects:
                stix_bundle = self._create_stix_bundle(octi_objects)
                bundles_sent = self.helper.send_stix2_bundle(
                    stix_bundle, work_id=work_id, cleanup_inconsistent_bundle=True
                )

                self.helper.connector_logger.info(
                    "Sending STIX objects to OpenCTI...",
                    {"bundles_sent": len(bundles_sent)},
                )

            # Store the current timestamp as a last run of the connector
            self.helper.connector_logger.debug(
                "Getting current state and update it with last run of the connector",
                {"current_timestamp": current_timestamp},
            )
            current_state = self.helper.get_state()
            current_state_datetime = now.strftime("%Y-%m-%d %H:%M:%S")
            last_run_datetime = datetime.utcfromtimestamp(current_timestamp).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            if current_state:
                current_state["last_run"] = current_state_datetime
            else:
                current_state = {"last_run": current_state_datetime}
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
