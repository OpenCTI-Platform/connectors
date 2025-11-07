import json
import sys
from datetime import datetime, timezone

from models.configs.config_loader import ConfigLoader
from pycti import OpenCTIConnectorHelper
from sparta.client_api import SpartaClient
from sparta.converter_to_stix import ConverterToStix
from stix2 import TLP_WHITE


class Sparta:
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

    ---

    Best practices
        - `self.helper.api.work.initiate_work(...)` is used to initiate a new work
        - `self.helper.schedule_iso()` is used to encapsulate the main process in a scheduler
        - `self.helper.connector_logger.[info/debug/warning/error]` is used when logging a message
        - `self.helper.stix2_create_bundle(stix_objects)` is used when creating a bundle
        - `self.helper.send_stix2_bundle(stix_objects_bundle)` is used to send the bundle to RabbitMQ
        - `self.helper.set_state()` is used to set state

    """

    def __init__(self, config: ConfigLoader, helper: OpenCTIConnectorHelper):
        """Load configuration file and connection helper
        Instantiate the connector helper from config
        """
        self.config = config
        self.helper = helper
        self.client = SpartaClient(self.helper, self.config)
        self.converter_to_stix = ConverterToStix()
        self.last_run = None
        self.work_id = None

    def _initiate_work(self):
        """Starts a work process.
        Sends a request to the API with the initiate_work method to initialize the work.
        """
        now_utc = datetime.now(timezone.utc)
        now_utc_isoformat = now_utc.isoformat(timespec="seconds")
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting work...",
            {
                "now_utc_isoformat": now_utc_isoformat,
            },
        )

        # Friendly name will be displayed on OpenCTI platform
        friendly_name = f"Aerospace SPARTA - run @ {now_utc_isoformat}"
        self.work_id = self.helper.api.work.initiate_work(
            self.config.connector.id, friendly_name
        )

    def _send_intelligence(self, prepared_objects: list):
        """This method prepares and sends unique STIX objects to OpenCTI.
        This method takes a list of objects prepared by the models, extracts their STIX representations, creates a
        serialized STIX bundle, and It then sends this bundle to OpenCTI.
        If prepared objects exist, the method ensures that only unique objects with an 'id' attribute are included.
        After sending the STIX objects, it keeps inform of the number of bundles sent.

        Args:
            prepared_objects (list): A list of objects containing STIX representations to be sent to OpenCTI.
        """
        bundle_sent = self.helper.send_stix2_bundle(
            prepared_objects,
            work_id=self.work_id,
            cleanup_inconsistent_bundle=True,
        )

        length_bundle_sent = len(bundle_sent)
        self.helper.connector_logger.info(
            "[CONNECTOR] Sending STIX objects to OpenCTI...",
            {"length_bundle_sent": length_bundle_sent},
        )

    def _complete_work(self):
        """Marks the work process as complete.
        This method logs the completion of the work for a specific work ID.
        Sends a request to the API with the to_processed method to complete the work.
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Complete work...",
            {
                "work_id": self.work_id,
            },
        )
        message = "Aerospace SPARTA - Finished work"
        if self.work_id:
            self.helper.api.work.to_processed(self.work_id, message)
        self.work_id = None

    def _collect_intelligence(self):
        """Collect intelligence from the source.
        Returns:
            List of STIX objects or None
        """
        try:
            stix_bundle = self.client.retrieve_data()

            return stix_bundle
        except Exception as err:
            self.helper.connector_logger.error(
                "[ERROR] An unexpected error has occurred while collecting intelligence.",
                {"error": err},
            )
            raise

    def _transform_intelligence(self, collected_intelligence: list) -> list:
        """Add author and TLP to each object in collected_intelligence
        Returns:
            List of STIX objects
        """
        try:
            self.helper.connector_logger.info(
                "[CONNECTOR] Starts transforming intelligence to STIX 2.1 format..."
            )

            stix_objects = collected_intelligence["objects"]
            author = self.converter_to_stix.create_author()

            for stix_object in stix_objects:
                stix_object["created_by_ref"] = author["id"]
                stix_object["object_marking_refs"] = [str(TLP_WHITE.id)]

            stix_objects.append(json.loads(author.serialize()))
            stix_objects.append(json.loads(TLP_WHITE.serialize()))
            collected_intelligence["objects"] = stix_objects

            # The SPARTA dataset is already a bundle
            len_stix_objects = len(collected_intelligence["objects"])
            self.helper.connector_logger.info(
                "[CONNECTOR] Finalisation of the transforming intelligence to STIX 2.1 format.",
                {"len_stix_objects": len_stix_objects},
            )
            return json.dumps(collected_intelligence)

        except Exception as err:
            self.helper.connector_logger.error(
                "[ERROR] An unexpected error has occurred during intelligence transformation.",
                {"error": err},
            )
            raise

    def process_message(self) -> None:
        """The main process used by the connector to collect intelligence.
        This method launches the connector, processes the current state,
        collects intelligence data and updates the state of the last successful execution.

        Returns:
            None
        """
        try:
            # Initialization to get the current start utc iso format.
            now_utc = datetime.now(timezone.utc)
            current_start_utc_isoformat = now_utc.isoformat(timespec="seconds")

            # Get the current state
            current_state = self.helper.get_state()

            self.last_run = (
                current_state.get("last_run", None) if current_state else None
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Starting connector...",
                {
                    "connector_name": self.config.connector.name,
                    "connector_start_time": current_start_utc_isoformat,
                    "last_run": (
                        self.last_run if self.last_run else "Connector has never run"
                    ),
                },
            )

            collected_intelligence = self._collect_intelligence()

            if collected_intelligence:
                # Initiate work
                self._initiate_work()

                # Start transforming data for OpenCTI - Converted to stix format
                prepared_intelligence = self._transform_intelligence(
                    collected_intelligence
                )
                self._send_intelligence(prepared_intelligence)

            # Store the current start utc isoformat as a last run of the connector.
            self.helper.connector_logger.info(
                "[CONNECTOR] Getting current state and update it with last run of the connector.",
                {
                    "current_state": self.last_run,
                    "new_last_run": current_start_utc_isoformat,
                },
            )
            if self.last_run:
                current_state["last_run"] = current_start_utc_isoformat
            else:
                current_state = {"last_run": current_start_utc_isoformat}

            self.helper.set_state(current_state)

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(str(err))
        finally:
            self._complete_work()

    def run(self) -> None:
        """Run the main process encapsulated in a scheduler
        It allows you to schedule the process to run at a certain intervals
        This specific scheduler from the pycti connector helper will also check the queue size of a connector
        If `CONNECTOR_QUEUE_THRESHOLD` is set, if the connector's queue size exceeds the queue threshold,
        the connector's main process will not run until the queue is ingested and reduced sufficiently,
        allowing it to restart during the next scheduler check. (default is 500MB)
        It requires the `duration_period` connector variable in ISO-8601 standard format
        Example: `CONNECTOR_DURATION_PERIOD=PT5M` => Will run the process every 5 minutes
        If `duration_period` is set to 0 then it will function as a run and terminate
        Returns:
            None
        """
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
