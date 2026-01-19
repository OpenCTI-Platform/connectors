import sys
from datetime import datetime, timezone
from typing import Generator

from pycti import OpenCTIConnectorHelper

from .client_api import ConnectorClient
from .config_loader import ConfigConnector
from .converter_to_stix import ConverterToStix


class ConnectorURLhaus:
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

    def __init__(self, config: ConfigConnector, helper: OpenCTIConnectorHelper):
        """
        Initialize the Connector with necessary configurations
        """

        # Load configuration file and connection helper
        self.config = config
        self.helper = helper
        self.client = ConnectorClient(self.helper, self.config)
        self.converter_to_stix = ConverterToStix(self.helper, self.config)

    def _collect_intelligence(self) -> Generator[list, None, None]:
        """
        Collect intelligence from the source and convert into STIX object
        :return: List of STIX objects
        """
        # Get entities from external sources
        entities_generator = self.client.get_entities()

        # Convert into STIX2 object and add it on a list
        for entities in entities_generator:
            stix_objects = []
            for entity in entities:
                external_reference = self.converter_to_stix.create_external_reference(
                    entity
                )
                stix_indicator = self.converter_to_stix.create_indicator(
                    entity, external_reference
                )
                stix_observable = self.converter_to_stix.create_obs_url(
                    entity, external_reference
                )
                stix_relationship = self.converter_to_stix.create_relationship(
                    stix_indicator.id, "based-on", stix_observable.id
                )

                stix_objects.append(stix_indicator)
                stix_objects.append(stix_observable)
                stix_objects.append(stix_relationship)

                if self.config.threats_from_labels:
                    stix_threat_relations = (
                        self.converter_to_stix.create_threat_relationship(
                            entity, stix_indicator.id, stix_observable.id
                        )
                    )
                    stix_objects.extend(stix_threat_relations)
            # end for

            if len(stix_objects) == 0:
                continue

            stix_objects.append(self.converter_to_stix.author)
            yield stix_objects
        # end for

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

            # Friendly name will be displayed on OpenCTI platform
            friendly_name = "Connector urlhaus feed"

            # Initiate a new work
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Running connector...",
                {"connector_name": self.helper.connect_name},
            )

            # initialize the threat cache with each run
            self.config.threat_cache = {}

            # Performing the collection of intelligence
            stix_objects_generator = self._collect_intelligence()
            for stix_objects in stix_objects_generator:
                if len(stix_objects) == 0:
                    continue

                stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
                bundles_sent = self.helper.send_stix2_bundle(
                    stix_objects_bundle,
                    update=self.config.update_existing_data,
                    work_id=work_id,
                )

                self.helper.connector_logger.info(
                    "Sending STIX objects to OpenCTI...",
                    {"bundles_sent": {str(len(bundles_sent))}},
                )
            # end for

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

            current_state["last_processed_entry"] = self.config.last_processed_entry_new
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
        :return: None
        """
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=f"P{self.config.interval}D",
        )
