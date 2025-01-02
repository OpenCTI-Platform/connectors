import sys
from datetime import datetime
from threading import Lock, Thread
from typing import NotRequired, Optional, TypedDict, cast

from pycti import OpenCTIConnectorHelper
from stix2 import TAXIICollectionSource

from .client_api import ConnectorClient
from .config_variables import ConfigConnector


class FeedState(TypedDict):
    added_after: NotRequired[str]


class ConnectorIBMXTIState(TypedDict):
    last_run: NotRequired[str]
    feed_states: NotRequired[dict[str, FeedState]]


class ConnectorIBMXTI:
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

    __config: ConfigConnector
    __helper: OpenCTIConnectorHelper
    __client: ConnectorClient
    __state_lock: Lock

    def __init__(self):
        """
        Initialize the Connector with necessary configurations
        """

        # Load configuration file and connection helper
        self.__config = ConfigConnector()
        self.__helper = OpenCTIConnectorHelper(self.__config.load)
        self.__client = ConnectorClient(self.__helper, self.__config)
        self.__state_lock = Lock()

    def __ingest_feed_helper(
        self,
        source: TAXIICollectionSource,
        current_state: ConnectorIBMXTIState,
    ):
        with self.__state_lock:
            feed_states = current_state.get("feed_states")
            if not feed_states:
                feed_states = current_state["feed_states"] = {}

        feed_state = feed_states.get(source.collection.id)
        if not feed_state:
            feed_state = feed_states[source.collection.id] = {}

        added_after = feed_state.get("added_after")

        for stix_objects, new_added_after in self.__client.get_latest_stix_objects(
            source, added_after
        ):
            if len(stix_objects) > 0:
                stix_objects_bundle = self.__helper.stix2_create_bundle(stix_objects)

                if self.__config.debug:
                    self.__helper.connector_logger.info(
                        "Created STIX bundle:", stix_objects_bundle
                    )
                    continue

                if stix_objects_bundle:
                    bundles_sent = self.__helper.send_stix2_bundle(stix_objects_bundle)
                else:
                    bundles_sent = []

                self.__helper.connector_logger.info(
                    f"Sent {len(bundles_sent)} STIX bundles to OpenCTI"
                )

            if (
                not self.__config.debug
            ):  # this would only happen if no STIX objects are found, but we still shouldn't update the state in debug mode
                with self.__state_lock:
                    feed_state["added_after"] = new_added_after
                    self.__helper.set_state(current_state)
                    self.__helper.connector_logger.info(
                        f"Updated 'added_after' to '{new_added_after}' for collection '{source.collection.title}'"
                    )

    def __ingest_feed(
        self, source: TAXIICollectionSource, current_state: ConnectorIBMXTIState
    ):
        t = Thread(
            target=self.__ingest_feed_helper, args=(source, current_state), daemon=True
        )
        t.start()

        return t

    def __collect_intelligence(self, current_state: Optional[ConnectorIBMXTIState]):
        """
        Collect intelligence from the source and convert into STIX object
        :return: List of STIX objects
        """
        taxii_collection_sources = self.__client.get_collection_sources()
        threads: list[Thread] = []

        if not current_state:
            current_state = {}

        if self.__config.taxii_collections and self.__config.taxii_collections.strip():
            self.__helper.connector_logger.info(
                "Retrieving data from specified collections only"
            )

            taxii_collection_ids = list(
                map(lambda c: c.strip(), self.__config.taxii_collections.split(","))
            )

            for collection_id in taxii_collection_ids:
                source = taxii_collection_sources.get(collection_id)
                if not source:
                    self.__helper.connector_logger.error(
                        f"Collection '{collection_id}' does not exist or user does not have access"
                    )
                    continue

                threads.append(self.__ingest_feed(source, current_state))
        else:
            self.__helper.connector_logger.info(
                "Retrieving data from all collections user has access to"
            )

            for source in taxii_collection_sources.values():
                threads.append(self.__ingest_feed(source, current_state))

        for t in threads:
            t.join()

    def process_message(self) -> None:
        """
        Connector main process to collect intelligence
        :return: None
        """
        self.__helper.connector_logger.info(
            "[CONNECTOR] Starting connector...",
            {"connector_name": self.__helper.connect_name},
        )

        try:
            # Get the current state
            now = datetime.now()
            current_timestamp = int(datetime.timestamp(now))
            current_state = cast(ConnectorIBMXTIState, self.__helper.get_state())

            if current_state is not None and "last_run" in current_state:
                self.__helper.connector_logger.info(
                    "[CONNECTOR] Connector last run",
                    {"last_run_datetime": current_state["last_run"]},
                )
            else:
                self.__helper.connector_logger.info(
                    "[CONNECTOR] Connector has never run..."
                )

            # Friendly name will be displayed on OpenCTI platform
            friendly_name = (
                "Connector IBM X-Force Premier Threat Intelligence Services feed"
            )

            # Initiate a new work
            work_id = self.__helper.api.work.initiate_work(
                self.__helper.connect_id, friendly_name  # type: ignore
            )

            self.__helper.connector_logger.info(
                "[CONNECTOR] Running connector...",
                {"connector_name": self.__helper.connect_name},
            )

            # Performing the collection of intelligence
            self.__collect_intelligence(current_state)

            # Store the current timestamp as a last run of the connector
            self.__helper.connector_logger.debug(
                "Getting current state and update it with last run of the connector",
                {"current_timestamp": current_timestamp},
            )
            current_state = self.__helper.get_state()
            current_state_datetime = now.strftime("%Y-%m-%d %H:%M:%S")
            last_run_datetime = datetime.utcfromtimestamp(current_timestamp).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            if current_state:
                current_state["last_run"] = current_state_datetime
            else:
                current_state = {"last_run": current_state_datetime}
            self.__helper.set_state(current_state)

            message = (
                f"{self.__helper.connect_name} connector successfully run, storing last_run as "
                + str(last_run_datetime)
            )

            self.__helper.api.work.to_processed(work_id, message)
            self.__helper.connector_logger.info(message)

        except (KeyboardInterrupt, SystemExit):
            self.__helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.__helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:  # pylint: disable=broad-exception-caught
            self.__helper.connector_logger.error(str(err))

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
        self.__helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.__config.duration_period,  # type: ignore
        )
