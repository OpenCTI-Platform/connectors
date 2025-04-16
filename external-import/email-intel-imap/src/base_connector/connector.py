import abc
import datetime
import sys
from typing import Any, Generic, TypeVar

from base_connector.client import BaseClient
from base_connector.config import BaseConnectorConfig
from base_connector.converter import BaseConverter
from base_connector.errors import ConnectorError, ConnectorWarning
from pycti import OpenCTIConnectorHelper

ConfigType = TypeVar("ConfigType", bound=BaseConnectorConfig)
ClientType = TypeVar("ClientType", bound=BaseClient)
ConverterType = TypeVar("ConverterType", bound=BaseConverter[Any, Any])


class BaseConnector(abc.ABC, Generic[ConfigType, ClientType, ConverterType]):
    """
    Specifications of the external import connector

    This class encapsulates the main actions, expected to be run by any external import connector.
    Note that the attributes defined below will be complemented per each connector type.
    This type of connector aim to fetch external data to create STIX bundle and send it in a RabbitMQ queue.
    The STIX bundle in the queue will be processed by the workers.
    This type of connector uses the basic methods of the helper.

    ---

    Attributes
        - `helper (OpenCTIConnectorHelper(config))`:
            This is the helper to use.
            ALL connectors have to instantiate the connector helper with configurations.
            Doing this will do a lot of operations behind the scene.
        - `config (BaseConnectorConfig)`:
            This is the connector configuration.
        - `client (BaseClient)`:
            This is the connector client.
        - `converter (BaseConverter)`:
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

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        config: ConfigType,
        client: ClientType,
        converter: ConverterType,
    ) -> None:
        self.helper = helper
        self.config = config
        self.client = client
        self.converter = converter

    @abc.abstractmethod
    def _collect_intelligence(self) -> list[Any]:
        """Collect intelligence from the source and return it as a list of Stix2 objects."""

    def _process_message(self) -> None:
        """Connector main process to collect intelligence."""
        # TODO: Implement all the steps to verify a connector here

        # TODO: Isolate and fix the next 3 lines
        now = datetime.datetime.now(tz=datetime.UTC)
        current_state = self.helper.get_state()
        if current_state is not None and "last_run" in current_state:
            last_run = current_state["last_run"]

            self.helper.connector_logger.info(
                "Connector last run",
                {"last_run_datetime": last_run},
            )
        else:
            self.helper.connector_logger.info("Connector has never run...")

        self.helper.connector_logger.info(
            "Running connector...",
            {"connector_name": self.helper.connect_name},
        )

        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, self.helper.connect_name
        )

        if stix_objects := self._collect_intelligence():
            stix_objects.extend([self.converter.author, self.converter.tlp_marking])
            stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
            bundles_sent = self.helper.send_stix2_bundle(
                stix_objects_bundle,
                work_id=work_id,
                cleanup_inconsistent_bundle=True,
            )

            self.helper.connector_logger.info(  # TODO: Implement checks on the bundle
                "Sending STIX objects to OpenCTI...",
                {"bundles_sent": {str(len(bundles_sent))}},
            )

        # TODO: Isolate set state
        # Store the current timestamp as a last run of the connector
        self.helper.connector_logger.debug(
            "Getting current state and update it with last run of the connector",
            {"current_timestamp": now.timestamp()},
        )
        current_state = self.helper.get_state()
        if current_state:
            current_state["last_run"] = now.isoformat(sep=" ", timespec="seconds")
        else:
            current_state = {"last_run": now.isoformat(sep=" ", timespec="seconds")}
        self.helper.set_state(current_state)

        message = f"Connector successfully run, storing last_run as {str(now)}"

        self.helper.api.work.to_processed(work_id, message)
        self.helper.connector_logger.info(message)

    def process_message(self) -> str | None:
        try:
            self.helper.connector_logger.info(
                "Starting connector...",
                {"connector_name": self.helper.connect_name},
            )

            self._process_message()
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except ConnectorWarning as e:
            self.helper.connector_logger.warning(e)
            return str(e)
        except ConnectorError as e:
            self.helper.connector_logger.error(e)
            return str(e)
        except Exception as e:
            self.helper.connector_logger.error("Unexpected error.", {"error": str(e)})
            return "Unexpected error. See connector's log for more details."
        return None

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
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
