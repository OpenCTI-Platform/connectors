import abc
import datetime
import sys
import traceback
from typing import Any

import stix2
from base_connector.client import BaseClient
from base_connector.config import BaseConnectorConfig
from base_connector.converter import BaseConverter
from base_connector.errors import ConnectorError, ConnectorWarning
from pycti import OpenCTIConnectorHelper


class BaseConnector(abc.ABC):
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
        config: BaseConnectorConfig,
        converter: BaseConverter,
        client: BaseClient | None = None,
    ) -> None:
        self.helper = helper
        self.config = config
        self.converter = converter
        self.client = client

    def get_state(self) -> dict[str, Any]:
        state = self.helper.get_state() or {}
        last_run = state.get("last_run", "Connector has never run...")
        self.helper.connector_logger.info(f"Connector last run: {last_run}")
        return state

    def update_state(
        self, current_state: dict[str, str], run_time: datetime.datetime
    ) -> None:
        current_state["last_run"] = run_time.isoformat(timespec="seconds")
        self.helper.connector_logger.info(f"Updating state last_run to {run_time}")
        self.helper.set_state(state=current_state)

    def initiate_work(self) -> str:
        return self.helper.api.work.initiate_work(
            connector_id=self.helper.connect_id, friendly_name=self.helper.connect_name
        )

    def finalize_work(self, work_id: str, message: str) -> None:
        self.helper.api.work.to_processed(work_id=work_id, message=message)

    def create_and_send_bundles(self, work_id: str, stix_objects: list[Any]) -> None:
        if not stix_objects:
            self.helper.connector_logger.info("No STIX objects to process.")
            return

        bundle = self.helper.stix2_create_bundle(
            items=stix_objects + [self.converter.author, self.converter.tlp_marking]
        )
        bundles_sent = self.helper.send_stix2_bundle(
            bundle=bundle,
            work_id=work_id,
            cleanup_inconsistent_bundle=True,
        )
        self.helper.connector_logger.info(
            f"Sent {len(bundles_sent)} STIX objects to OpenCTI."
        )

    def process_message(self) -> None:
        run_time = datetime.datetime.now(tz=datetime.UTC)
        state = self.get_state()
        work_id = self.initiate_work()

        stix_objects = self.collect_intelligence()
        self.create_and_send_bundles(work_id, stix_objects)

        self.update_state(state, run_time)
        message = f"Connector successfully run, storing last_run as {run_time}"
        self.finalize_work(work_id, message)

    def process(self) -> str | None:
        meta = {"connector_name": self.helper.connect_name}
        try:
            self.helper.connector_logger.info("Running connector...", meta=meta)
            self.process_message()
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("Connector stopped by user.", meta=meta)
            sys.exit(0)
        except ConnectorWarning as e:
            self.helper.connector_logger.warning(str(e), meta=meta)
            return str(e)
        except ConnectorError as e:
            self.helper.connector_logger.error(str(e), meta=meta)
            return str(e)
        except Exception as e:
            traceback.print_exc()
            self.helper.connector_logger.error(f"Unexpected error: {e}", meta=meta)
            return "Unexpected error. See connector logs for details."
        return None

    def run(self) -> None:
        self.helper.connector_logger.info("Starting connector...")
        self.helper.schedule_process(
            message_callback=self.process,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )

    @abc.abstractmethod
    def collect_intelligence(self) -> list[stix2.v21._STIXBase21]:
        """
        Collect and process the source of CTI.

        This method must be implemented by each connector and return  a list of STIX objects.
        """
