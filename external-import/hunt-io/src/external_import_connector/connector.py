import sys
from datetime import datetime, timezone
from typing import List, Optional

from external_import_connector.batch_manager import BatchManager
from external_import_connector.client_api import ConnectorClient
from external_import_connector.constants import (
    DateTimeFormats,
    LoggingPrefixes,
    StateKeys,
)
from external_import_connector.converter_to_stix import ConverterToStix
from external_import_connector.entity_processor import EntityProcessor
from external_import_connector.models import C2
from external_import_connector.settings import ConfigLoader
from pycti import OpenCTIConnectorHelper


class StateManager:
    """Manages connector state operations."""

    def __init__(self, helper: OpenCTIConnectorHelper):
        self.helper = helper

    def get_last_timestamp(self) -> Optional[str]:
        """Get the last processed timestamp from state."""
        current_state = self.helper.get_state()
        if current_state and StateKeys.LAST_TIMESTAMP in current_state:
            return current_state[StateKeys.LAST_TIMESTAMP]
        return None

    def update_processing_state(self, processing: bool) -> None:
        """Update the processing flag in state."""
        current_state = self.helper.get_state() or {}
        current_state[StateKeys.PROCESSING] = processing
        self.helper.set_state(current_state)

    def is_processing(self) -> bool:
        """Check if connector is currently processing."""
        current_state = self.helper.get_state()
        return current_state and current_state.get(StateKeys.PROCESSING, False)

    def update_run_state(
        self, latest_timestamp: Optional[str], entities_processed: int
    ) -> None:
        """Update state after successful run."""
        current_state = self.helper.get_state() or {}

        if latest_timestamp:
            current_state[StateKeys.LAST_TIMESTAMP] = latest_timestamp

        current_state[StateKeys.LAST_RUN] = datetime.now(timezone.utc).strftime(
            DateTimeFormats.STANDARD_FORMAT
        )
        current_state[StateKeys.ENTITIES_PROCESSED] = entities_processed
        current_state[StateKeys.PROCESSING] = False

        self.helper.set_state(current_state)


class IntelligenceCollector:
    """Handles the intelligence collection and ingestion process."""

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        client: ConnectorClient,
        entity_processor: EntityProcessor,
        batch_manager: BatchManager,
        state_manager: StateManager,
    ):
        self.helper = helper
        self.client = client
        self.entity_processor = entity_processor
        self.batch_manager = batch_manager
        self.state_manager = state_manager

    def collect(self) -> list[C2]:
        """Collect intelligence from the source"""
        # Get current state for incremental processing
        last_timestamp = self.state_manager.get_last_timestamp()

        if last_timestamp:
            self.helper.connector_logger.info(
                f"{LoggingPrefixes.CONNECTOR} Incremental run - fetching entities since: {last_timestamp}"
            )
        else:
            self.helper.connector_logger.info(
                f"{LoggingPrefixes.CONNECTOR} First run - fetching ALL entities"
            )

        # Fetch entities incrementally to prevent reprocessing large datasets
        entities: list[C2] = (
            self.client.get_entities(since_timestamp=last_timestamp) or []
        )

        return entities

    def ingest(self, entities) -> None:
        """Convert intelligence into STIX objects and send incrementally to OpenCTI."""

        # Check system health before processing
        if not self.batch_manager.check_processing_feasibility():
            return

        # Apply emergency limits
        entities = self.batch_manager.apply_emergency_limits(entities)

        self.helper.connector_logger.info(
            f"{LoggingPrefixes.CONNECTOR} Processing {len(entities)} NEW entities (incremental processing)"
        )

        # Process entities using sequential batching approach
        self._process_entities_sequentially(entities)

        # Update state with latest timestamp for next incremental run
        if hasattr(self.client, "latest_timestamp") and self.client.latest_timestamp:
            self.state_manager.update_run_state(
                self.client.latest_timestamp, len(entities)
            )

            self.helper.connector_logger.info(
                f"{LoggingPrefixes.CONNECTOR} Updated state - last_timestamp: {self.client.latest_timestamp}, "
                f"entities_processed: {len(entities)}"
            )

    def _process_entities_sequentially(self, entities: List[C2]) -> None:
        """
        Process entities using sequential batching to prevent race conditions.
        Phase 1: Create all STIX objects (indicators, infrastructure, malware, etc.)
        Phase 2: Create all relationships after objects exist
        This prevents MISSING_REFERENCE_ERROR issues.
        """
        batch_size = self.batch_manager.get_optimal_batch_size()

        self.helper.connector_logger.info(
            f"{LoggingPrefixes.CONNECTOR} Processing {len(entities)} entities using sequential batching approach "
            f"(batch size: {batch_size})"
        )

        # Phase 1: Process all entities to create STIX objects (no relationships)
        self.helper.connector_logger.info(
            f"{LoggingPrefixes.SEQUENTIAL_BATCH} Phase 1: Creating all STIX objects..."
        )
        all_objects, entity_metadata = (
            self.entity_processor.process_entities_objects_phase(entities, batch_size)
        )

        # Phase 2: Process all relationships using the created objects
        self.helper.connector_logger.info(
            f"{LoggingPrefixes.SEQUENTIAL_BATCH} Phase 2: Creating all relationships..."
        )
        all_relationships = self.entity_processor.process_entities_relationships_phase(
            entity_metadata, batch_size
        )

        # Phase 3: Send final consolidated bundle with all objects and relationships
        self.helper.connector_logger.info(
            f"{LoggingPrefixes.SEQUENTIAL_BATCH} Phase 3: Sending consolidated bundle..."
        )
        self.batch_manager.send_consolidated_bundle(
            all_objects, all_relationships, len(entities)
        )


class ConnectorHuntIo:
    """
    Hunt.IO external import connector.

    This connector fetches threat intelligence data from Hunt.IO API and converts it
    to STIX format for ingestion into OpenCTI. It follows SOLID principles with
    clear separation of concerns.
    """

    def __init__(self, config: ConfigLoader, helper: OpenCTIConnectorHelper):
        """Initialize the Connector with necessary configurations."""
        # Load configuration and setup helper
        self.config = config
        self.helper = helper

        # Initialize components following dependency injection pattern
        self.client = ConnectorClient(self.helper, self.config)
        self.converter_to_stix = ConverterToStix(
            self.helper, self.config.hunt_io.tlp_level
        )
        self.entity_processor = EntityProcessor(self.helper, self.converter_to_stix)
        self.batch_manager = BatchManager(self.helper)
        self.state_manager = StateManager(self.helper)

        # Initialize intelligence collector with all dependencies
        self.intelligence_collector = IntelligenceCollector(
            self.helper,
            self.client,
            self.entity_processor,
            self.batch_manager,
            self.state_manager,
        )

    def collect_intelligence(self) -> list[C2]:
        """Collect intelligence from the source"""
        return self.intelligence_collector.collect()

    def ingest_intelligence(self, entities: list[C2]) -> None:
        """Convert intelligence into STIX objects and send incrementally to OpenCTI."""
        self.intelligence_collector.ingest(entities)

    def process_message(self) -> None:
        """
        Connector main process to collect intelligence.
        """
        # Check if previous run is still processing
        if self.state_manager.is_processing():
            self.helper.connector_logger.warning(
                f"{LoggingPrefixes.CONNECTOR} Previous run still processing, skipping this cycle to prevent overlap"
            )
            return

        # Mark as processing
        self.state_manager.update_processing_state(True)

        self.helper.connector_logger.info(
            f"{LoggingPrefixes.CONNECTOR} Starting connector...",
            {"connector_name": self.helper.connect_name},
        )

        try:
            # Get the current state
            now = datetime.now(timezone.utc)
            current_timestamp = int(datetime.timestamp(now))
            current_state = self.helper.get_state()

            if current_state is not None and StateKeys.LAST_RUN in current_state:
                last_run = current_state[StateKeys.LAST_RUN]
                self.helper.connector_logger.info(
                    f"{LoggingPrefixes.CONNECTOR} Connector last run",
                    {"last_run_datetime": last_run},
                )
            else:
                self.helper.connector_logger.info(
                    f"{LoggingPrefixes.CONNECTOR} Connector has never run..."
                )

            self.helper.connector_logger.info(
                f"{LoggingPrefixes.CONNECTOR} Running connector...",
                {"connector_name": self.helper.connect_name},
            )

            # Performing the collection of intelligence
            entities = self.collect_intelligence()

            if entities:
                # Friendly name will be displayed on OpenCTI platform
                friendly_name = "Connector Hunt IO feed"

                # Initiate a new work
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )

                self.ingest_intelligence(entities)
            else:
                self.helper.connector_logger.info(
                    f"{LoggingPrefixes.CONNECTOR} No new entities to process since last run"
                )

            # Store the current timestamp as a last run of the connector
            self.helper.connector_logger.debug(
                "Getting current state and update it with last run of the connector",
                {"current_timestamp": current_timestamp},
            )
            current_state = self.helper.get_state()
            current_state_datetime = now.strftime(DateTimeFormats.STANDARD_FORMAT)
            if current_state:
                current_state[StateKeys.LAST_RUN] = current_state_datetime
            else:
                current_state = {
                    StateKeys.LAST_RUN: current_state_datetime,
                }

            if entities:
                current_state[StateKeys.LAST_RUN_WITH_INGESTED_DATA] = (
                    current_state_datetime
                )

            self.helper.set_state(current_state)

            # Mark processing as complete
            self.state_manager.update_processing_state(False)

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                f"{LoggingPrefixes.CONNECTOR} Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(str(err))
            # Mark processing as complete even on error
            self.state_manager.update_processing_state(False)
        finally:
            if entities:
                last_run_datetime = datetime.fromtimestamp(
                    current_timestamp, tz=timezone.utc
                ).strftime(DateTimeFormats.STANDARD_FORMAT)

                message = (
                    f"{self.helper.connect_name} connector successfully run, storing last_run as "
                    + str(last_run_datetime)
                )

                self.helper.connector_logger.info(message)
                self.helper.api.work.to_processed(work_id, message)

    def run(self) -> None:
        """
        Run the main process encapsulated in a scheduler.

        It allows you to schedule the process to run at certain intervals.
        This specific scheduler from the pycti connector helper will also check the queue size
        of a connector. If `CONNECTOR_QUEUE_THRESHOLD` is set, if the connector's queue size
        exceeds the queue threshold, the connector's main process will not run until the queue
        is ingested and reduced sufficiently, allowing it to restart during the next scheduler
        check. (default is 500MB)

        It requires the `duration_period` connector variable in ISO-8601 standard format.
        Example: `CONNECTOR_DURATION_PERIOD=PT5M` => Will run the process every 5 minutes
        """
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period,
        )
