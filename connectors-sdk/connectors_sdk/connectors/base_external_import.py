"""
Base classes for external-import connectors covering ~85% of use cases.

Architecture:
- BaseExternalImportConnector: Orchestrator (uses managers)
- StateManager: State lifecycle
- WorkManager: Work orchestration
- ErrorHandler: Error handling & logging
- ProcessingEngine: Collection → Bundle → Send pipeline
- ConverterFactory: Converter creation

Subclasses should:
1. Implement _create_converter() (ConverterFactory pattern)
2. Implement _get_processing_engine() to return appropriate engine
3. For simple case: inherit SimpleProcessingEngine via engine factory
"""

import sys
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, List, Optional

import stix2
from connectors_sdk.connectors.managers import (
    BatchingProcessingEngine,
    ConverterFactory,
    ErrorHandler,
    MultiHandlerProcessingEngine,
    ProcessingEngine,
    SimpleProcessingEngine,
    StateManager,
    StreamingProcessingEngine,
    WorkManager,
)
from pycti import OpenCTIConnectorHelper


class BaseExternalImportConnector(ABC):
    """
    Base orchestrator for external-import connectors.

    Orchestrates managers and processing engine without implementing business logic.
    Delegates to dependencies injected via factory methods.

    Responsibilities:
    - Orchestrate connector lifecycle (run, process_message)
    - Wire up managers and engines
    - Ensure error handling and logging consistency

    NOT responsible for:
    - Intelligence collection (ProcessingEngine)
    - State management details (StateManager)
    - Work orchestration details (WorkManager)
    - Error handling details (ErrorHandler)
    """

    def __init__(self, config: Any, helper: OpenCTIConnectorHelper) -> None:
        """Initialize connector with config and helper."""
        self.config = config
        self.helper = helper

        # Create managers
        self.state_manager = StateManager(helper)
        self.work_manager = WorkManager(helper)
        self.error_handler = ErrorHandler(helper)

        # Create processing engine (subclass decides type)
        self.processing_engine = self._create_processing_engine()

    def run(self) -> None:
        """
        Scheduler entry point. Can be overridden for custom scheduling.
        """
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period,
        )

    def process_message(self) -> None:
        """
        Main processing loop. Standard workflow for all connectors:
        1. Load state
        2. Process intelligence (engine creates and manages its own works)
        3. Update state
        """
        try:
            self.error_handler.log_info(
                f"Starting {self.helper.connect_name}...",
                connector_name=self.helper.connect_name,
            )

            # 1. Load state
            now = datetime.now(timezone.utc)
            current_timestamp = int(datetime.timestamp(now))
            self.state_manager.load_state()
            self.error_handler.log_debug(
                f"Loaded state",
                state=self.state_manager.load_state(),
            )

            # 2. Process intelligence (engine manages work creation)
            self.processing_engine.process()

            # 3. Update state
            self.state_manager.update_timestamp(current_timestamp)
            
            self.error_handler.log_info(
                f"{self.helper.connect_name} completed",
                connector_name=self.helper.connect_name,
            )

        except (KeyboardInterrupt, SystemExit):
            self.error_handler.handle_keyboard_interrupt()
        except Exception as err:
            self.error_handler.handle_error(
                err, {"connector": self.helper.connect_name}
            )

    @abstractmethod
    def _create_processing_engine(self) -> ProcessingEngine:
        """
        Create the processing engine for this connector.

        Subclasses choose: SimpleProcessingEngine, StreamingProcessingEngine, etc.

        Returns:
            ProcessingEngine instance
        """
        pass

    @abstractmethod
    def _create_converter(self) -> Any:
        """
        Create the converter for transforming data to STIX.

        Returns:
            Converter instance
        """
        pass

    # ============ Utility properties for backward compatibility ============

    @property
    def converter_to_stix(self) -> Any:
        """Access converter via common name."""
        return self._create_converter()


class SimpleExternalImportConnector(BaseExternalImportConnector):
    """
    Simple connector for basic feeds.

    Usage:
    ```python
    class MyConnector(SimpleExternalImportConnector):
        def _collect_intelligence(self):
            client = APIClient(self.config)
            data = client.fetch()
            return [self.converter_to_stix.convert(item) for item in data]

        def _create_converter(self):
            return MyConverter(self.config, self.helper)
    ```
    """

    def _create_processing_engine(self) -> ProcessingEngine:
        """Create simple processing engine."""
        converter = self._create_converter()
        engine = SimpleProcessingEngine(
            self.helper, self.error_handler, self.work_manager
        )

        # Bind converter to engine
        engine._converter = converter
        engine.collect_intelligence = self._collect_intelligence

        return engine

    @abstractmethod
    def _collect_intelligence(self) -> List[stix2.base._STIXBase]:
        """
        Collect and convert intelligence to STIX objects.
        Subclasses must implement this.

        Returns:
            List of STIX 2.1 objects
        """
        pass


class StreamingExternalImportConnector(BaseExternalImportConnector):
    """
    Streaming connector for large datasets.

    Processes data in chunks via generators for memory efficiency.

    Usage:
    ```python
    class MyConnector(StreamingExternalImportConnector):
        def _collect_intelligence_stream(self):
            client = APIClient(self.config)
            for page in client.fetch_paginated():
                yield [self.converter_to_stix.convert(item) for item in page]

        def _create_converter(self):
            return MyConverter(self.config, self.helper)
    ```
    """

    def _create_processing_engine(self) -> ProcessingEngine:
        """Create streaming processing engine."""
        converter = self._create_converter()
        
        engine = StreamingProcessingEngine(
            self.helper,
            self.error_handler,
            self.work_manager,
        )

        # Bind converter and stream method to engine
        engine._converter = converter
        engine.collect_intelligence_stream = self._collect_intelligence_stream

        return engine

    @abstractmethod
    def _collect_intelligence_stream(self):
        """
        Stream intelligence as chunks (generator).
        Subclasses must implement this instead of _collect_intelligence().

        Yields:
            Lists of STIX 2.1 objects
        """
        pass


class BatchingExternalImportConnector(BaseExternalImportConnector):
    """
    Batching connector for progressive sending.

    Collects all data then sends in batches, updating state per batch.
    Prevents memory spikes and allows progress tracking.

    Usage:
    ```python
    class MyConnector(BatchingExternalImportConnector):
        def _collect_intelligence(self):
            client = APIClient(self.config)
            data = client.fetch_all()
            return [self.converter_to_stix.convert(item) for item in data]

        def _create_converter(self):
            return MyConverter(self.config, self.helper)
    ```
    """

    def _create_processing_engine(self) -> ProcessingEngine:
        """Create batching processing engine."""
        converter = self._create_converter()
        batch_size = getattr(self.config, "batch_size", 100)
        work_per_batch = getattr(self.config, "work_per_batch", False)

        engine = BatchingProcessingEngine(
            self.helper,
            self.error_handler,
            self.work_manager,
            batch_size=batch_size,
            state_manager=self.state_manager,
            work_per_batch=work_per_batch,
        )

        # Bind converter to engine
        engine._converter = converter
        engine.collect_intelligence = self._collect_intelligence

        return engine

    @abstractmethod
    def _collect_intelligence(self) -> List[stix2.base._STIXBase]:
        """
        Collect all intelligence to process in batches.
        Subclasses must implement this.

        Returns:
            List of STIX 2.1 objects
        """
        pass


class MultiHandlerExternalImportConnector(BaseExternalImportConnector):
    """
    Multi-handler connector for multiple data sources.

    Orchestrates multiple independent handlers/importers.
    Each handler manages its own collection and state.

    Usage:
    ```python
    class MyConnector(MultiHandlerExternalImportConnector):
        def __init__(self, config, helper):
            super().__init__(config, helper)

        def _get_handlers(self):
            return [
                PublicationHandler(self.helper, self.config),
                IOCHandler(self.helper, self.config),
            ]

        def _create_converter(self):
            return None  # Handlers manage their own conversion
    ```
    """

    def _create_processing_engine(self) -> ProcessingEngine:
        """Create multi-handler processing engine."""
        handlers = self._get_handlers()
        work_per_handler = getattr(self.config, "work_per_handler", False)
        
        engine = MultiHandlerProcessingEngine(
            self.helper,
            self.error_handler,
            self.work_manager,
            handlers=handlers,
            work_per_handler=work_per_handler,
        )
        return engine

    @abstractmethod
    def _get_handlers(self) -> List[Any]:
        """
        Get list of handlers for this connector.

        Each handler should have a run(work_id) method that returns List[STIX].

        Returns:
            List of handler instances
        """
        pass

    def _create_converter(self) -> Any:
        """Not used in multi-handler mode."""
        return None
