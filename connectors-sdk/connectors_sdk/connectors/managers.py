"""
Managers and handlers for external-import connector lifecycle.

Separate concerns for better testability, reusability, and flexibility.
"""

import sys
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import stix2
from pycti import OpenCTIConnectorHelper


class StateManager:
    """
    Manages connector state (persisted via OpenCTI API).

    Responsibilities:
    - Load/save state
    - Update timestamps
    - Manage state cache
    """

    def __init__(self, helper: OpenCTIConnectorHelper) -> None:
        """Initialize with OpenCTI helper."""
        self.helper = helper
        self._cache: Optional[Dict[str, Any]] = None

    def load_state(self) -> Dict[str, Any]:
        """Load current state from OpenCTI."""
        if self._cache is None:
            self._cache = self.helper.get_state() or {}
        return self._cache

    def save_state(self, state: Dict[str, Any]) -> None:
        """Save state to OpenCTI."""
        self._cache = state
        self.helper.set_state(state)

    def get_value(self, key: str, default: Optional[Any] = None) -> Any:
        """Get a specific state value."""
        state = self.load_state()
        return state.get(key, default)

    def set_value(self, key: str, value: Any) -> None:
        """Set a specific state value."""
        state = self.load_state()
        state[key] = value
        self.save_state(state)

    def update_timestamp(self, timestamp: int) -> None:
        """Update last_run timestamp."""
        state = self.load_state()
        state["last_run"] = timestamp
        state["last_run_datetime"] = datetime.fromtimestamp(
            timestamp, tz=timezone.utc
        ).isoformat()
        self.save_state(state)

    def get_last_run(self) -> Optional[int]:
        """Get last run timestamp."""
        return self.get_value("last_run")

    def reset_cache(self) -> None:
        """Clear state cache to force reload."""
        self._cache = None


class WorkManager:
    """
    Manages work lifecycle with OpenCTI.

    Responsibilities:
    - Initiate work
    - Mark work complete
    - Handle work cleanup
    """

    def __init__(self, helper: OpenCTIConnectorHelper) -> None:
        """Initialize with OpenCTI helper."""
        self.helper = helper

    def initiate_work(self, friendly_name: str) -> str:
        """Initiate a new work."""
        return self.helper.api.work.initiate_work(
            self.helper.connect_id,
            friendly_name,
        )

    def mark_complete(
        self, work_id: str, message: str = "Successfully processed"
    ) -> None:
        """Mark work as complete."""
        self.helper.api.work.to_processed(work_id, message)

    def mark_failed(self, work_id: str, message: str = "Processing failed") -> None:
        """Mark work as failed."""
        self.helper.api.work.to_failed(work_id)


class ErrorHandler:
    """
    Centralized error handling and logging.

    Responsibilities:
    - Format error logs
    - Handle different error types
    - Provide consistent logging
    """

    def __init__(self, helper: OpenCTIConnectorHelper) -> None:
        """Initialize with OpenCTI helper."""
        self.helper = helper
        self.logger = helper.connector_logger

    def handle_error(
        self,
        error: Exception,
        context: Optional[Dict[str, Any]] = None,
        reraise: bool = True,
    ) -> None:
        """
        Handle an error with logging.

        Args:
            error: The exception to handle
            context: Additional context (meta data)
            reraise: Whether to re-raise the exception
        """
        meta = context or {}
        meta["error"] = str(error)
        meta["error_type"] = error.__class__.__name__

        self.logger.error(
            f"Error: {str(error)}",
            meta=meta,
        )

        if reraise:
            raise error

    def handle_keyboard_interrupt(self) -> None:
        """Handle keyboard interrupt."""
        connector_name = self.helper.connect_name
        self.logger.info(f"{connector_name} stopped by user")
        sys.exit(0)

    def log_info(self, msg: str, **kwargs) -> None:
        """Log info message."""
        self.logger.info(msg, meta=kwargs)

    def log_debug(self, msg: str, **kwargs) -> None:
        """Log debug message."""
        self.logger.debug(msg, meta=kwargs)

    def log_warning(self, msg: str, **kwargs) -> None:
        """Log warning message."""
        self.logger.warning(msg, meta=kwargs)


class ProcessingEngine(ABC):
    """
    Handles the intelligence processing pipeline.

    Responsibilities:
    - Orchestrate collect → bundle → send workflow
    - Handle different processing strategies (simple, streaming, batching)
    - Manage work lifecycle (single or multiple works)

    Subclasses implement different strategies.
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        error_handler: ErrorHandler,
        work_manager: "WorkManager",
    ) -> None:
        """Initialize with dependencies.
        
        Args:
            helper: OpenCTI helper
            error_handler: Error handler
            work_manager: Work manager for creating works
        """
        self.helper = helper
        self.error_handler = error_handler
        self.work_manager = work_manager

    def process(self) -> None:
        """
        Process intelligence and send to OpenCTI.
        
        Engine is responsible for creating its own work(s).
        """
        raise NotImplementedError

    def send_bundle(
        self,
        stix_objects: List[stix2.base._STIXBase],
        work_id: str,
        cleanup_inconsistent: bool = True,
    ) -> None:
        """
        Send STIX objects as bundle to OpenCTI.

        Args:
            stix_objects: List of STIX objects
            work_id: Work ID
            cleanup_inconsistent: Clean up inconsistent references
        """
        if not stix_objects:
            self.error_handler.log_info("No objects to send")
            return

        bundle = self.helper.stix2_create_bundle(stix_objects)
        self.helper.send_stix2_bundle(
            bundle,
            work_id=work_id,
            cleanup_inconsistent_bundle=cleanup_inconsistent,
        )

        self.error_handler.log_info(
            f"Sent {len(stix_objects)} STIX objects",
            object_count=len(stix_objects),
        )

    @abstractmethod
    def collect_intelligence(self) -> List[stix2.base._STIXBase]:
        """Collect intelligence from source. Implemented by subclass."""
        pass


class SimpleProcessingEngine(ProcessingEngine):
    """
    Simple processing: collect all → bundle once → send once.

    Best for small-to-medium datasets (~1K objects).
    Creates a single work.
    """

    def process(self) -> None:
        """Process all intelligence at once."""
        from datetime import datetime, timezone
        
        # Create work
        now = datetime.now(timezone.utc)
        work_id = self.work_manager.initiate_work(
            f"{self.helper.connect_name} @ {now.isoformat()}"
        )
        
        try:
            stix_objects = self.collect_intelligence()
            self.send_bundle(stix_objects, work_id)
            self.work_manager.mark_complete(
                work_id, f"{self.helper.connect_name} completed"
            )
        except Exception as e:
            self.work_manager.mark_failed(work_id, f"Error: {str(e)}")
            raise


class StreamingProcessingEngine(ProcessingEngine):
    """
    Streaming processing: collect chunks → bundle per chunk → send each.

    Best for large datasets (10k+ objects), memory-constrained environments.
    
    Always creates one work per chunk to avoid multiple bundles in a single work.
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        error_handler: ErrorHandler,
        work_manager: "WorkManager",
    ) -> None:
        """Initialize streaming engine.
        
        Args:
            helper: OpenCTI helper
            error_handler: Error handler
            work_manager: Work manager for creating works
        """
        super().__init__(helper, error_handler, work_manager)

    def process(self) -> None:
        """Process intelligence stream in chunks."""
        chunk_count = 0
        for chunk in self.collect_intelligence_stream():
            if not chunk:
                continue

            chunk_count += 1
            chunk_work_id = self.work_manager.initiate_work(
                f"{self.helper.connect_name} - Chunk {chunk_count}"
            )

            try:
                self.send_bundle(chunk, chunk_work_id)
                self.work_manager.mark_complete(
                    chunk_work_id, f"Chunk {chunk_count} processed"
                )
            except Exception as e:
                self.work_manager.mark_failed(chunk_work_id, f"Error: {str(e)}")
                self.error_handler.log_warning(f"Chunk {chunk_count} failed: {e}")
                # Continue with other chunks

            self.error_handler.log_info(
                f"Sent chunk {chunk_count} with {len(chunk)} objects"
            )

    def collect_intelligence_stream(self):
        """
        Stream intelligence as chunks.

        Yields:
            Lists of STIX objects
        """
        raise NotImplementedError

    def collect_intelligence(self) -> List[stix2.base._STIXBase]:
        """Not used in streaming mode."""
        raise NotImplementedError("Use collect_intelligence_stream() instead")


class BatchingProcessingEngine(ProcessingEngine):
    """
    Batching processing: collect all → partition → send each batch.

    Best for medium-large datasets with state tracking per batch.
    Allows state updates and progress tracking between batches.
    
    Supports:
    - Single work mode: All batches use same work_id
    - Multiple work mode: Create work per batch (requires work_manager)
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        error_handler: ErrorHandler,
        work_manager: "WorkManager",
        batch_size: int = 100,
        state_manager: Optional["StateManager"] = None,
        work_per_batch: bool = False,
    ) -> None:
        """Initialize with batch size and optional managers.
        
        Args:
            helper: OpenCTI helper
            error_handler: Error handler
            work_manager: Work manager for creating works
            batch_size: Number of objects per batch
            state_manager: State manager for tracking progress
            work_per_batch: If True, create separate work for each batch
        """
        super().__init__(helper, error_handler, work_manager)
        self.batch_size = batch_size
        self.state_manager = state_manager
        self.work_per_batch = work_per_batch

    def process(self) -> None:
        """Process with batching and progressive state updates."""
        collected_objects = self.collect_intelligence()

        if not collected_objects:
            self.error_handler.log_info("No intelligence collected")
            return

        total_batches = (len(collected_objects) + self.batch_size - 1) // self.batch_size

        if not self.work_per_batch:
            # Single work, single bundle (no sequential bundles in one work)
            now = datetime.now(timezone.utc)
            work_id = self.work_manager.initiate_work(
                f"{self.helper.connect_name} @ {now.isoformat()}"
            )

            try:
                self.send_bundle(collected_objects, work_id)
                if self.state_manager:
                    self.state_manager.set_value("last_batch_number", 1)
                    self.state_manager.set_value(
                        "last_batch_count", len(collected_objects)
                    )
                self.work_manager.mark_complete(
                    work_id, f"{self.helper.connect_name} processed {len(collected_objects)} objects"
                )
            except Exception as e:
                self.work_manager.mark_failed(work_id, f"Error: {str(e)}")
                raise
        else:
            # One work per batch
            total_sent = 0
            for batch_num, i in enumerate(
                range(0, len(collected_objects), self.batch_size), 1
            ):
                batch = collected_objects[i : i + self.batch_size]
                batch_work_id = self.work_manager.initiate_work(
                    f"{self.helper.connect_name} - Batch {batch_num}/{total_batches}"
                )
                
                try:
                    self.send_bundle(batch, batch_work_id)
                    self.work_manager.mark_complete(
                        batch_work_id, f"Batch {batch_num}/{total_batches} processed"
                    )
                except Exception as e:
                    self.work_manager.mark_failed(batch_work_id, f"Error: {str(e)}")
                    self.error_handler.log_warning(f"Batch {batch_num} failed: {e}")
                    # Continue with other batches

                # Update state after each batch if state manager provided
                if self.state_manager:
                    self.state_manager.set_value("last_batch_number", batch_num)
                    self.state_manager.set_value("last_batch_count", len(batch))

                total_sent += len(batch)
                self.error_handler.log_info(
                    f"Sent batch {batch_num}/{total_batches} with {len(batch)} objects"
                )
            
            self.error_handler.log_info(f"Total sent: {total_sent} STIX objects")


class MultiHandlerProcessingEngine(ProcessingEngine):
    """
    Multi-handler processing: orchestrate multiple independent handlers.

    Best for connectors with multiple data sources/scopes.
    Each handler manages its own collection and state.
    
    **NEW: Supports per-handler processing strategy**
    - Handlers can use batching, streaming, or simple processing
    - Set `send_per_handler=True` to send bundles per handler
    - Set `send_per_handler=False` to aggregate all and send once
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        error_handler: ErrorHandler,
        work_manager: "WorkManager",
        handlers: Optional[List[Any]] = None,
        send_per_handler: bool = False,
        work_per_handler: bool = False,
    ) -> None:
        """Initialize with handlers list.
        
        Args:
            helper: OpenCTI helper
            error_handler: Error handler instance
            work_manager: Work manager for creating works
            handlers: List of handler instances
            send_per_handler: If True, send bundle per handler. If False, aggregate all.
            work_per_handler: If True, create separate work for each handler
        """
        super().__init__(helper, error_handler, work_manager)
        self.handlers = handlers or []
        self.send_per_handler = send_per_handler
        self.work_per_handler = work_per_handler

    def process(self) -> None:
        """Process intelligence from multiple handlers."""
        from datetime import datetime, timezone

        if self.send_per_handler and not self.work_per_handler:
            raise ValueError(
                "send_per_handler requires work_per_handler=True to avoid "
                "sending multiple bundles in a single work"
            )
        
        if not self.work_per_handler:
            # Single work for all handlers
            now = datetime.now(timezone.utc)
            work_id = self.work_manager.initiate_work(
                f"{self.helper.connect_name} @ {now.isoformat()}"
            )
            
            try:
                all_objects = []
                for handler in self.handlers:
                    handler_name = handler.__class__.__name__
                    
                    # Handler can have its own processing engine
                    if hasattr(handler, 'processing_engine'):
                        # Handler uses its own strategy - creates its own works
                        self.error_handler.log_info(
                            f"Processing handler {handler_name} with custom engine"
                        )
                        handler.processing_engine.process()
                    else:
                        # Traditional handler: returns STIX objects
                        objects = handler.run(work_id)
                        if objects:
                            if self.send_per_handler:
                                # Send immediately per handler
                                self.send_bundle(objects, work_id)
                                self.error_handler.log_info(
                                    f"Handler {handler_name} sent {len(objects)} objects"
                                )
                            else:
                                # Aggregate for later
                                all_objects.extend(objects)
                                self.error_handler.log_info(
                                    f"Handler {handler_name} collected {len(objects)} objects"
                                )

                # Send aggregated bundle if not sending per handler
                if not self.send_per_handler and all_objects:
                    self.send_bundle(all_objects, work_id)
                
                self.work_manager.mark_complete(
                    work_id, f"{self.helper.connect_name} processed {len(self.handlers)} handlers"
                )
            except Exception as e:
                self.work_manager.mark_failed(work_id, f"Error: {str(e)}")
                raise
        else:
            # One work per handler
            for handler in self.handlers:
                handler_name = handler.__class__.__name__
                handler_work_id = self.work_manager.initiate_work(
                    f"{self.helper.connect_name} - {handler_name}"
                )
                
                try:
                    # Handler can have its own processing engine
                    if hasattr(handler, 'processing_engine'):
                        # Handler uses its own strategy - creates its own works
                        self.error_handler.log_info(
                            f"Processing handler {handler_name} with custom engine"
                        )
                        handler.processing_engine.process()
                        # Note: handler's engine creates its own works
                        self.work_manager.mark_complete(
                            handler_work_id, f"Handler {handler_name} completed"
                        )
                    else:
                        # Traditional handler: returns STIX objects
                        objects = handler.run(handler_work_id)
                        if objects:
                            self.send_bundle(objects, handler_work_id)
                            self.error_handler.log_info(
                                f"Handler {handler_name} sent {len(objects)} objects"
                            )
                        
                        self.work_manager.mark_complete(
                            handler_work_id, f"Handler {handler_name} completed"
                        )
                except Exception as e:
                    self.work_manager.mark_failed(handler_work_id, f"Error: {str(e)}")
                    self.error_handler.log_warning(
                        f"Handler {handler_name} failed: {str(e)}"
                    )
                    # Continue with other handlers on failure

    def collect_intelligence(self) -> List[stix2.base._STIXBase]:
        """Not used in multi-handler mode."""
        raise NotImplementedError("Use handlers instead")


class ConverterFactory:
    """
    Factory for creating converters.

    Responsibilities:
    - Create converter instances
    - Manage converter lifecycle
    """

    @staticmethod
    def create_converter(config: Any, helper: OpenCTIConnectorHelper) -> Any:
        """
        Create a converter instance.

        Override in subclass or provide custom factory.

        Args:
            config: Connector configuration
            helper: OpenCTI connector helper

        Returns:
            Converter instance
        """
        raise NotImplementedError("Subclass must implement create_converter()")
