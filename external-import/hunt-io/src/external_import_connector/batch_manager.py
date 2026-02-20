"""Batch processing management for the Hunt.IO connector."""

import time
from datetime import datetime, timezone
from typing import List

import stix2
from external_import_connector.constants import (
    LoggingPrefixes,
    ProcessingLimits,
    QueueThresholds,
    RetryableErrors,
    RetryConfig,
    StateKeys,
)
from external_import_connector.exceptions import BatchProcessingError
from external_import_connector.models import C2
from pycti import OpenCTIConnectorHelper


class QueueHealthMonitor:
    """Monitors queue health and determines processing constraints."""

    def __init__(self, helper: OpenCTIConnectorHelper):
        self.helper = helper

    def check_queue_health(self) -> bool:
        """
        Check system health before processing entities.
        Returns False if the system is too overwhelmed to process new entities.
        """
        try:
            connector_info = self.helper.api.connector.ping(
                self.helper.connector.id,
                self.helper.connector_state,
                self.helper.connector_info.all_details,
            )

            if not connector_info:
                self.helper.connector_logger.warning(
                    f"{LoggingPrefixes.QUEUE_MANAGEMENT} Could not retrieve connector info, proceeding with caution"
                )
                return True

            queue_messages = connector_info.get("messages_number", 0)
            queue_size_mb = connector_info.get("queue_messages_size", 0)

            self.helper.connector_logger.info(
                f"{LoggingPrefixes.QUEUE_MANAGEMENT} Current queue status: {queue_messages} messages, "
                f"{queue_size_mb:.1f} MB"
            )

            # Emergency stop - system is overwhelmed
            if (
                queue_messages > QueueThresholds.EMERGENCY_MESSAGE_THRESHOLD
                or queue_size_mb > QueueThresholds.EMERGENCY_SIZE_THRESHOLD_MB
            ):
                self._handle_emergency_stop(queue_messages, queue_size_mb)
                return False

            # Warning level - reduce processing
            elif (
                queue_messages > QueueThresholds.WARNING_MESSAGE_THRESHOLD
                or queue_size_mb > QueueThresholds.WARNING_SIZE_THRESHOLD_MB
            ):
                self._handle_warning_level(queue_messages, queue_size_mb)
                return True

            # Normal operation
            else:
                self._handle_normal_operation()
                return True

        except Exception as e:
            self.helper.connector_logger.error(
                f"{LoggingPrefixes.QUEUE_MANAGEMENT} Error checking queue health: {e}. Proceeding with caution."
            )
            return True  # Fail open - allow processing if we can't check queue

    def _handle_emergency_stop(self, queue_messages: int, queue_size_mb: float) -> None:
        """Handle emergency queue conditions."""
        self.helper.connector_logger.error(
            f"{LoggingPrefixes.QUEUE_MANAGEMENT} *** EMERGENCY STOP *** Queue overwhelmed: "
            f"{queue_messages} messages ({queue_size_mb:.1f} MB). "
            f"Thresholds: {QueueThresholds.EMERGENCY_MESSAGE_THRESHOLD} messages, "
            f"{QueueThresholds.EMERGENCY_SIZE_THRESHOLD_MB} MB. "
            f"Skipping this run to allow queue processing."
        )

        # Store emergency state for monitoring
        current_state = self.helper.get_state() or {}
        current_state[StateKeys.LAST_EMERGENCY_STOP] = datetime.now(
            timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%S")
        current_state[StateKeys.EMERGENCY_QUEUE_SIZE] = queue_messages
        current_state[StateKeys.EMERGENCY_QUEUE_MB] = queue_size_mb
        self.helper.set_state(current_state)

    def _handle_warning_level(self, queue_messages: int, queue_size_mb: float) -> None:
        """Handle warning level queue conditions."""
        self.helper.connector_logger.warning(
            f"{LoggingPrefixes.QUEUE_MANAGEMENT} *** WARNING *** Queue growing large: "
            f"{queue_messages} messages ({queue_size_mb:.1f} MB). "
            f"Will process with reduced batch size."
        )

        # Set reduced processing flag for batch size adjustment
        current_state = self.helper.get_state() or {}
        current_state[StateKeys.QUEUE_WARNING_MODE] = True
        current_state[StateKeys.WARNING_QUEUE_SIZE] = queue_messages
        self.helper.set_state(current_state)

    def _handle_normal_operation(self) -> None:
        """Handle normal queue conditions."""
        self.helper.connector_logger.info(
            f"{LoggingPrefixes.QUEUE_MANAGEMENT} Queue health: GOOD - Normal processing"
        )

        # Clear any warning flags
        current_state = self.helper.get_state() or {}
        if StateKeys.QUEUE_WARNING_MODE in current_state:
            del current_state[StateKeys.QUEUE_WARNING_MODE]
            self.helper.set_state(current_state)

    def get_adaptive_batch_size(self, default_batch_size: int) -> int:
        """Adjust batch size based on current queue health."""
        try:
            current_state = self.helper.get_state() or {}

            if current_state.get(StateKeys.QUEUE_WARNING_MODE, False):
                # Reduce batch size when queue is under pressure
                reduced_size = max(
                    ProcessingLimits.MIN_ADAPTIVE_BATCH_SIZE,
                    default_batch_size // ProcessingLimits.ADAPTIVE_BATCH_DIVISOR,
                )
                self.helper.connector_logger.info(
                    f"{LoggingPrefixes.QUEUE_MANAGEMENT} Reducing batch size from {default_batch_size} to "
                    f"{reduced_size} due to queue pressure"
                )
                return reduced_size

            return default_batch_size

        except Exception as e:
            self.helper.connector_logger.error(
                f"{LoggingPrefixes.QUEUE_MANAGEMENT} Error adjusting batch size: {e}. Using default."
            )
            return default_batch_size


class BundleSender:
    """Handles sending STIX bundles with retry logic."""

    def __init__(self, helper: OpenCTIConnectorHelper):
        self.helper = helper

    def send_bundle(self, stix_objects: List, description: str = "") -> None:
        """Send a STIX bundle with retry logic."""
        if not stix_objects:
            self.helper.connector_logger.warning(
                f"No objects to send for {description}"
            )
            return

        total_objects = len(stix_objects)
        self.helper.connector_logger.info(
            f"Sending bundle: {total_objects} STIX objects {description}"
        )

        for attempt in range(RetryConfig.MAX_RETRIES):
            try:
                stix_bundle = stix2.Bundle(objects=stix_objects, allow_custom=True)

                self.helper.send_stix2_bundle(
                    stix_bundle.serialize(),
                    update=True,
                    cleanup_inconsistent_bundle=True,
                )

                self.helper.connector_logger.info(
                    f"Successfully sent bundle: {total_objects} STIX objects {description}"
                    + (f" (attempt {attempt + 1})" if attempt > 0 else "")
                )
                return  # Success

            except Exception as e:
                if (
                    self._is_retryable_error(e)
                    and attempt < RetryConfig.MAX_RETRIES - 1
                ):
                    delay = RetryConfig.EXPONENTIAL_BASE**attempt
                    self.helper.connector_logger.warning(
                        f"Bundle sending failed (attempt {attempt + 1}/{RetryConfig.MAX_RETRIES}), "
                        f"retrying in {delay}s: {e}"
                    )
                    time.sleep(delay)
                else:
                    error_msg = (
                        f"Failed to send bundle after {attempt + 1} attempts: {e}"
                    )
                    self.helper.connector_logger.error(error_msg)
                    raise BatchProcessingError(error_msg) from e

    def _is_retryable_error(self, error: Exception) -> bool:
        """Check if an error is retryable based on error message."""
        error_msg = str(error).lower()
        return any(keyword in error_msg for keyword in RetryableErrors.KEYWORDS)


class BatchManager:
    """Manages batch processing of entities."""

    def __init__(self, helper: OpenCTIConnectorHelper):
        self.helper = helper
        self.queue_monitor = QueueHealthMonitor(helper)
        self.bundle_sender = BundleSender(helper)

    def check_processing_feasibility(self) -> bool:
        """Check if processing should proceed based on queue health."""
        if not self.queue_monitor.check_queue_health():
            self.helper.connector_logger.warning(
                f"{LoggingPrefixes.QUEUE_MANAGEMENT} Skipping processing due to queue health issues"
            )
            return False
        return True

    def get_optimal_batch_size(self) -> int:
        """Get the optimal batch size based on current system conditions."""
        return self.queue_monitor.get_adaptive_batch_size(
            ProcessingLimits.DEFAULT_BATCH_SIZE
        )

    def apply_emergency_limits(self, entities: List[C2]) -> List[C2]:
        """Apply emergency limits to prevent queue explosion."""
        if len(entities) > ProcessingLimits.EMERGENCY_MAX_ENTITIES:
            original_count = len(entities)
            limited_entities = entities[: ProcessingLimits.EMERGENCY_MAX_ENTITIES]

            self.helper.connector_logger.error(
                f"{LoggingPrefixes.EMERGENCY_CONNECTOR_LIMIT} *** HARD LIMIT *** "
                f"Reduced entities from {original_count} to {ProcessingLimits.EMERGENCY_MAX_ENTITIES} "
                f"to prevent queue explosion"
            )

            return limited_entities

        return entities

    def create_batches(self, entities: List[C2], batch_size: int) -> List[List[C2]]:
        """Split entities into batches of specified size."""
        batches = []
        for i in range(0, len(entities), batch_size):
            batch = entities[i : i + batch_size]
            batches.append(batch)
        return batches

    def send_consolidated_bundle(
        self, all_objects: List, all_relationships: List, entity_count: int
    ) -> None:
        """Send a consolidated bundle with all objects and relationships."""
        if not all_objects and not all_relationships:
            self.helper.connector_logger.warning(
                f"{LoggingPrefixes.PHASE_3} No objects or relationships to send"
            )
            return

        all_stix_objects = all_objects + all_relationships
        description = (
            f"({len(all_objects)} objects + {len(all_relationships)} relationships = "
            f"{len(all_stix_objects)} total STIX objects from {entity_count} entities)"
        )

        self.helper.connector_logger.info(
            f"{LoggingPrefixes.PHASE_3} Sending consolidated bundle: {description}"
        )

        try:
            self.bundle_sender.send_bundle(all_stix_objects, description)
            self.helper.connector_logger.info(
                f"{LoggingPrefixes.PHASE_3} Successfully sent consolidated bundle: "
                f"{len(all_stix_objects)} STIX objects"
            )
        except BatchProcessingError as e:
            self.helper.connector_logger.error(f"{LoggingPrefixes.PHASE_3} {e}")
            raise

    def add_inter_batch_delay(self) -> None:
        """Add a small delay between batches to prevent overwhelming the system."""
        time.sleep(RetryConfig.BATCH_DELAY)
