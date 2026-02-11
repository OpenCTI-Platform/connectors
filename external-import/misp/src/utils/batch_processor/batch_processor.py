"""Batch processor for any data type with configurable work management.

This module provides a flexible processor that can work with any data type,
handle configurable sizes and provide consistent work management.
"""

from typing import TYPE_CHECKING, Any

import stix2
from exceptions import MispWorkProcessingError

if TYPE_CHECKING:
    from custom_typings.protocols import LoggerProtocol
    from utils.work_manager import WorkManager


LOG_PREFIX = "[BatchProcessor]"


class BatchProcessor:
    """Batch processor for any data type with flexible work management."""

    def __init__(
        self,
        work_manager: "WorkManager",
        logger: "LoggerProtocol",
        batch_size: int,
    ) -> None:
        """Initialize the generic batch processor.

        Args:
            config: Configuration for the batch processor
            work_manager: The work manager object for OpenCTI operations
            logger: Logger for logging messages

        """
        self._work_manager = work_manager
        self._logger = logger

        self._current_batch: list[stix2.v21._STIXBase21] = []
        self._latest_date: str | None = None

        self._total_items_processed = 0
        self._total_batches_processed = 0
        self._total_items_sent = 0

        self._failed_items: list[Any] = []

        self.batch_size = batch_size
        self.work_name_template = "MISP - Batch #{batch_num}"
        self.entity_type = "stix_objects"
        self.display_name = "STIX objects"
        self.exception_class = MispWorkProcessingError

    def add_item(self, item: stix2.v21._STIXBase21) -> bool:
        """Add an item to the current batch.

        Args:
            item: The item to add to the batch

        Returns:
            True if item was added, False if validation failed

        Raises:
            Configured exception class: If auto-processing fails

        """
        processed_item = self._ensure_stix_format(item)
        if processed_item is None:
            self._logger.debug(
                "Item processing failed, skipping item",
                {"prefix": LOG_PREFIX},
            )
            return False

        if not self.validate_item(processed_item):
            self._logger.debug(
                "Item validation failed, skipping item",
                {"prefix": LOG_PREFIX},
            )
            return False

        self._current_batch.append(processed_item)
        self._logger.debug(
            "Added item to batch",
            {
                "prefix": LOG_PREFIX,
                "current_size": len(self._current_batch),
                "batch_size": self.batch_size,
            },
        )

        return True

    def add_items(self, items: list[stix2.v21._STIXBase21]) -> int:
        """Add multiple items to batches, processing full batches automatically.

        Args:
            items: list of items to add

        Returns:
            Number of items successfully added

        Raises:
            Configured exception class: If auto-processing fails

        """
        added_count = 0
        self._logger.debug(
            "Adding items to batch processor",
            {
                "prefix": LOG_PREFIX,
                "count": len(items),
                "display_name": self.display_name,
            },
        )

        for item in items:
            if self.add_item(item):
                added_count += 1

        self._logger.debug(
            "Successfully added items",
            {
                "prefix": LOG_PREFIX,
                "added_count": added_count,
                "total_count": len(items),
                "display_name": self.display_name,
            },
        )
        return added_count

    def process_current_batch(self) -> str | None:
        """Process the current batch and reset for next batch.

        Returns:
            Work ID if batch was processed, None if batch was empty and skipped

        Raises:
            Configured exception class: If batch processing fails

        """
        if not self._current_batch:
            self._logger.debug(
                "No items in batch to process",
                {"prefix": LOG_PREFIX, "display_name": self.display_name},
            )
            return None

        batch_items = self._current_batch.copy()
        self._current_batch.clear()

        self._total_batches_processed += 1
        batch_num = self._total_batches_processed

        self._logger.debug(
            "Processing batch",
            {
                "prefix": LOG_PREFIX,
                "batch_num": batch_num,
                "batch_size": len(batch_items),
                "display_name": self.display_name,
                "total_processed": self._total_items_processed + len(batch_items),
            },
        )

        return self._process_batch_with_retries(batch_items, batch_num)

    def flush(self) -> str | None:
        """Process any remaining items in the current batch.

        Returns:
            Work ID if batch was processed, None if no items to process

        Raises:
            Configured exception class: If batch processing fails

        """
        if self._current_batch:
            self._logger.debug(
                "Flushing remaining items",
                {
                    "prefix": LOG_PREFIX,
                    "count": len(self._current_batch),
                    "display_name": self.display_name,
                },
            )
            return self.process_current_batch()
        self._logger.debug("No items to flush", {"prefix": LOG_PREFIX})
        return None

    def get_statistics(self) -> dict[str, Any]:
        """Get processing statistics.

        Returns:
            dictionary containing processing statistics

        """
        return {
            "total_items_processed": self._total_items_processed,
            "total_batches_processed": self._total_batches_processed,
            "total_items_sent": self._total_items_sent,
            "current_batch_size": len(self._current_batch),
            "failed_items_count": len(self._failed_items),
            "latest_date": self._latest_date,
            "batch_size_limit": self.batch_size,
        }

    def get_current_batch_size(self) -> int:
        """Get the number of items in the current batch.

        Returns:
            Number of items in current batch

        """
        return len(self._current_batch)

    def get_failed_items(self) -> list[Any]:
        """Get list of items that failed processing.

        Returns:
            list of failed items

        """
        return self._failed_items.copy()

    def clear_failed_items(self) -> None:
        """Clear the list of failed items."""
        self._failed_items.clear()

    def _process_batch_with_retries(
        self,
        batch_items: list[Any],
        batch_num: int,
    ) -> str:
        """Process a batch with retry logic.

        Args:
            batch_items: Items to process
            batch_num: Batch number for logging

        Returns:
            Work ID of the processed batch

        Raises:
            Configured exception class: If all retries fail

        """
        last_exception = None

        try:
            return self._process_single_batch(batch_items, batch_num)

        except Exception as e:
            last_exception = e
            self._logger.error(
                "Batch failed after all retries",
                {
                    "prefix": LOG_PREFIX,
                    "batch_num": batch_num,
                    "error": str(e),
                },
            )
            self._failed_items.extend(batch_items)

        msg = f"Batch #{batch_num} processing failed"
        raise self.create_exception(msg) from last_exception

    def _process_single_batch(self, batch_items: list[Any], batch_num: int) -> str:
        """Process a single batch without retries.

        Args:
            batch_items: Items to process
            batch_num: Batch number for logging

        Returns:
            Work ID of the processed batch

        Raises:
            Configured exception class: If batch processing fails

        """

        work_name = self.format_work_name(
            batch_num=batch_num,
            entity_type=self.entity_type,
        )

        work_id = self._initiate_work(work_name, batch_num, batch_items)

        self._send_bundle(work_id, batch_items, batch_num)

        self._mark_work_for_processing(work_id, batch_num)

        self._total_items_processed += len(batch_items)
        self._total_items_sent += len(batch_items)

        self.postprocess_batch(batch_items, work_id)

        self._logger.debug(
            f"Successfully processed batch #{batch_num}. Total {self.display_name} sent: {self._total_items_sent}",
            {
                "prefix": LOG_PREFIX,
                "batch_num": batch_num,
                "total_items_sent": self._total_items_sent,
            },
        )

        return work_id

    def _initiate_work(self, work_name: str, batch_num: int, items: list[Any]) -> str:
        """Initiate work in OpenCTI.

        Args:
            work_name: Name for the work
            batch_num: Batch number for error context
            items: Items being processed for error context

        Returns:
            Work ID

        Raises:
            Configured exception class: If work initiation fails

        """
        try:
            work_id = self._work_manager.initiate_work(name=work_name)
            self._logger.debug(
                "Initiated work",
                {
                    "prefix": LOG_PREFIX,
                    "work_name": work_name,
                    "work_id": work_id,
                },
            )
            return work_id
        except Exception as work_init_err:
            self._logger.warning(
                "Failed to initiate work",
                {
                    "prefix": LOG_PREFIX,
                    "batch_num": batch_num,
                    "error": str(work_init_err),
                },
            )
            msg = f"Work initiation failed for batch #{batch_num}: {work_init_err!s}"
            raise self.create_exception(
                msg, batch_number=batch_num, items_count=len(items)
            ) from work_init_err

    def _send_bundle(self, work_id: str, items: list[Any], batch_num: int) -> None:
        """Send bundle to OpenCTI.

        Args:
            work_id: Work ID
            items: Items to send
            batch_num: Batch number for error context

        Raises:
            Configured exception class: If bundle sending fails

        """
        try:
            self._logger.debug(
                "Sending bundle",
                {
                    "prefix": LOG_PREFIX,
                    "items_count": len(items),
                    "batch_num": batch_num,
                },
            )
            self._work_manager.send_bundle(work_id=work_id, bundle=items)
        except Exception as bundle_err:
            self._logger.warning(
                "Failed to send bundle",
                {
                    "prefix": LOG_PREFIX,
                    "batch_num": batch_num,
                    "error": str(bundle_err),
                },
            )
            msg = f"Bundle sending failed for batch #{batch_num}: {bundle_err!s}"
            raise self.create_exception(
                msg, work_id=work_id, items_count=len(items)
            ) from bundle_err

    def _mark_work_for_processing(self, work_id: str, batch_num: int) -> None:
        """Mark work for processing in OpenCTI.

        Args:
            work_id: Work ID
            batch_num: Batch number for error context

        Raises:
            Configured exception class: If marking work fails

        """
        try:
            self._work_manager.work_to_process(work_id=work_id)
            self._logger.debug(
                "Work marked for processing",
                {
                    "prefix": LOG_PREFIX,
                    "work_id": work_id,
                    "batch_num": batch_num,
                },
            )
        except Exception as process_err:
            self._logger.warning(
                "Failed to mark work for processing",
                {
                    "prefix": LOG_PREFIX,
                    "batch_num": batch_num,
                    "error": str(process_err),
                },
            )
            msg = f"Failed to mark work for processing for batch #{batch_num}: {process_err}"
            raise self.create_exception(msg, work_id=work_id) from process_err

    def _ensure_stix_format(self, item: Any) -> Any | None:
        """Ensure item is in STIX format by checking type and converting if needed.

        Args:
            item: The item to check/convert

        Returns:
            STIX object or None if conversion failed

        """
        if isinstance(item, stix2.v21._STIXBase21):
            self._logger.debug(
                "Item is already a STIX object",
                {"prefix": LOG_PREFIX, "item_type": type(item).__name__},
            )
            return item

        if hasattr(item, "to_stix") and callable(item.to_stix):
            try:
                stix_result = item.to_stix()
                self._logger.debug(
                    "Converted to STIX format using to_stix() method",
                    {"prefix": LOG_PREFIX, "item_type": type(item).__name__},
                )
                return stix_result
            except Exception as e:
                self._logger.warning(
                    "Failed to convert item to STIX using to_stix() method",
                    {"prefix": LOG_PREFIX, "error": str(e)},
                )
                return None

        if hasattr(item, "to_stix2_object") and callable(item.to_stix2_object):
            try:
                stix_result = item.to_stix2_object()
                self._logger.debug(
                    "Converted to STIX format using to_stix2_object() method",
                    {"prefix": LOG_PREFIX, "item_type": type(item).__name__},
                )
                return stix_result
            except Exception as e:
                self._logger.warning(
                    "Failed to convert item to STIX using to_stix2_object() method",
                    {"prefix": LOG_PREFIX, "error": str(e)},
                )
                return None

        self._logger.debug(
            "Item passed through without conversion",
            {"prefix": LOG_PREFIX, "item_type": type(item).__name__},
        )
        return item

    def format_work_name(self, batch_num: int, **kwargs: Any) -> str:
        """Format the work name with batch number and optional parameters.

        Args:
            batch_num: The current batch number
            **kwargs: Additional parameters for work name formatting

        Returns:
            Formatted work name

        """
        try:
            return self.work_name_template.format(batch_num=batch_num, **kwargs)
        except KeyError as e:
            missing_param = str(e).strip("'")
            msg = f"Missing required parameter '{missing_param}' for work name template '{self.work_name_template}'"
            raise ValueError(msg) from e

    def validate_item(self, item: Any) -> bool:
        """Validate an item using the configured validation function.

        Args:
            item: The item to validate

        Returns:
            True if valid, False otherwise

        """
        try:
            return self._validate_stix_object(item)
        except Exception:
            return False

    def postprocess_batch(self, items: list[Any], work_id: str) -> None:
        """Run postprocessing after successful batch processing.

        Args:
            items: list of items that were processed
            work_id: ID of the work that was created

        """
        try:
            self._log_batch_completion(items, work_id)
        except Exception as e:
            msg = f"Batch postprocessing failed: {e!s}"
            raise self.exception_class(msg) from e

    def create_exception(self, message: str, **kwargs: Any) -> Any:
        """Create an exception instance with the configured exception class.

        Args:
            message: Error message
            **kwargs: Additional parameters to pass to exception constructor

        Returns:
            Exception instance

        """
        try:
            return self.exception_class(message, **kwargs)
        except TypeError:
            try:
                return self.exception_class(message)
            except TypeError:
                try:
                    return self.exception_class()
                except TypeError:
                    return Exception(message)

    @staticmethod
    def _validate_stix_object(stix_obj: "stix2.v21._STIXBase21") -> bool:
        """Validate STIX object before adding to batch.

        Args:
            stix_obj: STIX object to validate

        Returns:
            True if valid, False otherwise

        """
        return (
            hasattr(stix_obj, "id")
            and hasattr(stix_obj, "type")
            and stix_obj.id is not None
            and stix_obj.type is not None
        )

    def _log_batch_completion(
        self, stix_objects: list["stix2.v21._STIXBase21"], work_id: str
    ) -> None:
        """Log successful batch completion with object type breakdown.

        Args:
            stix_objects: list of processed STIX objects
            work_id: Work ID that was created

        """
        object_types: dict[str, int] = {}
        total_count = 0

        for obj in stix_objects:
            total_count += 1

            if total_count <= 2500:
                if hasattr(obj, "type"):
                    obj_type = obj.type
                elif hasattr(obj, "get"):
                    obj_type = obj.get("type", "unknown")
                else:
                    obj_type = "unknown"
                object_types[obj_type] = object_types.get(obj_type, 0) + 1

        if total_count > 2500:
            type_summary = (
                ", ".join(
                    [
                        f"{obj_type}: {count}"
                        for obj_type, count in object_types.items()
                    ],
                )
                + " (first 2500 objects)"
            )
        else:
            type_summary = ", ".join(
                [f"{obj_type}: {count}" for obj_type, count in object_types.items()],
            )

        self._logger.info(
            "Batch completed successfully",
            {
                "prefix": LOG_PREFIX,
                "work_id": work_id,
                "total_count": total_count,
                "type_summary": type_summary,
            },
        )
