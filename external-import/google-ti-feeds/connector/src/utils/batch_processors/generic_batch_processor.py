"""Generic batch processor for any data type with configurable work management.

This module provides a flexible batch processor that can work with any data type,
handle configurable batch sizes, and provide consistent work management and state updates.
"""

import logging
import time
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from connector.src.utils.batch_processors.generic_batch_processor_config import (
    GenericBatchProcessorConfig,
)

if TYPE_CHECKING:
    from logging import Logger

    from connector.src.octi.work_manager import WorkManager

try:
    from stix2.v21 import _STIXBase21  # type: ignore[import-untyped]
except ImportError:
    _STIXBase21 = None


LOG_PREFIX = "[GenericBatchProcessor]"


class GenericBatchProcessor:
    """Generic batch processor for any data type with flexible work management."""

    def __init__(
        self,
        config: GenericBatchProcessorConfig,
        work_manager: "WorkManager",
        logger: Optional["Logger"] = None,
    ) -> None:
        """Initialize the generic batch processor.

        Args:
            config: Configuration for the batch processor
            work_manager: The work manager object for OpenCTI operations
            logger: Logger for logging messages

        """
        self.config = config
        self._work_manager = work_manager
        self._logger = logger or logging.getLogger(__name__)

        self._current_batch: List[Any] = []
        self._latest_date: Optional[str] = None

        self._total_items_processed = 0
        self._total_batches_processed = 0
        self._total_items_sent = 0

        self._failed_items: List[Any] = []

    def add_item(self, item: Any) -> bool:
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
            self._logger.debug(f"{LOG_PREFIX} Item processing failed, skipping item")
            return False

        if not self.config.validate_item(processed_item):
            self._logger.debug(f"{LOG_PREFIX} Item validation failed, skipping item")
            return False

        item_date = self.config.extract_date(processed_item)
        if item_date and (not self._latest_date or item_date > self._latest_date):
            old_latest = self._latest_date
            self._latest_date = item_date
            self._logger.debug(
                f"{LOG_PREFIX} updated latest_date from '{old_latest}' to '{self._latest_date}'"
            )

        self._current_batch.append(processed_item)
        self._logger.debug(
            f"{LOG_PREFIX} Added item to batch ({len(self._current_batch)}/{self.config.batch_size})"
        )

        if (
            self.config.auto_process
            and len(self._current_batch) >= self.config.batch_size
        ):
            self.process_current_batch()

        return True

    def add_items(self, items: List[Any]) -> int:
        """Add multiple items to batches, processing full batches automatically.

        Args:
            items: List of items to add

        Returns:
            Number of items successfully added

        Raises:
            Configured exception class: If auto-processing fails

        """
        added_count = 0
        self._logger.info(
            f"{LOG_PREFIX} Adding {len(items)} {self.config.display_name} to batch processor"
        )

        for item in items:
            if self.add_item(item):
                added_count += 1

        self._logger.info(
            f"{LOG_PREFIX} Successfully added {added_count}/{len(items)} {self.config.display_name}"
        )
        return added_count

    def process_current_batch(self) -> Optional[str]:
        """Process the current batch and reset for next batch.

        Returns:
            Work ID if batch was processed, None if batch was empty and skipped

        Raises:
            Configured exception class: If batch processing fails

        """
        if not self._current_batch:
            return self._handle_empty_batch()

        batch_items = self._current_batch.copy()
        self._current_batch.clear()

        self._total_batches_processed += 1
        batch_num = self._total_batches_processed

        self._logger.info(
            f"{LOG_PREFIX} Processing batch #{batch_num} with {len(batch_items)} {self.config.display_name} (Total processed: {self._total_items_processed + len(batch_items)})"
        )

        return self._process_batch_with_retries(batch_items, batch_num)

    def flush(self) -> Optional[str]:
        """Process any remaining items in the current batch.

        Returns:
            Work ID if batch was processed, None if no items to process

        Raises:
            Configured exception class: If batch processing fails

        """
        if self._current_batch:
            self._logger.info(
                f"{LOG_PREFIX} Flushing remaining {len(self._current_batch)} {self.config.display_name}"
            )
            return self.process_current_batch()
        else:
            self._logger.debug(f"{LOG_PREFIX} No items to flush")
            return None

    def update_final_state(self) -> None:
        """Update the state with the final latest date after all processing is complete."""
        if self._latest_date:
            self._logger.info(
                f"{LOG_PREFIX} State update: Setting next_cursor_date to {self._latest_date}"
            )
            try:
                self._work_manager.update_state(
                    state_key=self.config.state_key, date_str=self._latest_date
                )
            except Exception as state_err:
                self._logger.error(
                    f"{LOG_PREFIX} Failed to update final state: {str(state_err)}",
                    extra={"error": str(state_err)},
                )
        else:
            current_time = self.config.get_current_timestamp()
            self._logger.info(
                f"{LOG_PREFIX} State update: Setting {self.config.state_key}, to current time {current_time}"
            )
            try:
                self._work_manager.update_state(
                    state_key=self.config.state_key, date_str=current_time
                )
            except Exception as state_err:
                self._logger.error(
                    f"{LOG_PREFIX} Failed to update final state with current time: {str(state_err)}",
                    extra={"error": str(state_err)},
                )

    def get_statistics(self) -> Dict[str, Any]:
        """Get processing statistics.

        Returns:
            Dictionary containing processing statistics

        """
        return {
            "total_items_processed": self._total_items_processed,
            "total_batches_processed": self._total_batches_processed,
            "total_items_sent": self._total_items_sent,
            "current_batch_size": len(self._current_batch),
            "failed_items_count": len(self._failed_items),
            "latest_date": self._latest_date,
            "batch_size_limit": self.config.batch_size,
        }

    def get_current_batch_size(self) -> int:
        """Get the number of items in the current batch.

        Returns:
            Number of items in current batch

        """
        return len(self._current_batch)

    def get_failed_items(self) -> List[Any]:
        """Get list of items that failed processing.

        Returns:
            List of failed items

        """
        return self._failed_items.copy()

    def clear_failed_items(self) -> None:
        """Clear the list of failed items."""
        self._failed_items.clear()

    def set_latest_date(self, date_str: str) -> None:
        """Set the latest date manually.

        Args:
            date_str: The date string in ISO format

        """
        if date_str and (not self._latest_date or date_str > self._latest_date):
            self._latest_date = date_str

    def _handle_empty_batch(self) -> Optional[str]:
        """Handle processing of empty batches based on configuration.

        Returns:
            None (empty batches don't create work)

        Raises:
            Configured exception class: If empty_batch_behavior is 'error'

        """
        if self.config.empty_batch_behavior == "error":
            raise self.config.create_exception("Cannot process empty batch")

        if self.config.empty_batch_behavior == "update_state":
            current_time = self.config.get_current_timestamp()
            self._logger.debug(
                f"{LOG_PREFIX} Updating state with current time for empty batch: {current_time}"
            )
            try:
                self._work_manager.update_state(
                    state_key=self.config.state_key, date_str=current_time
                )
                self._latest_date = current_time
            except Exception as state_err:
                self._logger.warning(
                    f"{LOG_PREFIX} Failed to update state for empty batch: {str(state_err)}"
                )

        self._logger.info(
            f"{LOG_PREFIX} No {self.config.display_name} in batch to process"
        )
        return None

    def _process_batch_with_retries(
        self, batch_items: List[Any], batch_num: int
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

        for attempt in range(self.config.max_retries + 1):
            try:
                if attempt > 0:
                    self._logger.info(
                        f"{LOG_PREFIX} Retrying batch #{batch_num} (attempt {attempt + 1}/{self.config.max_retries + 1})"
                    )
                    time.sleep(self.config.retry_delay)

                return self._process_single_batch(batch_items, batch_num)

            except Exception as e:
                last_exception = e
                if attempt < self.config.max_retries:
                    self._logger.warning(
                        f"{LOG_PREFIX} Batch #{batch_num} failed (attempt {attempt + 1}), will retry: {str(e)}"
                    )
                else:
                    self._logger.error(
                        f"{LOG_PREFIX} Batch #{batch_num} failed after all retries: {str(e)}"
                    )
                    self._failed_items.extend(batch_items)

        raise self.config.create_exception(
            f"Batch #{batch_num} processing failed after {self.config.max_retries + 1} attempts: {str(last_exception)}"
        ) from last_exception

    def _process_single_batch(self, batch_items: List[Any], batch_num: int) -> str:
        """Process a single batch without retries.

        Args:
            batch_items: Items to process
            batch_num: Batch number for logging

        Returns:
            Work ID of the processed batch

        Raises:
            Configured exception class: If batch processing fails

        """
        processed_items = self.config.preprocess_batch(batch_items)

        work_name = self.config.format_work_name(
            batch_num=batch_num,
            entity_type=self.config.entity_type,
        )

        work_id = self._initiate_work(work_name, batch_num, processed_items)

        self._send_bundle(work_id, processed_items, batch_num)

        self._mark_work_for_processing(work_id, batch_num)

        self._total_items_processed += len(batch_items)
        self._total_items_sent += len(processed_items)

        self._update_batch_state()

        self.config.postprocess_batch(processed_items, work_id)

        self._logger.info(
            f"{LOG_PREFIX} Successfully processed batch #{batch_num}. "
            f"Total {self.config.display_name} sent: {self._total_items_sent}"
        )

        return work_id

    def _initiate_work(self, work_name: str, batch_num: int, items: List[Any]) -> str:
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
                f"{LOG_PREFIX} Initiated work '{work_name}' with ID: {work_id}"
            )
            return work_id
        except Exception as work_init_err:
            self._logger.warning(
                f"{LOG_PREFIX} Failed to initiate work for batch #{batch_num}: {str(work_init_err)}"
            )
            raise self.config.create_exception(
                f"Work initiation failed for batch #{batch_num}: {str(work_init_err)}",
                batch_number=batch_num,
                items_count=len(items),
            ) from work_init_err

    def _send_bundle(self, work_id: str, items: List[Any], batch_num: int) -> None:
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
                f"{LOG_PREFIX} Sending bundle with {len(items)} items for batch #{batch_num}"
            )
            self._work_manager.send_bundle(work_id=work_id, bundle=items)
            self._logger.info(f"{LOG_PREFIX} Sent batch #{batch_num} to OpenCTI")
        except Exception as bundle_err:
            self._logger.warning(
                f"{LOG_PREFIX} Failed to send bundle for batch #{batch_num}: {str(bundle_err)}"
            )
            raise self.config.create_exception(
                f"Bundle sending failed for batch #{batch_num}: {str(bundle_err)}",
                work_id=work_id,
                items_count=len(items),
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
                f"{LOG_PREFIX} Marked work {work_id} for processing (batch #{batch_num})"
            )
        except Exception as process_err:
            self._logger.warning(
                f"{LOG_PREFIX} Failed to mark work for processing for batch #{batch_num}: {str(process_err)}"
            )
            raise self.config.create_exception(
                f"Failed to mark work for processing for batch #{batch_num}: {str(process_err)}",
                work_id=work_id,
            ) from process_err

    def _ensure_stix_format(self, item: Any) -> Optional[Any]:
        """Ensure item is in STIX format by checking type and converting if needed.

        Args:
            item: The item to check/convert

        Returns:
            STIX object or None if conversion failed

        """
        if _STIXBase21 is not None and isinstance(item, _STIXBase21):
            self._logger.debug(
                f"{LOG_PREFIX} Item is already a STIX object of type: {type(item).__name__}"
            )
            return item

        if hasattr(item, "to_stix") and callable(item.to_stix):
            try:
                stix_result = item.to_stix()
                self._logger.debug(
                    f"{LOG_PREFIX} Converted {type(item).__name__} to STIX format using to_stix() method"
                )
                return stix_result
            except Exception as e:
                self._logger.warning(
                    f"{LOG_PREFIX} Failed to convert item to STIX using to_stix() method: {str(e)}"
                )
                return None

        if hasattr(item, "to_stix2_object") and callable(item.to_stix2_object):
            try:
                stix_result = item.to_stix2_object()
                self._logger.debug(
                    f"{LOG_PREFIX} Converted {type(item).__name__} to STIX format using to_stix2_object() method"
                )
                return stix_result
            except Exception as e:
                self._logger.warning(
                    f"{LOG_PREFIX} Failed to convert item to STIX using to_stix2_object() method: {str(e)}"
                )
                return None

        self._logger.debug(
            f"{LOG_PREFIX} Item of type {type(item).__name__} passed through without conversion"
        )
        return item

    def _update_batch_state(self) -> None:
        """Update state with the latest date after successful batch processing."""
        if self._latest_date:
            self._logger.debug(
                f"{LOG_PREFIX} Updating state with latest date: {self._latest_date}"
            )
            try:
                self._work_manager.update_state(
                    state_key=self.config.state_key, date_str=self._latest_date
                )
            except Exception as state_err:
                self._logger.warning(
                    f"{LOG_PREFIX} Failed to update state after batch processing: {str(state_err)}"
                )
