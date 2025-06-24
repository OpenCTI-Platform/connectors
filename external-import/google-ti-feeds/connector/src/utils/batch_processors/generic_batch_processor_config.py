"""Generic batch processor configuration for any data type with work management.

This module provides a flexible configuration system for creating batch processors
that can work with any data type, batch size, and work management requirements.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Callable, List, Optional


@dataclass
class GenericBatchProcessorConfig:
    """Configuration for a generic batch processor.

    This configuration allows creating batch processors for any data type with
    flexible batch size, work management, and state update handling.
    """

    batch_size: int
    """Number of items to accumulate before processing a batch"""

    work_name_template: str
    """Template for work names (e.g., 'API Import - Batch #{batch_num}')"""

    state_key: str
    """Key used for state updates (e.g., 'next_cursor_start_date')"""

    entity_type: str
    """The type of entity being processed (e.g., 'reports', 'indicators')"""

    display_name: str
    """Human-readable name for logging (e.g., 'threat reports', 'IOCs')"""

    exception_class: type = Exception
    """Exception class to raise on processing errors"""

    display_name_singular: Optional[str] = None
    """Singular form of display name. Auto-generated if not provided"""

    auto_process: bool = True
    """Whether to automatically process batches when they reach batch_size"""

    date_extraction_function: Optional[Callable[[Any], Optional[str]]] = None
    """Function to extract date from an item for state updates"""

    preprocessing_function: Optional[Callable[[List[Any]], List[Any]]] = None
    """Function to preprocess batch before sending to work manager"""

    postprocessing_function: Optional[Callable[[List[Any], str], None]] = None
    """Function to run after successful batch processing (items, work_id)"""

    validation_function: Optional[Callable[[Any], bool]] = None
    """Function to validate individual items before adding to batch"""

    empty_batch_behavior: str = "update_state"
    """Behavior when processing empty batches: 'skip', 'update_state', or 'error'"""

    max_retries: int = 0
    """Maximum number of retries for failed batch processing"""

    retry_delay: float = 1.0
    """Delay in seconds between retries"""

    work_timeout: Optional[float] = None
    """Timeout for work operations in seconds"""

    def __post_init__(self) -> None:
        """Post-initialization to set defaults and validate."""
        if self.batch_size <= 0:
            raise ValueError("batch_size must be greater than 0")

        if self.display_name_singular is None:
            if self.display_name.endswith("s") and len(self.display_name) > 1:
                self.display_name_singular = self.display_name[:-1]
            else:
                self.display_name_singular = self.display_name

        if self.empty_batch_behavior not in ("skip", "update_state", "error"):
            raise ValueError(
                "empty_batch_behavior must be 'skip', 'update_state', or 'error'"
            )

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
            raise ValueError(
                f"Missing required parameter '{missing_param}' for work name template '{self.work_name_template}'"
            ) from e

    def extract_date(self, item: Any) -> Optional[str]:
        """Extract date from an item using the configured function.

        Args:
            item: The item to extract date from

        Returns:
            Date string or None

        """
        if self.date_extraction_function:
            try:
                return self.date_extraction_function(item)
            except Exception:
                return None
        return None

    def validate_item(self, item: Any) -> bool:
        """Validate an item using the configured validation function.

        Args:
            item: The item to validate

        Returns:
            True if valid, False otherwise

        """
        if self.validation_function:
            try:
                return self.validation_function(item)
            except Exception:
                return False
        return True

    def preprocess_batch(self, items: List[Any]) -> List[Any]:
        """Preprocess a batch using the configured function.

        Args:
            items: List of items to preprocess

        Returns:
            Preprocessed items

        """
        if self.preprocessing_function:
            try:
                return self.preprocessing_function(items)
            except Exception as e:
                raise self.exception_class(
                    f"Batch preprocessing failed: {str(e)}"
                ) from e
        return items

    def postprocess_batch(self, items: List[Any], work_id: str) -> None:
        """Run postprocessing after successful batch processing.

        Args:
            items: List of items that were processed
            work_id: ID of the work that was created

        """
        if self.postprocessing_function:
            try:
                self.postprocessing_function(items, work_id)
            except Exception as e:
                raise self.exception_class(
                    f"Batch postprocessing failed: {str(e)}"
                ) from e

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

    def get_current_timestamp(self) -> str:
        """Get current timestamp in ISO format for state updates.

        Returns:
            Current timestamp as ISO string

        """
        return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S+00:00")
