"""Test module for GenericBatchProcessor functionality."""

from datetime import UTC, datetime
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import MagicMock

import pytest
from connector.src.utils.batch_processors.generic_batch_processor import (
    GenericBatchProcessor,
)
from connector.src.utils.batch_processors.generic_batch_processor_config import (
    GenericBatchProcessorConfig,
)

# =====================
# Test Data Models
# =====================


class MockSTIXObject:
    """Mock STIX object for testing."""

    def __init__(self, id: str, name: str, modified: Optional[str] = None) -> None:
        """Initialize a MockSTIXObject."""
        self.id = id
        self.name = name
        self.type = "test-object"
        self.modified = modified or datetime.now(UTC).strftime(
            "%Y-%m-%dT%H:%M:%S+00:00"
        )


class MockMapper:
    """Mock mapper that can convert to STIX."""

    def __init__(self, id: str, name: str, modified: Optional[str] = None) -> None:
        """Initialize a MockMapper."""
        self.id = id
        self.name = name
        self.modified = modified

    def to_stix(self) -> MockSTIXObject:
        """Convert to STIX object."""
        return MockSTIXObject(self.id, self.name, self.modified)


class MockWorkManager:
    """Mock work manager for testing."""

    def __init__(self) -> None:
        """Initialize a MockWorkManager."""
        self.initiate_work = MagicMock(return_value="work-123")
        self.send_bundle = MagicMock()
        self.work_to_process = MagicMock()
        self.update_state = MagicMock()


# =====================
# Test Exceptions
# =====================


class BatchProcessingError(Exception):
    """Custom exception for batch processing."""

    def __init__(
        self,
        message: str,
        batch_number: Optional[int] = None,
        work_id: Optional[str] = None,
    ) -> None:
        """Initialize a BatchProcessingError."""
        super().__init__(message)
        self.batch_number = batch_number
        self.work_id = work_id


class SimpleError(Exception):
    """Simple exception for testing."""

    pass


# =====================
# Fixtures
# =====================


@pytest.fixture
def mock_work_manager() -> MockWorkManager:
    """Fixture for mocked work manager."""
    return MockWorkManager()


@pytest.fixture
def mock_logger() -> MagicMock:
    """Fixture for mocked logger."""
    return MagicMock()


@pytest.fixture
def basic_config() -> GenericBatchProcessorConfig:
    """Fixture for basic batch processor configuration."""
    return GenericBatchProcessorConfig(
        batch_size=3,
        work_name_template="Test Batch - #{batch_num}",
        state_key="test_cursor",
        entity_type="test_objects",
        display_name="test objects",
    )


@pytest.fixture
def validation_config() -> GenericBatchProcessorConfig:
    """Fixture for configuration with validation function."""

    def validate_item(item: Any) -> bool:
        return hasattr(item, "id") and hasattr(item, "name")

    return GenericBatchProcessorConfig(
        batch_size=2,
        work_name_template="Validated Batch - #{batch_num}",
        state_key="validated_cursor",
        entity_type="validated_objects",
        display_name="validated objects",
        validation_function=validate_item,
        auto_process=False,
    )


@pytest.fixture
def date_extraction_config() -> GenericBatchProcessorConfig:
    """Fixture for configuration with date extraction function."""

    def extract_date(item: Any) -> Optional[str]:
        if hasattr(item, "modified"):
            return str(item.modified)
        return None

    return GenericBatchProcessorConfig(
        batch_size=2,
        work_name_template="Dated Batch - #{batch_num}",
        state_key="dated_cursor",
        entity_type="dated_objects",
        display_name="dated objects",
        date_extraction_function=extract_date,
    )


@pytest.fixture
def preprocessing_config() -> GenericBatchProcessorConfig:
    """Fixture for configuration with preprocessing function."""

    def preprocess_batch(items: List[Any]) -> List[Any]:
        for item in items:
            item.preprocessed = True
        return items

    def postprocess_batch(items: List[Any], work_id: str) -> None:
        for item in items:
            item.postprocessed = work_id

    return GenericBatchProcessorConfig(
        batch_size=2,
        work_name_template="Processed Batch - #{batch_num}",
        state_key="processed_cursor",
        entity_type="processed_objects",
        display_name="processed objects",
        preprocessing_function=preprocess_batch,
        postprocessing_function=postprocess_batch,
        auto_process=False,
    )


@pytest.fixture
def retry_config() -> GenericBatchProcessorConfig:
    """Fixture for configuration with retry settings."""
    return GenericBatchProcessorConfig(
        batch_size=2,
        work_name_template="Retry Batch - #{batch_num}",
        state_key="retry_cursor",
        entity_type="retry_objects",
        display_name="retry objects",
        exception_class=BatchProcessingError,
        max_retries=2,
        retry_delay=0.1,
        auto_process=False,
    )


@pytest.fixture
def manual_config() -> GenericBatchProcessorConfig:
    """Fixture for configuration with manual processing."""
    return GenericBatchProcessorConfig(
        batch_size=3,
        work_name_template="Manual Batch - #{batch_num}",
        state_key="manual_cursor",
        entity_type="manual_objects",
        display_name="manual objects",
        auto_process=False,
    )


@pytest.fixture
def stix_conversion_config() -> GenericBatchProcessorConfig:
    """Fixture for configuration to test STIX object conversion."""
    return GenericBatchProcessorConfig(
        batch_size=2,
        work_name_template="STIX Batch - #{batch_num}",
        state_key="stix_cursor",
        entity_type="stix_objects",
        display_name="STIX objects",
        auto_process=False,
    )


@pytest.fixture
def basic_processor(
    basic_config: GenericBatchProcessorConfig, mock_work_manager: Any, mock_logger: Any
) -> GenericBatchProcessor:
    """Fixture for basic batch processor."""
    return GenericBatchProcessor(
        config=basic_config,
        work_manager=mock_work_manager,
        logger=mock_logger,
    )


@pytest.fixture
def validation_processor(
    validation_config: GenericBatchProcessorConfig,
    mock_work_manager: Any,
    mock_logger: Any,
) -> GenericBatchProcessor:
    """Fixture for validation batch processor."""
    return GenericBatchProcessor(
        config=validation_config,
        work_manager=mock_work_manager,
        logger=mock_logger,
    )


@pytest.fixture
def date_extraction_processor(
    date_extraction_config: GenericBatchProcessorConfig,
    mock_work_manager: Any,
    mock_logger: Any,
) -> GenericBatchProcessor:
    """Fixture for batch processor with date extraction."""
    return GenericBatchProcessor(
        config=date_extraction_config,
        work_manager=mock_work_manager,
        logger=mock_logger,
    )


@pytest.fixture
def stix_conversion_processor(
    stix_conversion_config: GenericBatchProcessorConfig,
    mock_work_manager: Any,
    mock_logger: Any,
) -> GenericBatchProcessor:
    """Fixture for batch processor with STIX conversion handling."""
    return GenericBatchProcessor(
        config=stix_conversion_config,
        work_manager=mock_work_manager,
        logger=mock_logger,
    )


# =====================
# Test Cases
# =====================

# Scenario: Successful single item addition and auto-processing


def test_add_single_item_success(basic_processor: GenericBatchProcessor) -> None:
    """Test adding a single item successfully."""
    # Given: A basic processor and a valid item
    item = MockSTIXObject("test-001", "Test Object")

    # When: A single item is added
    result, exception = _when_item_added(basic_processor, item)

    # Then: The item should be added successfully without triggering batch processing
    _then_item_added_successfully(result, exception)
    _then_current_batch_size_is(basic_processor, 1)


def test_add_item_triggers_auto_processing(
    basic_processor: GenericBatchProcessor, mock_work_manager: Any
) -> None:
    """Test that adding items triggers auto-processing when batch size is reached."""
    # Given: A basic processor with batch size 3
    items = [
        MockSTIXObject("test-001", "Object 1"),
        MockSTIXObject("test-002", "Object 2"),
        MockSTIXObject("test-003", "Object 3"),
    ]

    # When: Items are added until batch size is reached
    for item in items:
        _when_item_added(basic_processor, item)

    # Then: Batch processing should be triggered automatically
    _then_work_initiated(mock_work_manager, 1)
    _then_bundle_sent(mock_work_manager, 1)
    _then_work_marked_for_processing(mock_work_manager, 1)
    _then_current_batch_is_empty(basic_processor)


def test_add_item_with_validation_success(
    validation_processor: GenericBatchProcessor,
) -> None:
    """Test adding items with successful validation."""
    # Given: A validation processor and valid items
    valid_item = MockSTIXObject("valid-001", "Valid Object")

    # When: A valid item is added
    result, exception = _when_item_added(validation_processor, valid_item)

    # Then: The item should be added successfully
    _then_item_added_successfully(result, exception)
    _then_current_batch_size_is(validation_processor, 1)


def test_add_item_with_validation_failure(
    validation_processor: GenericBatchProcessor,
) -> None:
    """Test adding items with validation failure."""
    # Given: A validation processor and invalid item
    invalid_item = {"invalid": "data"}  # Missing required attributes

    # When: An invalid item is added
    result, exception = _when_item_added(validation_processor, invalid_item)

    # Then: The item should be rejected and not added
    _then_item_validation_failed(result, exception)
    _then_current_batch_is_empty(validation_processor)


def test_add_item_with_date_extraction(
    date_extraction_processor: GenericBatchProcessor,
) -> None:
    """Test adding items with date extraction."""
    # Given: A date extraction processor and items with dates
    item1 = MockSTIXObject("dated-001", "Object 1", "2023-01-01T10:00:00+00:00")
    item2 = MockSTIXObject("dated-002", "Object 2", "2023-01-02T10:00:00+00:00")

    # When: Items with dates are added
    _when_item_added(date_extraction_processor, item1)
    _when_item_added(date_extraction_processor, item2)

    # Then: The latest date should be tracked
    _then_latest_date_tracked(date_extraction_processor, "2023-01-02T10:00:00+00:00")


# Scenario: Multiple item addition


def test_add_multiple_items_success(basic_processor: GenericBatchProcessor) -> None:
    """Test adding multiple items successfully."""
    # Given: A basic processor and multiple items
    items = [
        MockSTIXObject("multi-001", "Object 1"),
        MockSTIXObject("multi-002", "Object 2"),
    ]

    # When: Multiple items are added
    added_count, exception = _when_multiple_items_added(basic_processor, items)

    # Then: All items should be added successfully
    _then_multiple_items_added_successfully(added_count, exception, 2)
    _then_current_batch_size_is(basic_processor, 2)


def test_add_multiple_items_with_auto_processing(
    basic_processor: GenericBatchProcessor, mock_work_manager: Any
) -> None:
    """Test adding multiple items that trigger auto-processing."""
    # Given: A basic processor with batch size 3 and more items than batch size
    items = [
        MockSTIXObject("auto-001", "Object 1"),
        MockSTIXObject("auto-002", "Object 2"),
        MockSTIXObject("auto-003", "Object 3"),
        MockSTIXObject("auto-004", "Object 4"),
        MockSTIXObject("auto-005", "Object 5"),
    ]

    # When: Multiple items are added
    added_count, exception = _when_multiple_items_added(basic_processor, items)

    # Then: Items should be processed in batches and remainder should be in current batch
    _then_multiple_items_added_successfully(added_count, exception, 5)
    _then_work_initiated(mock_work_manager, 1)  # One batch processed
    _then_current_batch_size_is(basic_processor, 2)  # Two items remaining


def test_add_multiple_items_with_validation_mixed(
    validation_processor: GenericBatchProcessor,
) -> None:
    """Test adding multiple items with mixed validation results."""
    # Given: A validation processor and mixed items (valid and invalid)
    items = [
        MockSTIXObject("valid-001", "Valid Object"),
        {"invalid": "data"},  # Invalid item
        MockSTIXObject("valid-002", "Another Valid Object"),
    ]

    # When: Mixed items are added
    added_count, exception = _when_multiple_items_added(validation_processor, items)

    # Then: Only valid items should be added
    _then_multiple_items_partial_success(added_count, exception, 2)
    _then_current_batch_size_is(validation_processor, 2)


# Scenario: Manual batch processing


def test_process_current_batch_success(
    basic_processor: GenericBatchProcessor, mock_work_manager: Any
) -> None:
    """Test manually processing the current batch successfully."""
    # Given: A basic processor with items in current batch
    items = [
        MockSTIXObject("manual-001", "Object 1"),
        MockSTIXObject("manual-002", "Object 2"),
    ]
    for item in items:
        basic_processor.add_item(item)

    # When: The current batch is processed manually
    work_id, exception = _when_current_batch_processed(basic_processor)

    # Then: The batch should be processed successfully
    _then_batch_processed_successfully(work_id, exception)
    _then_work_initiated(mock_work_manager, 1)
    _then_bundle_sent(mock_work_manager, 1)
    _then_current_batch_is_empty(basic_processor)


def test_process_current_batch_empty(basic_processor: GenericBatchProcessor) -> None:
    """Test processing empty batch."""
    # Given: A basic processor with empty batch

    # When: The empty batch is processed
    work_id, exception = _when_current_batch_processed(basic_processor)

    # Then: Processing should handle empty batch gracefully
    _then_empty_batch_processed(work_id, exception)


def test_process_current_batch_with_preprocessing(
    preprocessing_config: GenericBatchProcessorConfig,
    mock_work_manager: Any,
    mock_logger: Any,
) -> None:
    """Test batch processing with preprocessing and postprocessing."""
    # Given: A processor with preprocessing/postprocessing and items
    processor = GenericBatchProcessor(
        preprocessing_config, mock_work_manager, mock_logger
    )
    items = [
        MockSTIXObject("preprocess-001", "Object 1"),
        MockSTIXObject("preprocess-002", "Object 2"),
    ]
    for item in items:
        processor.add_item(item)

    # When: The batch is processed
    work_id, exception = _when_current_batch_processed(processor)

    # Then: Preprocessing and postprocessing should be applied
    _then_batch_processed_successfully(work_id, exception)
    _then_items_were_preprocessed(items)


def test_process_current_batch_with_retry_success(
    retry_config: GenericBatchProcessorConfig, mock_work_manager: Any, mock_logger: Any
) -> None:
    """Test batch processing with retry logic success on first attempt."""
    # Given: A retry processor and items
    processor = GenericBatchProcessor(retry_config, mock_work_manager, mock_logger)
    items = [
        MockSTIXObject("retry-001", "Object 1"),
        MockSTIXObject("retry-002", "Object 2"),
    ]
    for item in items:
        processor.add_item(item)

    # When: The batch is processed
    work_id, exception = _when_current_batch_processed(processor)

    # Then: Processing should succeed on first attempt
    _then_batch_processed_successfully(work_id, exception)
    _then_work_initiated(mock_work_manager, 1)


def test_process_current_batch_with_retry_eventual_success(
    retry_config: GenericBatchProcessorConfig, mock_work_manager: Any, mock_logger: Any
) -> None:
    """Test batch processing with retry logic eventual success."""
    # Given: A retry processor with work manager that fails initially
    mock_work_manager.initiate_work.side_effect = [
        Exception("First failure"),
        Exception("Second failure"),
        "work-123",
    ]

    processor = GenericBatchProcessor(retry_config, mock_work_manager, mock_logger)
    items = [MockSTIXObject("retry-001", "Object 1")]
    for item in items:
        processor.add_item(item)

    # When: The batch is processed with retries
    work_id, exception = _when_current_batch_processed(processor)

    # Then: Processing should eventually succeed after retries
    _then_batch_processed_successfully(work_id, exception)
    _then_work_initiated_with_retries(mock_work_manager, 3)


def test_process_current_batch_with_retry_exhausted(
    retry_config: GenericBatchProcessorConfig, mock_work_manager: Any, mock_logger: Any
) -> None:
    """Test batch processing with retry logic exhausted."""
    # Given: A retry processor with work manager that always fails
    mock_work_manager.initiate_work.side_effect = Exception("Persistent failure")

    processor = GenericBatchProcessor(retry_config, mock_work_manager, mock_logger)
    items = [MockSTIXObject("retry-fail-001", "Object 1")]
    for item in items:
        processor.add_item(item)

    # When: The batch is processed with failing retries
    work_id, exception = _when_current_batch_processed(processor)

    # Then: Processing should fail after exhausting retries
    _then_batch_processing_failed_after_retries(work_id, exception)
    _then_failed_items_tracked(processor, 1)


# Scenario: Flush operations


def test_flush_with_items(
    basic_processor: GenericBatchProcessor, mock_work_manager: Any
) -> None:
    """Test flushing when there are items in current batch."""
    # Given: A basic processor with items in current batch
    items = [
        MockSTIXObject("flush-001", "Object 1"),
        MockSTIXObject("flush-002", "Object 2"),
    ]
    for item in items:
        basic_processor.add_item(item)

    # When: Flush is called
    work_id, exception = _when_flush_called(basic_processor)

    # Then: Items should be processed and batch should be empty
    _then_batch_processed_successfully(work_id, exception)
    _then_work_initiated(mock_work_manager, 1)
    _then_current_batch_is_empty(basic_processor)


def test_flush_empty_batch(basic_processor: GenericBatchProcessor) -> None:
    """Test flushing when current batch is empty."""
    # Given: A basic processor with empty batch

    # When: Flush is called
    work_id, exception = _when_flush_called(basic_processor)

    # Then: Flush should handle empty batch gracefully
    _then_flush_empty_batch(work_id, exception)


# Scenario: State management


def test_update_final_state_with_tracked_date(
    date_extraction_processor: GenericBatchProcessor, mock_work_manager: Any
) -> None:
    """Test updating final state with tracked date."""
    # Given: A date extraction processor with items that have dates
    item = MockSTIXObject("state-001", "Object 1", "2023-01-01T10:00:00+00:00")
    date_extraction_processor.add_item(item)

    # When: Final state is updated
    _when_final_state_updated(date_extraction_processor)

    # Then: State should be updated with the latest tracked date
    _then_state_updated_with_date(mock_work_manager, "2023-01-01T10:00:00+00:00")


def test_update_final_state_without_tracked_date(
    basic_processor: GenericBatchProcessor, mock_work_manager: Any
) -> None:
    """Test updating final state without tracked date."""
    # Given: A basic processor without date tracking

    # When: Final state is updated
    _when_final_state_updated(basic_processor)

    # Then: State should be updated with current time
    _then_state_updated_with_current_time(mock_work_manager)


def test_set_latest_date_manually(basic_processor: GenericBatchProcessor) -> None:
    """Test manually setting the latest date."""
    # Given: A basic processor
    test_date = "2023-01-01T10:00:00+00:00"

    # When: Latest date is set manually
    _when_latest_date_set(basic_processor, test_date)

    # Then: The latest date should be updated
    _then_latest_date_tracked(basic_processor, test_date)


def test_set_latest_date_only_updates_if_newer(
    basic_processor: GenericBatchProcessor,
) -> None:
    """Test that latest date only updates if newer."""
    # Given: A basic processor with an existing latest date
    older_date = "2023-01-01T10:00:00+00:00"
    newer_date = "2023-01-02T10:00:00+00:00"
    basic_processor.set_latest_date(newer_date)

    # When: An older date is set
    _when_latest_date_set(basic_processor, older_date)

    # Then: The latest date should remain the newer date
    _then_latest_date_tracked(basic_processor, newer_date)


# Scenario: Statistics and tracking


def test_get_statistics_initial(basic_processor: GenericBatchProcessor) -> None:
    """Test getting initial statistics."""
    # Given: A basic processor with no activity

    # When: Statistics are retrieved
    stats = _when_statistics_retrieved(basic_processor)

    # Then: Initial statistics should be zero
    _then_statistics_are_initial(stats)


def test_get_statistics_after_processing(
    basic_processor: GenericBatchProcessor, mock_work_manager: Any
) -> None:
    """Test getting statistics after processing."""
    # Given: A basic processor with processed items
    items = [
        MockSTIXObject("stats-001", "Object 1"),
        MockSTIXObject("stats-002", "Object 2"),
        MockSTIXObject("stats-003", "Object 3"),
    ]
    for item in items:
        basic_processor.add_item(item)

    # When: Statistics are retrieved
    stats = _when_statistics_retrieved(basic_processor)

    # Then: Statistics should reflect processing activity
    _then_statistics_show_processing(stats, 3, 1, 3)


def test_get_current_batch_size(basic_processor: GenericBatchProcessor) -> None:
    """Test getting current batch size."""
    # Given: A basic processor with items added
    items = [
        MockSTIXObject("size-001", "Object 1"),
        MockSTIXObject("size-002", "Object 2"),
    ]
    for item in items:
        basic_processor.add_item(item)

    # When: Current batch size is retrieved
    batch_size = _when_current_batch_size_retrieved(basic_processor)

    # Then: Correct batch size should be returned
    _then_current_batch_size_correct(batch_size, 2)


def test_get_failed_items(
    retry_config: GenericBatchProcessorConfig, mock_work_manager: Any, mock_logger: Any
) -> None:
    """Test getting failed items after processing failures."""
    # Given: A retry processor that will fail
    mock_work_manager.initiate_work.side_effect = Exception("Persistent failure")

    processor = GenericBatchProcessor(retry_config, mock_work_manager, mock_logger)
    items = [MockSTIXObject("fail-001", "Object 1")]
    for item in items:
        processor.add_item(item)

    with pytest.raises(Exception):  # noqa: B017
        processor.process_current_batch()

    # When: Failed items are retrieved
    failed_items = _when_failed_items_retrieved(processor)

    # Then: Failed items should be tracked
    _then_failed_items_correct(failed_items, 1)


def test_clear_failed_items(
    retry_config: GenericBatchProcessorConfig, mock_work_manager: Any, mock_logger: Any
) -> None:
    """Test clearing failed items."""
    # Given: A retry processor with failed items
    mock_work_manager.initiate_work.side_effect = Exception("Failure")

    processor = GenericBatchProcessor(retry_config, mock_work_manager, mock_logger)
    items = [MockSTIXObject("clear-001", "Object 1")]
    for item in items:
        processor.add_item(item)

    with pytest.raises(Exception):  # noqa: B017
        processor.process_current_batch()

    # When: Failed items are cleared
    _when_failed_items_cleared(processor)

    # Then: Failed items list should be empty
    _then_failed_items_empty(processor)


# Scenario: Manual processing control


def test_manual_processing_control(
    manual_config: GenericBatchProcessorConfig, mock_work_manager: Any, mock_logger: Any
) -> None:
    """Test manual processing control with auto_process=False."""
    # Given: A manual processor with auto-processing disabled
    processor = GenericBatchProcessor(manual_config, mock_work_manager, mock_logger)
    items = [
        MockSTIXObject("manual-001", "Object 1"),
        MockSTIXObject("manual-002", "Object 2"),
        MockSTIXObject("manual-003", "Object 3"),
        MockSTIXObject("manual-004", "Object 4"),
    ]

    # When: Items are added beyond batch size
    for item in items:
        processor.add_item(item)

    # Then: No auto-processing should occur
    _then_no_work_initiated(mock_work_manager)
    _then_current_batch_size_is(processor, 4)


def test_add_stix_object_directly(
    stix_conversion_processor: GenericBatchProcessor,
) -> None:
    """Test adding STIX objects directly to batch processor."""
    # Given: A processor and a STIX object
    stix_obj = MockSTIXObject("stix-001", "Direct STIX Object")

    # When: STIX object is added
    result, exception = _when_item_added(stix_conversion_processor, stix_obj)

    # Then: STIX object should be added successfully
    _then_item_added_successfully(result, exception)
    _then_current_batch_size_is(stix_conversion_processor, 1)


def test_add_mapper_object_converts_to_stix(
    stix_conversion_processor: GenericBatchProcessor,
) -> None:
    """Test adding a mapper object that gets converted to STIX."""
    # Given: A processor and a mapper object
    mapper_obj = MockMapper("mapper-001", "Mapper Object")

    # When: Mapper object is added
    result, exception = _when_item_added(stix_conversion_processor, mapper_obj)

    # Then: Mapper should be converted to STIX and added successfully
    _then_item_added_successfully(result, exception)
    _then_current_batch_size_is(stix_conversion_processor, 1)


def test_add_stix_dict_object(stix_conversion_processor: GenericBatchProcessor) -> None:
    """Test adding a STIX dictionary object."""
    # Given: A processor and a STIX-like dictionary
    stix_dict = {
        "id": "dict-001",
        "type": "test-object",
        "name": "Dictionary STIX Object",
    }

    # When: STIX dictionary is added
    result, exception = _when_item_added(stix_conversion_processor, stix_dict)

    # Then: STIX dictionary should be added successfully
    _then_item_added_successfully(result, exception)
    _then_current_batch_size_is(stix_conversion_processor, 1)


def test_add_mapper_conversion_failure(
    stix_conversion_processor: GenericBatchProcessor,
) -> None:
    """Test handling mapper conversion failures."""

    # Given: A processor and a mapper that fails conversion
    class FailingMapper:
        def __init__(self, id: str):
            """Initialize the failing mapper."""
            self.id = id

        def to_stix(self) -> None:
            raise Exception("Conversion failed")

    failing_mapper = FailingMapper("fail-001")

    # When: Failing mapper is added
    result, exception = _when_item_added(stix_conversion_processor, failing_mapper)

    # Then: Item should fail to be added
    _then_item_validation_failed(result, exception)
    _then_current_batch_size_is(stix_conversion_processor, 0)


def test_add_mixed_stix_and_mapper_objects(
    stix_conversion_processor: GenericBatchProcessor,
) -> None:
    """Test adding a mix of STIX objects and mappers."""
    # Given: A processor and mixed object types
    items = [
        MockSTIXObject("stix-001", "Direct STIX"),
        MockMapper("mapper-001", "Mapper Object"),
        {"id": "dict-001", "type": "test", "name": "Dict STIX"},
        MockMapper("mapper-002", "Another Mapper"),
    ]

    # When: Mixed items are added
    added_count, exception = _when_multiple_items_added(
        stix_conversion_processor, items
    )

    # Then: All items should be added successfully
    _then_multiple_items_added_successfully(added_count, exception, 4)
    _then_current_batch_size_is(stix_conversion_processor, 4)


def test_process_batch_with_converted_objects(
    stix_conversion_processor: GenericBatchProcessor, mock_work_manager: Any
) -> None:
    """Test processing batch containing converted objects."""
    # Given: A processor with mixed objects
    items = [
        MockMapper("mapper-001", "Converted Object 1"),
        MockSTIXObject("stix-001", "Direct Object 1"),
    ]

    for item in items:
        stix_conversion_processor.add_item(item)

    # When: Batch is processed
    work_id, exception = _when_current_batch_processed(stix_conversion_processor)

    # Then: Batch should be processed successfully
    _then_batch_processed_successfully(work_id, exception)
    _then_work_initiated(mock_work_manager, 1)
    _then_bundle_sent(mock_work_manager, 1)


def test_ensure_stix_format_with_base_mapper(
    stix_conversion_processor: GenericBatchProcessor,
) -> None:
    """Test _ensure_stix_format method with BaseMapper instances."""
    # Given: A processor and items to test
    stix_obj = MockSTIXObject("test-001", "STIX Object")
    mapper_obj = MockMapper("test-002", "Mapper Object")
    dict_obj = {"id": "test-003", "type": "test", "name": "Dict Object"}
    plain_obj = {"data": "plain object"}

    # When: Items are processed through _ensure_stix_format
    result1 = stix_conversion_processor._ensure_stix_format(stix_obj)
    result2 = stix_conversion_processor._ensure_stix_format(mapper_obj)
    result3 = stix_conversion_processor._ensure_stix_format(dict_obj)
    result4 = stix_conversion_processor._ensure_stix_format(plain_obj)

    # Then: Results should be appropriate for each type
    assert result1 == stix_obj  # noqa: S101
    assert isinstance(result2, MockSTIXObject)  # noqa: S101
    assert result3 == dict_obj  # noqa: S101
    assert result4 == plain_obj  # noqa: S101


# =====================
# GWT Helper Functions
# =====================

# --- WHEN: Execute the system under test ---


def _when_item_added(
    processor: GenericBatchProcessor, item: Any
) -> Tuple[Optional[Any], Optional[Exception]]:
    """Add an item and capture result and exception."""
    try:
        result = processor.add_item(item)
        return result, None
    except Exception as e:
        return None, e


def _when_multiple_items_added(
    processor: GenericBatchProcessor, items: List[Any]
) -> Tuple[Optional[Any], Optional[Exception]]:
    """Add multiple items and capture result and exception."""
    try:
        result = processor.add_items(items)
        return result, None
    except Exception as e:
        return None, e


def _when_current_batch_processed(
    processor: GenericBatchProcessor,
) -> Tuple[Optional[Any], Optional[Exception]]:
    """Process current batch and capture result and exception."""
    try:
        result = processor.process_current_batch()
        return result, None
    except Exception as e:
        return None, e


def _when_flush_called(
    processor: GenericBatchProcessor,
) -> Tuple[Optional[Any], Optional[Exception]]:
    """Call flush and capture result and exception."""
    try:
        result = processor.flush()
        return result, None
    except Exception as e:
        return None, e


def _when_final_state_updated(processor: GenericBatchProcessor) -> None:
    """Update final state."""
    processor.update_final_state()


def _when_latest_date_set(processor: GenericBatchProcessor, date_str: str) -> None:
    """Set latest date manually."""
    processor.set_latest_date(date_str)


def _when_statistics_retrieved(processor: GenericBatchProcessor) -> Dict[str, Any]:
    """Retrieve statistics from processor."""
    return processor.get_statistics()


def _when_current_batch_size_retrieved(processor: GenericBatchProcessor) -> int:
    """Retrieve current batch size."""
    return processor.get_current_batch_size()


def _when_failed_items_retrieved(processor: GenericBatchProcessor) -> List[Any]:
    """Retrieve failed items."""
    return processor.get_failed_items()


def _when_failed_items_cleared(processor: GenericBatchProcessor) -> None:
    """Clear failed items."""
    processor.clear_failed_items()


# --- THEN: Verify the expected outcomes ---


def _then_item_added_successfully(
    result: Optional[bool], exception: Optional[Exception]
) -> None:
    """Assert that item was added successfully."""
    assert exception is None  # noqa: S101
    assert result is True  # noqa: S101


def _then_item_validation_failed(
    result: Optional[bool], exception: Optional[Exception]
) -> None:
    """Assert that item validation failed."""
    assert exception is None  # noqa: S101
    assert result is False  # noqa: S101


def _then_multiple_items_added_successfully(
    added_count: Optional[int], exception: Optional[Exception], expected_count: int
) -> None:
    """Assert that multiple items were added successfully."""
    assert exception is None  # noqa: S101
    assert added_count == expected_count  # noqa: S101


def _then_multiple_items_partial_success(
    added_count: Optional[int], exception: Optional[Exception], expected_count: int
) -> None:
    """Assert that multiple items had partial success."""
    assert exception is None  # noqa: S101
    assert added_count == expected_count  # noqa: S101


def _then_current_batch_size_is(
    processor: GenericBatchProcessor, expected_size: int
) -> None:
    """Assert that current batch size matches expected."""
    assert processor.get_current_batch_size() == expected_size  # noqa: S101


def _then_current_batch_is_empty(processor: GenericBatchProcessor) -> None:
    """Assert that current batch is empty."""
    assert processor.get_current_batch_size() == 0  # noqa: S101


def _then_latest_date_tracked(
    processor: GenericBatchProcessor, expected_date: str
) -> None:
    """Assert that latest date is tracked correctly."""
    stats = processor.get_statistics()
    assert stats["latest_date"] == expected_date  # noqa: S101


def _then_batch_processed_successfully(
    work_id: Optional[str], exception: Optional[Exception]
) -> None:
    """Assert that batch was processed successfully."""
    assert exception is None  # noqa: S101
    assert work_id is not None  # noqa: S101
    assert work_id.startswith("work-")  # noqa: S101


def _then_empty_batch_processed(
    work_id: Optional[str], exception: Optional[Exception]
) -> None:
    """Assert that empty batch was processed (returns None)."""
    assert exception is None  # noqa: S101
    assert work_id is None  # noqa: S101


def _then_batch_processing_failed_after_retries(
    work_id: Optional[str], exception: Optional[Exception]
) -> None:
    """Assert that batch processing failed after retries."""
    assert work_id is None  # noqa: S101
    assert exception is not None  # noqa: S101
    assert isinstance(exception, BatchProcessingError)  # noqa: S101


def _then_flush_empty_batch(
    work_id: Optional[str], exception: Optional[Exception]
) -> None:
    """Assert that flush handled empty batch correctly."""
    assert exception is None  # noqa: S101
    assert work_id is None  # noqa: S101


def _then_work_initiated(
    mock_work_manager: MockWorkManager, expected_calls: int
) -> None:
    """Assert that work was initiated expected number of times."""
    assert mock_work_manager.initiate_work.call_count == expected_calls  # noqa: S101


def _then_work_initiated_with_retries(
    mock_work_manager: MockWorkManager, expected_calls: int
) -> None:
    """Assert that work was initiated with retries."""
    assert mock_work_manager.initiate_work.call_count == expected_calls  # noqa: S101


def _then_bundle_sent(mock_work_manager: MockWorkManager, expected_calls: int) -> None:
    """Assert that bundle was sent expected number of times."""
    assert mock_work_manager.send_bundle.call_count == expected_calls  # noqa: S101


def _then_work_marked_for_processing(
    mock_work_manager: MockWorkManager, expected_calls: int
) -> None:
    """Assert that work was marked for processing expected number of times."""
    assert mock_work_manager.work_to_process.call_count == expected_calls  # noqa: S101


def _then_no_work_initiated(mock_work_manager: MockWorkManager) -> None:
    """Assert that no work was initiated."""
    assert mock_work_manager.initiate_work.call_count == 0  # noqa: S101


def _then_state_updated_with_date(
    mock_work_manager: MockWorkManager, expected_date: str
) -> None:
    """Assert that state was updated with specific date."""
    mock_work_manager.update_state.assert_called_with(
        state_key="dated_cursor", date_str=expected_date
    )


def _then_state_updated_with_current_time(mock_work_manager: MockWorkManager) -> None:
    """Assert that state was updated with current time."""
    mock_work_manager.update_state.assert_called()
    call_args = mock_work_manager.update_state.call_args
    assert call_args[1]["state_key"] == "test_cursor"  # noqa: S101
    assert "T" in call_args[1]["date_str"]  # noqa: S101


def _then_statistics_are_initial(stats: Dict[str, Any]) -> None:
    """Assert that statistics show initial state."""
    assert stats["total_items_processed"] == 0  # noqa: S101
    assert stats["total_batches_processed"] == 0  # noqa: S101
    assert stats["total_items_sent"] == 0  # noqa: S101
    assert stats["current_batch_size"] == 0  # noqa: S101
    assert stats["failed_items_count"] == 0  # noqa: S101


def _then_statistics_show_processing(
    stats: Dict[str, Any],
    expected_items: int,
    expected_batches: int,
    expected_sent: int,
) -> None:
    """Assert that statistics show processing activity."""
    assert stats["total_items_processed"] == expected_items  # noqa: S101
    assert stats["total_batches_processed"] == expected_batches  # noqa: S101
    assert stats["total_items_sent"] == expected_sent  # noqa: S101


def _then_current_batch_size_correct(batch_size: int, expected_size: int) -> None:
    """Assert that current batch size is correct."""
    assert batch_size == expected_size  # noqa: S101


def _then_failed_items_tracked(
    processor: GenericBatchProcessor, expected_count: int
) -> None:
    """Assert that failed items are tracked correctly."""
    failed_items = processor.get_failed_items()
    assert len(failed_items) == expected_count  # noqa: S101


def _then_failed_items_correct(failed_items: List[Any], expected_count: int) -> None:
    """Assert that failed items list is correct."""
    assert len(failed_items) == expected_count  # noqa: S101


def _then_failed_items_empty(processor: GenericBatchProcessor) -> None:
    """Assert that failed items list is empty."""
    failed_items = processor.get_failed_items()
    assert len(failed_items) == 0  # noqa: S101


def _then_items_were_preprocessed(items: List[Any]) -> None:
    """Assert that items were preprocessed."""
    for item in items:
        assert hasattr(item, "preprocessed")  # noqa: S101
        assert item.preprocessed is True  # noqa: S101


def _then_stix_object_added(
    processor: GenericBatchProcessor, expected_count: int
) -> None:
    """Assert that STIX objects were added to batch."""
    assert processor.get_current_batch_size() == expected_count  # noqa: S101


def _then_mapper_converted_to_stix(result: Any) -> None:
    """Assert that mapper was converted to STIX object."""
    assert isinstance(result, MockSTIXObject)  # noqa: S101
    assert hasattr(result, "id")  # noqa: S101
    assert hasattr(result, "type")  # noqa: S101
