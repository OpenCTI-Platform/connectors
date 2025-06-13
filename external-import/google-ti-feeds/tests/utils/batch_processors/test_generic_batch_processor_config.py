"""Test module for GenericBatchProcessorConfig functionality."""

from typing import Any, List, Optional, Tuple

import pytest
from connector.src.utils.batch_processors.generic_batch_processor_config import (
    GenericBatchProcessorConfig,
)

# =====================
# Test Models and Functions
# =====================


class MockSTIXObject:
    """Mock STIX object for testing."""

    def __init__(self, id: str, name: str, modified: Optional[str] = None) -> None:
        """Initialize a MockSTIXObject instance."""
        self.id = id
        self.name = name
        self.modified = modified


class CustomError(Exception):
    """Custom exception for testing."""

    def __init__(
        self,
        message: str,
        batch_number: Optional[int] = None,
        work_id: Optional[str] = None,
    ) -> None:
        """Initialize a CustomError instance."""
        super().__init__(message)
        self.batch_number = batch_number
        self.work_id = work_id


class SimpleError(Exception):
    """Simple exception for testing."""

    pass


def sample_date_extractor(item: Any) -> Optional[str]:
    """Test date extraction function."""
    if hasattr(item, "modified"):
        return str(item.modified) if item.modified is not None else None
    return None


def sample_validator(item: Any) -> bool:
    """Test validation function."""
    return hasattr(item, "id") and hasattr(item, "name")


def sample_preprocessor(items: List[Any]) -> List[Any]:
    """Test preprocessing function."""
    for item in items:
        item.preprocessed = True
    return items


def sample_postprocessor(items: List[Any], work_id: str) -> None:
    """Test postprocessing function."""
    for item in items:
        item.postprocessed = work_id


def failing_preprocessor(items: List[Any]) -> List[Any]:
    """Preprocessing function that fails."""
    raise ValueError("Preprocessing failed")


# =====================
# Fixtures
# =====================


@pytest.fixture
def basic_config() -> GenericBatchProcessorConfig:
    """Fixture for basic configuration."""
    return GenericBatchProcessorConfig(
        batch_size=10,
        work_name_template="Basic Batch - #{batch_num}",
        state_key="basic_cursor",
        entity_type="basic_entities",
        display_name="basic entities",
    )


@pytest.fixture
def full_config() -> GenericBatchProcessorConfig:
    """Fixture for configuration with all options."""
    return GenericBatchProcessorConfig(
        batch_size=25,
        work_name_template="Full Batch - {entity_type} - #{batch_num}",
        state_key="full_cursor",
        entity_type="full_entities",
        display_name="full entities",
        exception_class=CustomError,
        display_name_singular="full entity",
        auto_process=False,
        date_extraction_function=sample_date_extractor,
        preprocessing_function=sample_preprocessor,
        postprocessing_function=sample_postprocessor,
        validation_function=sample_validator,
        empty_batch_behavior="skip",
        max_retries=3,
        retry_delay=2.0,
        work_timeout=120.0,
    )


@pytest.fixture
def config_with_plural_display_name() -> GenericBatchProcessorConfig:
    """Fixture for configuration with plural display name."""
    return GenericBatchProcessorConfig(
        batch_size=5,
        work_name_template="Categories - #{batch_num}",
        state_key="categories_cursor",
        entity_type="categories",
        display_name="categories",
    )


@pytest.fixture
def config_with_non_plural_display_name() -> GenericBatchProcessorConfig:
    """Fixture for configuration with non-plural display name."""
    return GenericBatchProcessorConfig(
        batch_size=5,
        work_name_template="Data - #{batch_num}",
        state_key="data_cursor",
        entity_type="data",
        display_name="data",
    )


# =====================
# Test Cases
# =====================

# Scenario: Creating basic configuration with required parameters


def test_basic_config_creation_with_required_parameters(
    basic_config: GenericBatchProcessorConfig,
) -> None:
    """Test creating configuration with only required parameters."""
    # Given: A basic configuration is created with required parameters
    config = basic_config

    # When: The configuration is inspected
    # Then: All required parameters should be set correctly
    _then_config_has_basic_properties(config)


def test_basic_config_sets_default_values(
    basic_config: GenericBatchProcessorConfig,
) -> None:
    """Test that basic configuration sets appropriate default values."""
    # Given: A basic configuration is created
    config = basic_config

    # When: Default values are inspected
    # Then: Defaults should be set correctly
    _then_config_has_default_values(config)


def test_basic_config_validation_on_creation() -> None:
    """Test that configuration validation occurs during creation."""
    # Given: Invalid configuration parameters

    # When: Configuration is created with invalid batch size
    # Then: ValueError should be raised
    with pytest.raises(ValueError) as excinfo:
        GenericBatchProcessorConfig(
            batch_size=0,  # Invalid
            work_name_template="Test",
            state_key="test",
            entity_type="test",
            display_name="test",
        )
    assert "batch_size must be greater than 0" in str(excinfo.value)  # noqa: S101


def test_basic_config_validation_empty_batch_behavior() -> None:
    """Test validation of empty_batch_behavior parameter."""
    # Given: Invalid empty_batch_behavior value

    # When: Configuration is created with invalid empty_batch_behavior
    # Then: ValueError should be raised
    with pytest.raises(ValueError) as excinfo:
        GenericBatchProcessorConfig(
            batch_size=10,
            work_name_template="Test",
            state_key="test",
            entity_type="test",
            display_name="test",
            empty_batch_behavior="invalid_value",
        )
    assert "empty_batch_behavior must be" in str(excinfo.value)  # noqa: S101


# Scenario: Creating full configuration with all parameters


def test_full_config_creation_with_all_parameters(
    full_config: GenericBatchProcessorConfig,
) -> None:
    """Test creating configuration with all parameters specified."""
    # Given: A full configuration is created with all parameters
    config = full_config

    # When: The configuration is inspected
    # Then: All parameters should be set correctly
    _then_config_has_full_properties(config)


# Scenario: Auto-generation of singular display names


def test_display_name_singular_auto_generated_from_plural(
    config_with_plural_display_name: GenericBatchProcessorConfig,
) -> None:
    """Test automatic generation of singular form from plural display name."""
    # Given: A configuration with a plural display name ending in 's'
    config = config_with_plural_display_name

    # When: The singular display name is inspected
    # Then: It should be automatically generated by removing the 's'
    _then_singular_name_is_auto_generated(config, expected="categorie")


def test_display_name_singular_unchanged_for_non_plural(
    config_with_non_plural_display_name: GenericBatchProcessorConfig,
) -> None:
    """Test that non-plural display names remain unchanged."""
    # Given: A configuration with a non-plural display name
    config = config_with_non_plural_display_name

    # When: The singular display name is inspected
    # Then: It should remain the same as the original display name
    _then_singular_name_unchanged(config, expected="data")


def test_explicit_singular_name_overrides_auto_generation() -> None:
    """Test that explicitly set singular name overrides auto-generation."""
    # Given: A configuration with explicit singular name
    config = GenericBatchProcessorConfig(
        batch_size=5,
        work_name_template="People - #{batch_num}",
        state_key="people_cursor",
        entity_type="people",
        display_name="people",
        display_name_singular="person",
    )

    # When: The singular display name is inspected
    # Then: It should use the explicitly set value
    _then_singular_name_is_explicit(config, expected="person")


# Scenario: Work name formatting


def test_format_work_name_basic() -> None:
    """Test formatting work name with basic parameters."""
    # Given: A configuration with a work name template
    config = GenericBatchProcessorConfig(
        batch_size=10,
        work_name_template="Test Batch - #{batch_num}",
        state_key="test_cursor",
        entity_type="test",
        display_name="test",
    )

    # When: Work name is formatted with batch number
    work_name, exception = _when_work_name_formatted(config, batch_num=5)

    # Then: Work name should be correctly formatted
    assert work_name is not None  # noqa: S101
    _then_work_name_formatted_successfully(work_name, "Test Batch - #5")


def test_format_work_name_with_multiple_parameters() -> None:
    """Test formatting work name with multiple parameters."""
    # Given: A configuration with a multi-parameter template
    config = GenericBatchProcessorConfig(
        batch_size=10,
        work_name_template="Import - {entity_type} - Batch #{batch_num} - {custom}",
        state_key="test_cursor",
        entity_type="reports",
        display_name="reports",
    )

    # When: Work name is formatted with multiple parameters
    work_name, exception = _when_work_name_formatted(
        config, batch_num=3, entity_type="reports", custom="high_priority"
    )

    # Then: Work name should be correctly formatted
    assert work_name is not None  # noqa: S101
    _then_work_name_formatted_successfully(
        work_name, "Import - reports - Batch #3 - high_priority"
    )


def test_format_work_name_with_missing_parameter() -> None:
    """Test formatting work name with missing required parameter."""
    # Given: A configuration with a parameterized template
    config = GenericBatchProcessorConfig(
        batch_size=10,
        work_name_template="Test - {missing_param} - #{batch_num}",
        state_key="test_cursor",
        entity_type="test",
        display_name="test",
    )

    # When: Work name is formatted without required parameter
    work_name, exception = _when_work_name_formatted(config, batch_num=1)

    # Then: ValueError should be raised with appropriate message
    assert exception is not None  # noqa: S101
    _then_work_name_formatting_failed(exception, expected_param="missing_param")


# Scenario: Date extraction functionality


def test_extract_date_with_function() -> None:
    """Test date extraction with configured function."""
    # Given: A configuration with date extraction function
    config = GenericBatchProcessorConfig(
        batch_size=10,
        work_name_template="Test",
        state_key="test",
        entity_type="test",
        display_name="test",
        date_extraction_function=sample_date_extractor,
    )

    item_with_date = MockSTIXObject("test-001", "Test", "2023-01-01T10:00:00+00:00")

    # When: Date is extracted from item
    extracted_date = _when_date_extracted(config, item_with_date)

    # Then: Correct date should be extracted
    assert extracted_date is not None  # noqa: S101
    _then_date_extracted_successfully(extracted_date, "2023-01-01T10:00:00+00:00")


def test_extract_date_without_function() -> None:
    """Test date extraction without configured function."""
    # Given: A configuration without date extraction function
    config = GenericBatchProcessorConfig(
        batch_size=10,
        work_name_template="Test",
        state_key="test",
        entity_type="test",
        display_name="test",
        date_extraction_function=None,
    )

    item = MockSTIXObject("test-001", "Test")

    # When: Date is extracted from item
    extracted_date = _when_date_extracted(config, item)

    # Then: None should be returned
    _then_date_extraction_returns_none(extracted_date)


def test_extract_date_with_failing_function() -> None:
    """Test date extraction when function fails."""

    # Given: A configuration with failing date extraction function
    def failing_extractor(item: Any) -> str:
        raise ValueError("Date extraction failed")

    config = GenericBatchProcessorConfig(
        batch_size=10,
        work_name_template="Test",
        state_key="test",
        entity_type="test",
        display_name="test",
        date_extraction_function=failing_extractor,
    )

    item = MockSTIXObject("test-001", "Test")

    # When: Date is extracted from item with failing function
    extracted_date = _when_date_extracted(config, item)

    # Then: None should be returned (graceful failure)
    _then_date_extraction_returns_none(extracted_date)


# Scenario: Item validation functionality


def test_validate_item_with_function() -> None:
    """Test item validation with configured function."""
    # Given: A configuration with validation function
    config = GenericBatchProcessorConfig(
        batch_size=10,
        work_name_template="Test",
        state_key="test",
        entity_type="test",
        display_name="test",
        validation_function=sample_validator,
    )

    valid_item = MockSTIXObject("test-001", "Valid Item")
    invalid_item = {"missing": "attributes"}

    # When: Items are validated
    valid_result = _when_item_validated(config, valid_item)
    invalid_result = _when_item_validated(config, invalid_item)

    # Then: Validation results should be correct
    _then_item_validation_successful(valid_result)
    _then_item_validation_failed(invalid_result)


def test_validate_item_without_function() -> None:
    """Test item validation without configured function."""
    # Given: A configuration without validation function
    config = GenericBatchProcessorConfig(
        batch_size=10,
        work_name_template="Test",
        state_key="test",
        entity_type="test",
        display_name="test",
        validation_function=None,
    )

    item = {"any": "data"}

    # When: Item is validated
    result = _when_item_validated(config, item)

    # Then: Validation should pass (default behavior)
    _then_item_validation_successful(result)


def test_validate_item_with_failing_function() -> None:
    """Test item validation when function fails."""

    # Given: A configuration with failing validation function
    def failing_validator(item: Any) -> bool:
        raise ValueError("Validation failed")

    config = GenericBatchProcessorConfig(
        batch_size=10,
        work_name_template="Test",
        state_key="test",
        entity_type="test",
        display_name="test",
        validation_function=failing_validator,
    )

    item = MockSTIXObject("test-001", "Test")

    # When: Item is validated with failing function
    result = _when_item_validated(config, item)

    # Then: Validation should fail gracefully
    _then_item_validation_failed(result)


# Scenario: Batch preprocessing functionality


def test_preprocess_batch_with_function() -> None:
    """Test batch preprocessing with configured function."""
    # Given: A configuration with preprocessing function
    config = GenericBatchProcessorConfig(
        batch_size=10,
        work_name_template="Test",
        state_key="test",
        entity_type="test",
        display_name="test",
        preprocessing_function=sample_preprocessor,
    )

    items = [
        MockSTIXObject("test-001", "Item 1"),
        MockSTIXObject("test-002", "Item 2"),
    ]

    # When: Batch is preprocessed
    processed_items, exception = _when_batch_preprocessed(config, items)

    # Then: Preprocessing should succeed and items should be modified
    assert processed_items is not None  # noqa: S101
    assert exception is None  # noqa: S101
    _then_batch_preprocessing_successful(processed_items, exception)
    _then_items_were_preprocessed(processed_items)


def test_preprocess_batch_without_function() -> None:
    """Test batch preprocessing without configured function."""
    # Given: A configuration without preprocessing function
    config = GenericBatchProcessorConfig(
        batch_size=10,
        work_name_template="Test",
        state_key="test",
        entity_type="test",
        display_name="test",
        preprocessing_function=None,
    )

    items = [MockSTIXObject("test-001", "Item 1")]

    # When: Batch is preprocessed
    processed_items, exception = _when_batch_preprocessed(config, items)

    # Then: Preprocessing should succeed and return items unchanged
    assert processed_items is not None  # noqa: S101
    assert exception is None  # noqa: S101
    _then_batch_preprocessing_successful(processed_items, exception)
    _then_items_unchanged(processed_items, items)


def test_preprocess_batch_with_failing_function() -> None:
    """Test batch preprocessing when function fails."""
    # Given: A configuration with failing preprocessing function
    config = GenericBatchProcessorConfig(
        batch_size=10,
        work_name_template="Test",
        state_key="test",
        entity_type="test",
        display_name="test",
        exception_class=CustomError,
        preprocessing_function=failing_preprocessor,
    )

    items = [MockSTIXObject("test-001", "Item 1")]

    # When: Batch is preprocessed with failing function
    processed_items, exception = _when_batch_preprocessed(config, items)

    # Then: CustomError should be raised
    assert exception is not None  # noqa: S101
    _then_batch_preprocessing_failed(processed_items, exception, CustomError)


# Scenario: Batch postprocessing functionality


def test_postprocess_batch_with_function() -> None:
    """Test batch postprocessing with configured function."""
    # Given: A configuration with postprocessing function
    config = GenericBatchProcessorConfig(
        batch_size=10,
        work_name_template="Test",
        state_key="test",
        entity_type="test",
        display_name="test",
        postprocessing_function=sample_postprocessor,
    )

    items = [MockSTIXObject("test-001", "Item 1")]
    work_id = "work-123"

    # When: Batch is postprocessed
    _when_batch_postprocessed(config, items, work_id)

    # Then: Items should be postprocessed
    _then_items_were_postprocessed(items, work_id)


def test_postprocess_batch_without_function() -> None:
    """Test batch postprocessing without configured function."""
    # Given: A configuration without postprocessing function
    config = GenericBatchProcessorConfig(
        batch_size=10,
        work_name_template="Test",
        state_key="test",
        entity_type="test",
        display_name="test",
        postprocessing_function=None,
    )

    items = [MockSTIXObject("test-001", "Item 1")]
    work_id = "work-123"

    # When: Batch is postprocessed
    processed_items, exception = _when_batch_postprocessed(config, items, work_id)

    # Then: Postprocessing should complete successfully without errors
    _then_postprocessing_completed_successfully()
    assert exception is None  # noqa: S101
    assert processed_items == items  # noqa: S101


def test_postprocess_batch_with_failing_function() -> None:
    """Test batch postprocessing when function fails."""

    # Given: A configuration with failing postprocessing function
    def failing_postprocessor(items: List[Any], work_id: str) -> None:
        raise ValueError("Postprocessing failed")

    config = GenericBatchProcessorConfig(
        batch_size=10,
        work_name_template="Test",
        state_key="test",
        entity_type="test",
        display_name="test",
        postprocessing_function=failing_postprocessor,
        exception_class=CustomError,
    )

    items = [MockSTIXObject("test-001", "Item 1")]
    work_id = "work-123"

    # When/Then: Batch postprocessed with failing function should raise an exception
    with pytest.raises(CustomError) as exc_info:
        config.postprocess_batch(items, work_id)

    assert "Postprocessing failed" in str(exc_info.value)  # noqa: S101


# Scenario: Exception creation functionality


def test_create_exception_with_full_parameters() -> None:
    """Test creating exception with all parameters."""
    # Given: A configuration with custom exception class
    config = GenericBatchProcessorConfig(
        batch_size=10,
        work_name_template="Test",
        state_key="test",
        entity_type="test",
        display_name="test",
        exception_class=CustomError,
    )

    # When: Exception is created with all parameters
    exception = _when_exception_created(
        config, "Test error", batch_number=1, work_id="work-123"
    )

    # Then: Exception should be created with all parameters
    _then_exception_created_with_full_params(exception, "Test error", 1, "work-123")


def test_create_exception_with_simple_constructor() -> None:
    """Test creating exception with simple message-only constructor."""
    # Given: A configuration with simple exception class
    config = GenericBatchProcessorConfig(
        batch_size=10,
        work_name_template="Test",
        state_key="test",
        entity_type="test",
        display_name="test",
        exception_class=SimpleError,
    )

    # When: Exception is created with additional parameters
    exception = _when_exception_created(
        config, "Test error", batch_number=1, work_id="work-123"
    )

    # Then: Exception should fall back to message-only constructor
    _then_exception_created_simple(exception, "Test error")


# Scenario: Current timestamp generation


def test_get_current_timestamp() -> None:
    """Test getting current timestamp."""
    # Given: A configuration
    config = GenericBatchProcessorConfig(
        batch_size=10,
        work_name_template="Test",
        state_key="test",
        entity_type="test",
        display_name="test",
    )

    # When: Current timestamp is generated
    timestamp = _when_current_timestamp_generated(config)

    # Then: Timestamp should be in ISO format
    _then_timestamp_is_iso_format(timestamp)


# =====================
# GWT Helper Functions
# =====================

# --- WHEN: Execute the system under test ---


def _when_work_name_formatted(
    config: GenericBatchProcessorConfig, **kwargs: Any
) -> Tuple[Optional[str], Optional[Exception]]:
    """Format work name and capture result and exception."""
    try:
        return config.format_work_name(**kwargs), None
    except Exception as e:
        return None, e


def _when_date_extracted(
    config: GenericBatchProcessorConfig, item: Any
) -> Optional[str]:
    """Extract date from item."""
    return config.extract_date(item)


def _when_item_validated(config: GenericBatchProcessorConfig, item: Any) -> bool:
    """Validate item."""
    return config.validate_item(item)


def _when_batch_preprocessed(
    config: GenericBatchProcessorConfig, items: List[Any]
) -> Tuple[Optional[List[Any]], Optional[Exception]]:
    """Preprocess batch and capture result and exception."""
    try:
        return config.preprocess_batch(items), None
    except Exception as e:
        return None, e


def _when_batch_postprocessed(
    config: GenericBatchProcessorConfig, items: List[Any], work_id: str
) -> Tuple[Optional[List[Any]], Optional[Exception]]:
    """Postprocess batch."""
    try:
        config.postprocess_batch(items, work_id)
        return (
            items,
            None,
        )
    except Exception as e:
        return None, e


def _when_exception_created(
    config: GenericBatchProcessorConfig, message: str, **kwargs: Any
) -> Any:
    """Create exception using config's exception factory."""
    return config.create_exception(message, **kwargs)


def _when_current_timestamp_generated(config: GenericBatchProcessorConfig) -> str:
    """Generate current timestamp."""
    return config.get_current_timestamp()


# --- THEN: Verify the expected outcomes ---


def _then_config_has_basic_properties(config: GenericBatchProcessorConfig) -> None:
    """Assert that basic configuration properties are set correctly."""
    assert config.batch_size == 10  # noqa: S101
    assert config.work_name_template == "Basic Batch - #{batch_num}"  # noqa: S101
    assert config.state_key == "basic_cursor"  # noqa: S101
    assert config.entity_type == "basic_entities"  # noqa: S101
    assert config.display_name == "basic entities"  # noqa: S101


def _then_config_has_default_values(config: GenericBatchProcessorConfig) -> None:
    """Assert that default values are set correctly."""
    assert config.exception_class is Exception  # noqa: S101
    assert config.display_name_singular == "basic entitie"  # noqa: S101
    assert config.auto_process is True  # noqa: S101
    assert config.date_extraction_function is None  # noqa: S101
    assert config.preprocessing_function is None  # noqa: S101
    assert config.postprocessing_function is None  # noqa: S101
    assert config.validation_function is None  # noqa: S101
    assert config.empty_batch_behavior == "update_state"  # noqa: S101
    assert config.max_retries == 0  # noqa: S101
    assert config.retry_delay == 1.0  # noqa: S101
    assert config.work_timeout is None  # noqa: S101


def _then_config_has_full_properties(config: GenericBatchProcessorConfig) -> None:
    """Assert that full configuration properties are set correctly."""
    assert config.batch_size == 25  # noqa: S101
    assert (  # noqa: S101
        config.work_name_template == "Full Batch - {entity_type} - #{batch_num}"
    )
    assert config.state_key == "full_cursor"  # noqa: S101
    assert config.entity_type == "full_entities"  # noqa: S101
    assert config.display_name == "full entities"  # noqa: S101
    assert config.exception_class == CustomError  # noqa: S101
    assert config.display_name_singular == "full entity"  # noqa: S101
    assert config.auto_process is False  # noqa: S101
    assert config.date_extraction_function == sample_date_extractor  # noqa: S101
    assert config.preprocessing_function == sample_preprocessor  # noqa: S101
    assert config.postprocessing_function == sample_postprocessor  # noqa: S101
    assert config.validation_function == sample_validator  # noqa: S101
    assert config.empty_batch_behavior == "skip"  # noqa: S101
    assert config.max_retries == 3  # noqa: S101
    assert config.retry_delay == 2.0  # noqa: S101
    assert config.work_timeout == 120.0  # noqa: S101


def _then_singular_name_is_auto_generated(
    config: GenericBatchProcessorConfig, expected: str
) -> None:
    """Assert that singular name was auto-generated correctly."""
    assert config.display_name_singular == expected  # noqa: S101


def _then_singular_name_unchanged(
    config: GenericBatchProcessorConfig, expected: str
) -> None:
    """Assert that singular name remained unchanged."""
    assert config.display_name_singular == expected  # noqa: S101


def _then_singular_name_is_explicit(
    config: GenericBatchProcessorConfig, expected: str
) -> None:
    """Assert that explicit singular name was used."""
    assert config.display_name_singular == expected  # noqa: S101


def _then_work_name_formatted_successfully(work_name: str, expected: str) -> None:
    """Assert that work name was formatted successfully."""
    assert work_name == expected  # noqa: S101


def _then_work_name_formatting_failed(
    exception: Exception, expected_param: str
) -> None:
    """Assert that work name formatting failed with expected parameter."""
    assert exception is not None  # noqa: S101
    assert isinstance(exception, ValueError)  # noqa: S101
    assert expected_param in str(exception)  # noqa: S101


def _then_date_extracted_successfully(extracted_date: str, expected: str) -> None:
    """Assert that date was extracted successfully."""
    assert extracted_date == expected  # noqa: S101


def _then_date_extraction_returns_none(extracted_date: Optional[str]) -> None:
    """Assert that date extraction returns None."""
    assert extracted_date is None  # noqa: S101


def _then_item_validation_successful(result: bool) -> None:
    """Assert that item validation was successful."""
    assert result is True  # noqa: S101


def _then_item_validation_failed(result: bool) -> None:
    """Assert that item validation failed."""
    assert result is False  # noqa: S101


def _then_batch_preprocessing_successful(
    processed_items: List[Any], exception: Optional[Exception]
) -> None:
    """Assert that batch preprocessing was successful."""
    assert exception is None  # noqa: S101
    assert processed_items is not None  # noqa: S101


def _then_batch_preprocessing_failed(
    processed_items: Optional[List[Any]],
    exception: Exception,
    expected_exception_type: type,
) -> None:
    """Assert that batch preprocessing failed with expected exception."""
    assert processed_items is None  # noqa: S101
    assert exception is not None  # noqa: S101
    assert isinstance(exception, expected_exception_type)  # noqa: S101


def _then_items_were_preprocessed(items: List[Any]) -> None:
    """Assert that items were preprocessed."""
    for item in items:
        assert hasattr(item, "preprocessed")  # noqa: S101
        assert item.preprocessed is True  # noqa: S101


def _then_items_unchanged(
    processed_items: List[Any], original_items: List[Any]
) -> None:
    """Assert that items remained unchanged."""
    assert processed_items == original_items  # noqa: S101


def _then_items_were_postprocessed(items: List[Any], work_id: str) -> None:
    """Assert that items were postprocessed."""
    for item in items:
        assert hasattr(item, "postprocessed")  # noqa: S101
        assert item.postprocessed == work_id  # noqa: S101


def _then_postprocessing_completed_successfully() -> None:
    """Assert that postprocessing completed without errors."""
    pass


def _then_batch_postprocessing_failed(
    processed_items: Optional[List[Any]],
    exception: Exception,
    expected_exception_type: type,
) -> None:
    """Assert that batch preprocessing failed with expected exception."""
    assert processed_items is None  # noqa: S101
    assert exception is not None  # noqa: S101
    assert isinstance(exception, expected_exception_type)  # noqa: S101


def _then_exception_created_with_full_params(
    exception: Exception,
    expected_message: str,
    expected_batch: int,
    expected_work_id: str,
) -> None:
    """Assert that exception was created with full parameters."""
    assert isinstance(exception, CustomError)  # noqa: S101
    assert str(exception) == expected_message  # noqa: S101
    assert exception.batch_number == expected_batch  # noqa: S101
    assert exception.work_id == expected_work_id  # noqa: S101


def _then_exception_created_simple(exception: Exception, expected_message: str) -> None:
    """Assert that exception was created with simple constructor."""
    assert isinstance(exception, SimpleError)  # noqa: S101
    assert str(exception) == expected_message  # noqa: S101


def _then_timestamp_is_iso_format(timestamp: str) -> None:
    """Assert that timestamp is in ISO format."""
    assert isinstance(timestamp, str)  # noqa: S101
    assert "T" in timestamp  # noqa: S101
    assert timestamp.endswith("+00:00")  # noqa: S101
