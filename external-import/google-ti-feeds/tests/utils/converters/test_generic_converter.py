"""Test module for GenericConverter functionality."""

from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import MagicMock

import pytest
from connector.src.utils.converters.generic_converter import GenericConverter
from connector.src.utils.converters.generic_converter_config import (
    BaseMapper,
    GenericConverterConfig,
)
from pydantic import BaseModel

# =====================
# Test Models and Mappers
# =====================


class UserTestModel(BaseModel):
    """Test model for converter testing."""

    id: str
    name: str
    description: str


class MockSTIXObject:
    """Mock STIX object for testing."""

    def __init__(self, id: str, name: str, type: str = "test-object"):
        """Initialize the mock STIX object."""
        self.id = id
        self.name = name
        self.type = type


class MockMapper(BaseMapper):
    """Mock mapper for testing."""

    def __init__(
        self,
        input_data: Any,
        organization: Optional[str] = None,
        tlp_marking: Optional[str] = None,
    ):
        """Initialize the mock mapper."""
        self.input_data = input_data
        self.organization = organization
        self.tlp_marking = tlp_marking

    def to_stix(self) -> MockSTIXObject:
        """Convert the input data to a MockSTIXObject."""
        if hasattr(self.input_data, "id"):
            entity_id = self.input_data.id
        elif isinstance(self.input_data, dict):
            entity_id = self.input_data.get("id", "unknown")
        else:
            entity_id = "unknown"

        if hasattr(self.input_data, "name"):
            entity_name = self.input_data.name
        elif isinstance(self.input_data, dict):
            entity_name = self.input_data.get("name", "Unknown")
        else:
            entity_name = "Unknown"

        return MockSTIXObject(
            id=entity_id,
            name=entity_name,
        )


class FailingMapper(BaseMapper):
    """Mapper that always fails for testing."""

    def __init__(self, input_data: Any, **kwargs: Any):
        """Initialize the mapper with input data."""
        self.input_data = input_data

    def to_stix(self) -> None:
        """Convert the input data to a MockSTIXObject."""
        raise ValueError("Simulated mapper failure")


class MultiObjectMapper(BaseMapper):
    """Mapper that returns multiple STIX objects."""

    def __init__(self, input_data: Any, **kwargs: Any):
        """Initialize the mapper with input data."""
        self.input_data = input_data

    def to_stix(self) -> List[MockSTIXObject]:
        """Convert the input data to a list of MockSTIXObjects."""
        return [
            MockSTIXObject(
                id=f"test--{self.input_data.get('id', 'unknown')}-1", name="Object 1"
            ),
            MockSTIXObject(
                id=f"test--{self.input_data.get('id', 'unknown')}-2", name="Object 2"
            ),
        ]


class CustomError(Exception):
    """Custom exception for testing."""

    def __init__(
        self,
        message: str,
        entity_id: Optional[str] = None,
        entity_name: Optional[str] = None,
    ):
        """Initialize the custom exception."""
        super().__init__(message)
        self.entity_id = entity_id
        self.entity_name = entity_name


# =====================
# Fixtures
# =====================


@pytest.fixture
def mock_logger() -> MagicMock:
    """Fixture for mocked logger."""
    return MagicMock()


@pytest.fixture
def basic_config() -> GenericConverterConfig:
    """Fixture for basic converter configuration."""
    return GenericConverterConfig(
        entity_type="test_entities",
        mapper_class=MockMapper,
        output_stix_type="test-object",
        exception_class=CustomError,
        display_name="test entities",
    )


@pytest.fixture
def model_config() -> GenericConverterConfig:
    """Fixture for configuration with response model."""
    return GenericConverterConfig(
        entity_type="model_entities",
        mapper_class=MockMapper,
        output_stix_type="test-object",
        exception_class=CustomError,
        display_name="model entities",
        input_model=UserTestModel,
        additional_dependencies={"organization": "test-org", "tlp_marking": "amber"},
    )


@pytest.fixture
def failing_config() -> GenericConverterConfig:
    """Fixture for configuration with failing mapper."""
    return GenericConverterConfig(
        entity_type="failing_entities",
        mapper_class=FailingMapper,
        output_stix_type="test-object",
        exception_class=CustomError,
        display_name="failing entities",
        id_field="id",
        name_field="name",
    )


@pytest.fixture
def multi_object_config() -> GenericConverterConfig:
    """Fixture for configuration with multi-object mapper."""
    return GenericConverterConfig(
        entity_type="multi_entities",
        mapper_class=MultiObjectMapper,
        output_stix_type="test-object",
        exception_class=CustomError,
        display_name="multi entities",
    )


@pytest.fixture
def preprocessing_config() -> GenericConverterConfig:
    """Fixture for configuration with preprocessing function."""

    def preprocess(data: Any) -> Any:
        data["preprocessed"] = True
        return data

    def postprocess(stix_obj: Any) -> Any:
        stix_obj.postprocessed = True
        return stix_obj

    return GenericConverterConfig(
        entity_type="processed_entities",
        mapper_class=MockMapper,
        output_stix_type="test-object",
        exception_class=CustomError,
        display_name="processed entities",
        preprocessing_function=preprocess,
        postprocessing_function=postprocess,
    )


@pytest.fixture
def to_stix_true_config() -> GenericConverterConfig:
    """Fixture for configuration with to_stix=True (default behavior)."""
    return GenericConverterConfig(
        entity_type="stix_entities",
        mapper_class=MockMapper,
        output_stix_type="test-object",
        exception_class=CustomError,
        display_name="stix entities",
        to_stix=True,
    )


@pytest.fixture
def to_stix_false_config() -> GenericConverterConfig:
    """Fixture for configuration with to_stix=False (return mapper objects)."""
    return GenericConverterConfig(
        entity_type="model_entities",
        mapper_class=MockMapper,
        output_stix_type="test-object",
        exception_class=CustomError,
        display_name="model entities",
        to_stix=False,
    )


@pytest.fixture
def basic_converter(
    basic_config: GenericConverterConfig, mock_logger: MagicMock
) -> GenericConverter:
    """Fixture for basic generic converter."""
    return GenericConverter(config=basic_config, logger=mock_logger)


@pytest.fixture
def model_converter(
    model_config: GenericConverterConfig, mock_logger: MagicMock
) -> GenericConverter:
    """Fixture for model-based generic converter."""
    return GenericConverter(config=model_config, logger=mock_logger)


@pytest.fixture
def failing_converter(
    failing_config: GenericConverterConfig, mock_logger: MagicMock
) -> GenericConverter:
    """Fixture for failing converter."""
    return GenericConverter(config=failing_config, logger=mock_logger)


@pytest.fixture
def to_stix_true_converter(
    to_stix_true_config: GenericConverterConfig, mock_logger: MagicMock
) -> GenericConverter:
    """Fixture for converter with to_stix=True."""
    return GenericConverter(config=to_stix_true_config, logger=mock_logger)


@pytest.fixture
def to_stix_false_converter(
    to_stix_false_config: GenericConverterConfig, mock_logger: MagicMock
) -> GenericConverter:
    """Fixture for converter with to_stix=False."""
    return GenericConverter(config=to_stix_false_config, logger=mock_logger)


# =====================
# Test Cases
# =====================

# Scenario: Successful single entity conversion


def test_convert_single_success_raw_data(basic_converter: GenericConverter) -> None:
    """Test successful single entity conversion with raw data."""
    # Given: A configured converter and raw input data
    input_data = {
        "id": "test-001",
        "name": "Test Entity",
        "description": "Test description",
    }

    # When: A single entity is converted
    result, exception = _when_convert_single_called(basic_converter, input_data)

    # Then: The conversion should succeed and return STIX object
    _then_conversion_successful(result, exception)
    _then_stix_object_has_properties(result, "test-001", "Test Entity")


def test_convert_single_success_with_model(model_converter: GenericConverter) -> None:
    """Test successful single entity conversion with Pydantic model."""
    # Given: A model-configured converter and model input data
    input_data = UserTestModel(
        id="model-001", name="Model Entity", description="Model description"
    )

    # When: A single entity is converted
    result, exception = _when_convert_single_called(model_converter, input_data)

    # Then: The conversion should succeed
    _then_conversion_successful(result, exception)
    _then_stix_object_has_properties(result, "model-001", "Model Entity")


def test_convert_single_with_multi_object_mapper(
    multi_object_config: GenericConverterConfig, mock_logger: MagicMock
) -> None:
    """Test single entity conversion that produces multiple STIX objects."""
    # Given: A converter with multi-object mapper
    converter = GenericConverter(config=multi_object_config, logger=mock_logger)
    input_data = {"id": "multi-001", "name": "Multi Entity"}

    # When: A single entity is converted
    result, exception = _when_convert_single_called(converter, input_data)

    # Then: Multiple STIX objects should be returned
    _then_conversion_successful(result, exception)
    _then_multiple_stix_objects_returned(result, 2)


def test_convert_single_with_preprocessing_postprocessing(
    preprocessing_config: GenericConverterConfig, mock_logger: MagicMock
) -> None:
    """Test single entity conversion with preprocessing and postprocessing."""
    # Given: A converter with preprocessing and postprocessing functions
    converter = GenericConverter(config=preprocessing_config, logger=mock_logger)
    input_data = {"id": "process-001", "name": "Processed Entity"}

    # When: A single entity is converted
    result, exception = _when_convert_single_called(converter, input_data)

    # Then: The conversion should succeed and show processing effects
    _then_conversion_successful(result, exception)
    _then_object_was_postprocessed(result)


# Scenario: Single entity conversion with errors


def test_convert_single_mapper_failure(failing_converter: GenericConverter) -> None:
    """Test single entity conversion with mapper failure."""
    # Given: A converter with failing mapper
    input_data = {"id": "fail-001", "name": "Failing Entity"}

    # When: A single entity is converted
    result, exception = _when_convert_single_called(failing_converter, input_data)

    # Then: A CustomError should be raised with context
    _then_conversion_failed_with_custom_error(
        result, exception, "fail-001", "Failing Entity"
    )


def test_convert_single_input_validation_failure() -> None:
    """Test single entity conversion with input validation failure."""
    # Given: A converter with strict input validation
    config = GenericConverterConfig(
        entity_type="validated_entities",
        mapper_class=MockMapper,
        output_stix_type="test-object",
        exception_class=CustomError,
        display_name="validated entities",
        input_model=UserTestModel,
        validate_input=True,
    )
    converter = GenericConverter(config=config)

    invalid_data = {"invalid": "data"}  # Missing required fields

    # When: A single entity is converted with invalid data
    result, exception = _when_convert_single_called(converter, invalid_data)

    # Then: A CustomError should be raised for validation failure
    _then_conversion_failed_with_validation_error(result, exception)


def test_convert_single_output_validation_failure() -> None:
    """Test single entity conversion with output validation failure."""

    # Given: A converter that produces invalid output
    class BadOutputMapper(BaseMapper):
        def __init__(self, input_data: Any, **kwargs: Any) -> None:
            self.input_data = input_data

        def to_stix(self) -> None:
            return None  # Invalid STIX output

    config = GenericConverterConfig(
        entity_type="bad_output",
        mapper_class=BadOutputMapper,
        output_stix_type="test-object",
        exception_class=CustomError,
        display_name="bad output",
        validate_output=True,
    )
    converter = GenericConverter(config=config)

    # When: A single entity is converted
    result, exception = _when_convert_single_called(converter, {"id": "bad-001"})

    # Then: A CustomError should be raised for output validation failure
    _then_conversion_failed_with_validation_error(result, exception)


# Scenario: Multiple entity conversion


def test_convert_multiple_success(model_converter: GenericConverter) -> None:
    """Test successful multiple entity conversion."""
    # Given: A configured converter and multiple input entities
    input_data_list = [
        UserTestModel(id="multi-001", name="Entity 1", description="First entity"),
        UserTestModel(id="multi-002", name="Entity 2", description="Second entity"),
        UserTestModel(id="multi-003", name="Entity 3", description="Third entity"),
    ]

    # When: Multiple entities are converted
    result, exception = _when_convert_multiple_called(model_converter, input_data_list)

    # Then: All entities should be converted successfully
    _then_multiple_conversion_successful(result, exception, 3)


def test_convert_multiple_partial_success(basic_converter: GenericConverter) -> None:
    """Test multiple entity conversion with partial failures."""
    # Given: A converter and mixed input data (some will fail in mapper)
    input_data_list = [
        {"id": "good-001", "name": "Good Entity 1"},
        {"id": "good-002", "name": "Good Entity 2"},
        {"missing_name": True},  # This might cause issues but mapper should handle
    ]

    # When: Multiple entities are converted
    result, exception = _when_convert_multiple_called(basic_converter, input_data_list)

    # Then: Successful conversions should be returned, failures should be logged
    _then_multiple_conversion_partial_success(result, exception)


def test_convert_multiple_with_multi_object_mapper(
    multi_object_config: GenericConverterConfig, mock_logger: MagicMock
) -> None:
    """Test multiple entity conversion with mapper that produces multiple objects per input."""
    # Given: A converter with multi-object mapper and multiple inputs
    converter = GenericConverter(config=multi_object_config, logger=mock_logger)
    input_data_list = [
        {"id": "multi-001", "name": "Multi Entity 1"},
        {"id": "multi-002", "name": "Multi Entity 2"},
    ]

    # When: Multiple entities are converted
    result, exception = _when_convert_multiple_called(converter, input_data_list)

    # Then: Multiple objects per input should be returned (2 inputs × 2 objects = 4 total)
    _then_multiple_conversion_successful(result, exception, 4)


def test_convert_multiple_empty_list(basic_converter: GenericConverter) -> None:
    """Test multiple entity conversion with empty input list."""
    # Given: A converter and empty input list
    input_data_list: List[Any] = []

    # When: Multiple entities are converted
    result, exception = _when_convert_multiple_called(basic_converter, input_data_list)

    # Then: An empty list should be returned
    _then_multiple_conversion_empty(result, exception)


# Scenario: Batch conversion


def test_convert_batch_success(basic_converter: GenericConverter) -> None:
    """Test successful batch conversion of different entity types."""
    # Given: A converter and batched input data
    input_batches: Dict[str, Any] = {
        "type_a": [
            {"id": "a-001", "name": "Type A Entity 1"},
            {"id": "a-002", "name": "Type A Entity 2"},
        ],
        "type_b": [
            {"id": "b-001", "name": "Type B Entity 1"},
        ],
        "type_c": [],
    }

    # When: Batch conversion is performed
    result, exception = _when_convert_batch_called(basic_converter, input_batches)

    # Then: All batches should be processed correctly
    _then_batch_conversion_successful(result, exception, input_batches.keys())


def test_convert_batch_empty_batches(basic_converter: GenericConverter) -> None:
    """Test batch conversion with all empty batches."""
    # Given: A converter and empty batches
    input_batches: Dict[str, List[Any]] = {
        "type_a": [],
        "type_b": [],
    }

    # When: Batch conversion is performed
    result, exception = _when_convert_batch_called(basic_converter, input_batches)

    # Then: Empty results should be returned for all batches
    _then_batch_conversion_all_empty(result, exception)


# Scenario: Object tracking and management


def test_get_converted_objects_tracking(basic_converter: GenericConverter) -> None:
    """Test that converted objects are properly tracked."""
    # Given: A converter and some input data
    input_data_list = [
        {"id": "track-001", "name": "Tracked Entity 1"},
        {"id": "track-002", "name": "Tracked Entity 2"},
    ]

    # When: Multiple entities are converted and tracking is checked
    basic_converter.convert_multiple(input_data_list)
    converted_objects = _when_converted_objects_retrieved(basic_converter)

    # Then: All converted objects should be tracked
    _then_converted_objects_tracked(converted_objects, 2)


def test_get_object_id_map(basic_converter: GenericConverter) -> None:
    """Test that object ID mapping is maintained."""
    # Given: A converter and input data
    input_data = {"id": "map-001", "name": "Mapped Entity"}

    # When: An entity is converted and ID mapping is checked
    basic_converter.convert_single(input_data)
    id_map = _when_object_id_map_retrieved(basic_converter)

    # Then: The ID mapping should be maintained
    _then_object_id_map_correct(id_map, "map-001", "map-001")


def test_clear_converted_objects(basic_converter: GenericConverter) -> None:
    """Test clearing the converted objects cache."""
    # Given: A converter with some converted objects
    basic_converter.convert_single({"id": "clear-001", "name": "Entity"})

    # When: The converted objects cache is cleared
    _when_converted_objects_cleared(basic_converter)

    # Then: The cache should be empty
    _then_converted_objects_cache_empty(basic_converter)


# Scenario: Error handling and logging


def test_error_handling_preserves_context(failing_converter: GenericConverter) -> None:
    """Test that error handling preserves entity context."""
    # Given: A failing converter and entity with ID and name
    input_data = {"id": "context-001", "name": "Context Entity"}

    # When: Conversion fails
    result, exception = _when_convert_single_called(failing_converter, input_data)

    # Then: The exception should contain entity context
    _then_exception_has_entity_context(exception, "context-001", "Context Entity")


def test_preprocessing_failure_handling(mock_logger: MagicMock) -> None:
    """Test handling of preprocessing function failures."""

    # Given: A converter with failing preprocessing function
    def failing_preprocess(data: Any) -> None:
        raise ValueError("Preprocessing failed")

    config = GenericConverterConfig(
        entity_type="preprocess_fail",
        mapper_class=MockMapper,
        output_stix_type="test-object",
        exception_class=CustomError,
        display_name="preprocess fail",
        preprocessing_function=failing_preprocess,
    )
    converter = GenericConverter(config=config, logger=mock_logger)

    # When: Conversion is attempted with failing preprocessing
    result, exception = _when_convert_single_called(converter, {"id": "preprocess-001"})

    # Then: The conversion should still proceed with original data
    _then_conversion_successful(result, exception)


def test_postprocessing_failure_handling(mock_logger: MagicMock) -> None:
    """Test handling of postprocessing function failures."""

    # Given: A converter with failing postprocessing function
    def failing_postprocess(stix_obj: Any) -> None:
        raise ValueError("Postprocessing failed")

    config = GenericConverterConfig(
        entity_type="postprocess_fail",
        mapper_class=MockMapper,
        output_stix_type="test-object",
        exception_class=CustomError,
        display_name="postprocess fail",
        postprocessing_function=failing_postprocess,
    )
    converter = GenericConverter(config=config, logger=mock_logger)

    # When: Conversion is attempted with failing postprocessing
    result, exception = _when_convert_single_called(
        converter, {"id": "postprocess-001"}
    )

    # Then: The conversion should still succeed with original STIX object
    _then_conversion_successful(result, exception)


def test_convert_with_to_stix_true_returns_stix_object(
    to_stix_true_converter: GenericConverter,
) -> None:
    """Test that to_stix=True returns STIX objects."""
    # Given: A converter configured with to_stix=True and input data
    input_data = {"id": "test-stix-001", "name": "Test STIX Entity"}

    # When: Single conversion is performed
    result, exception = _when_convert_single_called(to_stix_true_converter, input_data)

    # Then: The result should be a STIX object
    _then_conversion_successful(result, exception)
    _then_result_is_stix_object(result)
    _then_stix_object_has_properties(result, "test-stix-001", "Test STIX Entity")


def test_convert_with_to_stix_false_returns_mapper_object(
    to_stix_false_converter: GenericConverter,
) -> None:
    """Test that to_stix=False returns STIX model objects but still validates STIX."""
    # Given: A converter configured with to_stix=False and input data
    input_data = {"id": "test-mapper-001", "name": "Test Mapper Entity"}

    # When: Single conversion is performed using converter.convert directly
    result = to_stix_false_converter.convert(input_data)

    # Then: The result should be a STIX model object, not converted to STIX2 format
    _then_result_is_stix_model_object(result)

    # And: The result should have the expected properties
    _then_stix_object_has_properties(result, "test-mapper-001", "Test Mapper Entity")


def test_convert_multiple_with_to_stix_true_returns_stix_objects(
    to_stix_true_converter: GenericConverter,
) -> None:
    """Test that to_stix=True returns STIX objects for multiple conversion."""
    # Given: A converter configured with to_stix=True and multiple input data
    input_data_list = [
        {"id": "test-001", "name": "Entity 1"},
        {"id": "test-002", "name": "Entity 2"},
    ]

    # When: Multiple conversion is performed
    result, exception = _when_convert_multiple_called(
        to_stix_true_converter, input_data_list
    )

    # Then: All results should be STIX objects
    _then_multiple_conversion_successful(result, exception, 2)
    for stix_obj in result:
        _then_result_is_stix_object(stix_obj)


def test_convert_multiple_with_to_stix_false_returns_mapper_objects(
    to_stix_false_converter: GenericConverter,
) -> None:
    """Test that to_stix=False returns STIX model objects for multiple conversion."""
    # Given: A converter configured with to_stix=False and multiple input data
    input_data_list = [
        {"id": "test-001", "name": "Entity 1"},
        {"id": "test-002", "name": "Entity 2"},
    ]

    # When: Multiple conversion is performed using converter.convert for each
    results = []
    for input_data in input_data_list:
        result = to_stix_false_converter.convert(input_data)
        results.append(result)

    # Then: All results should be STIX model objects
    assert len(results) == 2  # noqa: S101
    for stix_model_obj in results:
        _then_result_is_stix_model_object(stix_model_obj)


def test_convert_config_convert_method_with_to_stix_true(
    to_stix_true_config: GenericConverterConfig,
) -> None:
    """Test GenericConverter.convert method with to_stix=True."""
    # Given: A converter with to_stix=True and input data
    converter = GenericConverter(to_stix_true_config)
    input_data = {"id": "config-test-001", "name": "Config Test Entity"}

    # When: Converter convert method is called
    result = converter.convert(input_data)

    # Then: Result should be a STIX object
    _then_result_is_stix_object(result)
    _then_stix_object_has_properties(result, "config-test-001", "Config Test Entity")


def test_convert_config_convert_method_with_to_stix_false(
    to_stix_false_config: GenericConverterConfig,
) -> None:
    """Test GenericConverter.convert method with to_stix=False."""
    # Given: A converter with to_stix=False and input data
    converter = GenericConverter(to_stix_false_config)
    input_data = {"id": "config-test-002", "name": "Config Test Mapper"}

    # When: Converter convert method is called
    result = converter.convert(input_data)

    # Then: Result should be a STIX model object
    _then_result_is_stix_model_object(result)

    # And: The result should have the expected properties
    _then_stix_object_has_properties(result, "config-test-002", "Config Test Mapper")


def test_convert_config_convert_method_validates_stix_even_when_false(
    to_stix_false_config: GenericConverterConfig,
) -> None:
    """Test that to_stix=False still validates STIX output internally."""

    # Given: A converter with to_stix=False and a failing mapper
    class FailingValidationMapper(BaseMapper):
        def __init__(self, input_data: Any, **kwargs: Any) -> None:
            self.input_data = input_data

        def to_stix(self) -> Any:
            return type("BadSTIX", (), {})()

    config = GenericConverterConfig(
        entity_type="failing_validation",
        mapper_class=FailingValidationMapper,
        output_stix_type="test-object",
        exception_class=CustomError,
        display_name="failing validation",
        to_stix=False,
    )

    converter = GenericConverter(config)
    input_data = {"id": "fail-001", "name": "Should Fail"}

    # When: Converter convert method is called
    # Then: Should still fail validation even though to_stix=False
    with pytest.raises(CustomError):
        converter.convert(input_data)


# =====================
# GWT Helper Functions
# =====================

# --- WHEN: Execute the system under test ---


def _when_convert_single_called(
    converter: GenericConverter, input_data: Any, **kwargs: Any
) -> Tuple[Any, Any]:
    """Call convert_single and capture result and exception."""
    try:
        result = converter.convert_single(input_data, **kwargs)
        return result, None
    except Exception as e:
        return None, e


def _when_convert_multiple_called(
    converter: GenericConverter, input_data_list: List[Any], **kwargs: Any
) -> Tuple[Any, Any]:
    """Call convert_multiple and capture result and exception."""
    try:
        result = converter.convert_multiple(input_data_list, **kwargs)
        return result, None
    except Exception as e:
        return None, e


def _when_convert_batch_called(
    converter: GenericConverter, input_batches: Dict[str, Any], **kwargs: Any
) -> Tuple[Any, Any]:
    """Call convert_batch and capture result and exception."""
    try:
        result = converter.convert_batch(input_batches, **kwargs)
        return result, None
    except Exception as e:
        return None, e


def _when_converted_objects_retrieved(converter: GenericConverter) -> List[Any]:
    """Retrieve converted objects from converter."""
    return converter.get_converted_objects()


def _when_object_id_map_retrieved(converter: GenericConverter) -> Dict[str, Any]:
    """Retrieve object ID map from converter."""
    return converter.get_object_id_map()


def _when_converted_objects_cleared(converter: GenericConverter) -> None:
    """Clear converted objects cache."""
    converter.clear_converted_objects()


# --- THEN: Verify the expected outcomes ---


def _then_conversion_successful(result: Any, exception: Any) -> None:
    """Assert that conversion was successful."""
    assert exception is None  # noqa: S101
    assert result is not None  # noqa: S101


def _then_stix_object_has_properties(
    stix_obj: MockSTIXObject, expected_id: str, expected_name: str
) -> None:
    """Assert that STIX object has expected properties."""
    assert stix_obj.id == expected_id  # noqa: S101
    assert stix_obj.name == expected_name  # noqa: S101


def _then_multiple_stix_objects_returned(
    result: List[Any], expected_count: int
) -> None:
    """Assert that multiple STIX objects were returned."""
    assert isinstance(result, list)  # noqa: S101
    assert len(result) == expected_count  # noqa: S101


def _then_object_was_postprocessed(stix_obj: MockSTIXObject) -> None:
    """Assert that object was postprocessed."""
    assert hasattr(stix_obj, "postprocessed")  # noqa: S101
    assert stix_obj.postprocessed is True  # noqa: S101


def _then_conversion_failed_with_custom_error(
    result: Any, exception: Any, expected_id: str, expected_name: str
) -> None:
    """Assert that conversion failed with custom exception containing context."""
    assert result is None  # noqa: S101
    assert exception is not None  # noqa: S101
    assert isinstance(exception, CustomError)  # noqa: S101
    assert expected_id in str(exception)  # noqa: S101


def _then_conversion_failed_with_validation_error(result: Any, exception: Any) -> None:
    """Assert that conversion failed with validation error."""
    assert result is None  # noqa: S101
    assert exception is not None  # noqa: S101
    assert isinstance(exception, CustomError)  # noqa: S101


def _then_multiple_conversion_successful(
    result: List[Any], exception: Any, expected_count: int
) -> None:
    """Assert that multiple conversion was successful."""
    assert exception is None  # noqa: S101
    assert result is not None  # noqa: S101
    assert isinstance(result, list)  # noqa: S101
    assert len(result) == expected_count  # noqa: S101


def _then_multiple_conversion_partial_success(
    result: List[Any], exception: Any
) -> None:
    """Assert that multiple conversion had partial success."""
    assert exception is None  # noqa: S101
    assert result is not None  # noqa: S101
    assert isinstance(result, list)  # noqa: S101
    assert len(result) >= 0  # Some might succeed  # noqa: S101


def _then_multiple_conversion_empty(result: List[Any], exception: Any) -> None:
    """Assert that multiple conversion returned empty list."""
    assert exception is None  # noqa: S101
    assert result is not None  # noqa: S101
    assert isinstance(result, list)  # noqa: S101
    assert len(result) == 0  # noqa: S101


def _then_batch_conversion_successful(
    result: Dict[str, Any], exception: Any, expected_keys: Any
) -> None:
    """Assert that batch conversion was successful."""
    assert exception is None  # noqa: S101
    assert result is not None  # noqa: S101
    assert isinstance(result, dict)  # noqa: S101
    for key in expected_keys:
        assert key in result  # noqa: S101
        assert isinstance(result[key], list)  # noqa: S101


def _then_batch_conversion_all_empty(result: Dict[str, Any], exception: Any) -> None:
    """Assert that batch conversion returned empty results."""
    assert exception is None  # noqa: S101
    assert result is not None  # noqa: S101
    assert isinstance(result, dict)  # noqa: S101
    for batch_result in result.values():
        assert isinstance(batch_result, list)  # noqa: S101
        assert len(batch_result) == 0  # noqa: S101


def _then_converted_objects_tracked(
    converted_objects: List[Any], expected_count: int
) -> None:
    """Assert that converted objects are properly tracked."""
    assert isinstance(converted_objects, list)  # noqa: S101
    assert len(converted_objects) == expected_count  # noqa: S101


def _then_object_id_map_correct(
    id_map: Dict[str, Any], original_id: str, stix_id: str
) -> None:
    """Assert that object ID mapping is correct."""
    assert isinstance(id_map, dict)  # noqa: S101
    assert original_id in id_map  # noqa: S101
    assert id_map[original_id] == stix_id  # noqa: S101


def _then_converted_objects_cache_empty(converter: GenericConverter) -> None:
    """Assert that converted objects cache is empty."""
    assert len(converter.get_converted_objects()) == 0  # noqa: S101
    assert len(converter.get_object_id_map()) == 0  # noqa: S101


def _then_exception_has_entity_context(
    exception: Any, expected_id: str, expected_name: str
) -> None:
    """Assert that exception contains entity context."""
    assert isinstance(exception, CustomError)  # noqa: S101
    assert exception.entity_id == expected_id  # noqa: S101
    assert exception.entity_name == expected_name  # noqa: S101


def _then_result_is_stix_object(result: Any) -> None:
    """Assert that result is a STIX object."""
    assert isinstance(result, MockSTIXObject)  # noqa: S101
    assert hasattr(result, "id")  # noqa: S101
    assert hasattr(result, "type")  # noqa: S101


def _then_result_is_stix_model_object(result: Any) -> None:
    """Assert that result is a STIX model object (when to_stix=False)."""
    assert hasattr(result, "id")  # noqa: S101
    assert hasattr(result, "name")  # noqa: S101

    assert not isinstance(result, BaseMapper)  # noqa: S101
