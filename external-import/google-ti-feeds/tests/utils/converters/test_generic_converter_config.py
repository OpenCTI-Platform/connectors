"""Test module for GenericConverterConfig functionality."""

from typing import Any, Optional, Tuple
from unittest.mock import MagicMock

import pytest
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

    def to_stix(self) -> Any:
        """Convert input data to STIX format."""
        return {"type": "test-object", "id": "test-123", "name": "test"}


class SimpleMapper(BaseMapper):
    """Simple mapper without dependencies."""

    def __init__(self, input_data: Any):
        """Initialize the simple mapper."""
        self.input_data = input_data

    def to_stix(self) -> Any:
        """Convert input data to STIX format."""
        return {"type": "simple-object", "id": "simple-123"}


class FlexibleMapper(BaseMapper):
    """Flexible mapper that can be initialized in different ways."""

    def __init__(self, **kwargs: Any) -> None:
        """Initialize the flexible mapper."""
        self.kwargs = kwargs

    def set_input_data(self, input_data: Any) -> None:
        """Set the input data for the mapper."""
        self.input_data = input_data

    def to_stix(self) -> Any:
        """Convert input data to STIX format."""
        return {"type": "flexible-object", "id": "flex-123"}


class CustomError(Exception):
    """Custom exception for testing."""

    def __init__(
        self,
        message: str,
        entity_id: Optional[str] = None,
        entity_name: Optional[str] = None,
    ):
        """Initialize the custom error."""
        super().__init__(message)
        self.entity_id = entity_id
        self.entity_name = entity_name


class SimpleError(Exception):
    """Simple exception for testing."""

    def __init__(self, message: str):
        """Initialize the simple error."""
        super().__init__(message)
        self.message = message


# =====================
# Fixtures
# =====================


@pytest.fixture
def basic_config() -> GenericConverterConfig:
    """Fixture for basic configuration."""
    return GenericConverterConfig(
        entity_type="test_entities",
        mapper_class=MockMapper,
        output_stix_type="test-object",
        exception_class=CustomError,
        display_name="test entities",
    )


@pytest.fixture
def full_config() -> GenericConverterConfig:
    """Fixture for configuration with all options."""
    return GenericConverterConfig(
        entity_type="full_entities",
        mapper_class=MockMapper,
        output_stix_type="full-object",
        exception_class=CustomError,
        display_name="full entities",
        input_model=UserTestModel,
        display_name_singular="full entity",
        validate_input=True,
        validate_output=True,
        additional_dependencies={"organization": "test-org", "tlp_marking": "amber"},
        id_field="custom_id",
        name_field="custom_name",
        required_attributes=["id", "name"],
        preprocessing_function=lambda x: x,
        postprocessing_function=lambda x: x,
    )


@pytest.fixture
def config_with_plural_display_name() -> GenericConverterConfig:
    """Fixture for configuration with plural display name."""
    return GenericConverterConfig(
        entity_type="categories",
        mapper_class=SimpleMapper,
        output_stix_type="category",
        exception_class=SimpleError,
        display_name="categories",
    )


@pytest.fixture
def config_with_non_plural_display_name() -> GenericConverterConfig:
    """Fixture for configuration with non-plural display name."""
    return GenericConverterConfig(
        entity_type="data",
        mapper_class=SimpleMapper,
        output_stix_type="data-object",
        exception_class=SimpleError,
        display_name="data",
    )


# =====================
# Test Cases
# =====================

# Scenario: Creating basic configuration with required parameters


def test_basic_config_creation_with_required_parameters(
    basic_config: GenericConverterConfig,
) -> None:
    """Test creating configuration with only required parameters."""
    # Given: A basic configuration is created with required parameters
    config = basic_config

    # When: The configuration is inspected
    # Then: All required parameters should be set correctly
    _then_config_has_basic_properties(config)


def test_basic_config_sets_default_values(basic_config: GenericConverterConfig) -> None:
    """Test that basic configuration sets appropriate default values."""
    # Given: A basic configuration is created
    config = basic_config

    # When: Default values are inspected
    # Then: Defaults should be set correctly
    _then_config_has_default_values(config)


# Scenario: Creating full configuration with all parameters


def test_full_config_creation_with_all_parameters(
    full_config: GenericConverterConfig,
) -> None:
    """Test creating configuration with all parameters specified."""
    # Given: A full configuration is created with all parameters
    config = full_config

    # When: The configuration is inspected
    # Then: All parameters should be set correctly
    _then_config_has_full_properties(config)


# Scenario: Auto-generation of singular display names


def test_display_name_singular_auto_generated_from_plural(
    config_with_plural_display_name: GenericConverterConfig,
) -> None:
    """Test automatic generation of singular form from plural display name."""
    # Given: A configuration with a plural display name ending in 's'
    config = config_with_plural_display_name

    # When: The singular display name is inspected
    # Then: It should be automatically generated by removing the 's'
    _then_singular_name_is_auto_generated(config, expected="categorie")


def test_display_name_singular_unchanged_for_non_plural(
    config_with_non_plural_display_name: GenericConverterConfig,
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
    config = GenericConverterConfig(
        entity_type="people",
        mapper_class=SimpleMapper,
        output_stix_type="person",
        exception_class=SimpleError,
        display_name="people",
        display_name_singular="person",
    )

    # When: The singular display name is inspected
    # Then: It should use the explicitly set value
    _then_singular_name_is_explicit(config, expected="person")


# Scenario: Mapper creation with different initialization patterns


def test_create_mapper_with_dependencies() -> None:
    """Test creating mapper with input data and dependencies."""
    # Given: A configuration with additional dependencies
    config = GenericConverterConfig(
        entity_type="test",
        mapper_class=MockMapper,
        output_stix_type="test",
        exception_class=Exception,
        display_name="test",
        additional_dependencies={"organization": "org1", "tlp_marking": "amber"},
    )

    input_data = {"id": "test-001", "name": "Test"}

    # When: A mapper is created
    mapper, exception = _when_mapper_created(config, input_data)

    # Then: The mapper should be created successfully with dependencies
    _then_mapper_created_successfully(mapper, exception, MockMapper)
    _then_mapper_has_dependencies(mapper, "org1", "amber")


def test_create_mapper_with_additional_kwargs() -> None:
    """Test creating mapper with additional runtime dependencies."""
    # Given: A configuration and additional runtime dependencies
    config = GenericConverterConfig(
        entity_type="test",
        mapper_class=MockMapper,
        output_stix_type="test",
        exception_class=Exception,
        display_name="test",
        additional_dependencies={"organization": "org1"},
    )

    input_data = {"id": "test-001"}
    additional_kwargs = {"tlp_marking": "red"}

    # When: A mapper is created with additional kwargs
    mapper, exception = _when_mapper_created(config, input_data, **additional_kwargs)

    # Then: The mapper should have both config and runtime dependencies
    _then_mapper_created_successfully(mapper, exception, MockMapper)
    _then_mapper_has_dependencies(mapper, "org1", "red")


def test_create_mapper_with_flexible_initialization() -> None:
    """Test creating mapper with flexible initialization pattern."""
    # Given: A configuration with a flexible mapper class
    config = GenericConverterConfig(
        entity_type="flexible",
        mapper_class=FlexibleMapper,
        output_stix_type="flexible",
        exception_class=Exception,
        display_name="flexible",
        additional_dependencies={"param1": "value1"},
    )

    input_data = {"id": "flex-001"}

    # When: A mapper is created
    mapper, exception = _when_mapper_created(config, input_data)

    # Then: The mapper should be created using fallback initialization
    _then_mapper_created_successfully(mapper, exception, FlexibleMapper)
    assert hasattr(mapper, "input_data")  # noqa: S101


def test_create_mapper_initialization_failure() -> None:
    """Test mapper creation failure with incompatible class."""

    # Given: A configuration with a mapper class that cannot be initialized
    class BadMapper:
        def __init__(
            self, required_param_that_wont_be_provided: Any, another_required_param: Any
        ) -> None:
            """Initialize the bad mapper."""
            self.param1 = required_param_that_wont_be_provided
            self.param2 = another_required_param

    config = GenericConverterConfig(
        entity_type="bad",
        mapper_class=BadMapper,  # type: ignore[arg-type]
        output_stix_type="bad",
        exception_class=Exception,
        display_name="bad",
    )

    # When: A mapper creation is attempted
    mapper, exception = _when_mapper_created(config, {"id": "bad-001"})

    # Then: A TypeError should be raised
    _then_mapper_creation_failed(mapper, exception, TypeError)


# Scenario: Exception creation with different constructors


def test_create_exception_with_full_parameters() -> None:
    """Test creating exception with all parameters."""
    # Given: A configuration with a custom exception class
    config = GenericConverterConfig(
        entity_type="test",
        mapper_class=MockMapper,
        output_stix_type="test",
        exception_class=CustomError,
        display_name="test",
    )

    # When: An exception is created with all parameters
    exception = _when_exception_created(
        config, "Test error", "entity-001", "TestEntity"
    )

    # Then: The exception should be created with all parameters
    _then_exception_created_with_full_params(
        exception, "Test error", "entity-001", "TestEntity"
    )


def test_create_exception_with_simple_constructor() -> None:
    """Test creating exception with simple message-only constructor."""
    # Given: A configuration with a simple exception class
    config = GenericConverterConfig(
        entity_type="test",
        mapper_class=MockMapper,
        output_stix_type="test",
        exception_class=SimpleError,
        display_name="test",
    )

    # When: An exception is created with additional parameters
    exception = _when_exception_created(
        config, "Test error", "entity-001", "TestEntity"
    )

    # Then: The exception should fall back to message-only constructor
    _then_exception_created_simple(exception, "Test error")


# Scenario: Entity ID and name extraction


def test_get_entity_id_from_object_attribute() -> None:
    """Test extracting entity ID from object attribute."""
    # Given: A configuration and an object with ID attribute
    config = GenericConverterConfig(
        entity_type="test",
        mapper_class=MockMapper,
        output_stix_type="test",
        exception_class=Exception,
        display_name="test",
        id_field="custom_id",
    )

    class MockEntity:
        def __init__(self) -> None:
            self.custom_id = "entity-123"

    entity = MockEntity()

    # When: Entity ID is extracted
    entity_id = _when_entity_id_extracted(config, entity)

    # Then: The correct ID should be returned
    _then_entity_id_correct(entity_id, "entity-123")


def test_get_entity_id_from_dict() -> None:
    """Test extracting entity ID from dictionary."""
    # Given: A configuration and a dictionary with ID field
    config = GenericConverterConfig(
        entity_type="test",
        mapper_class=MockMapper,
        output_stix_type="test",
        exception_class=Exception,
        display_name="test",
        id_field="id",
    )

    entity_data = {"id": "dict-456", "name": "Test"}

    # When: Entity ID is extracted
    entity_id = _when_entity_id_extracted(config, entity_data)

    # Then: The correct ID should be returned
    _then_entity_id_correct(entity_id, "dict-456")


def test_get_entity_id_fallback_to_unknown() -> None:
    """Test entity ID extraction fallback when field is missing."""
    # Given: A configuration and data without the ID field
    config = GenericConverterConfig(
        entity_type="test",
        mapper_class=MockMapper,
        output_stix_type="test",
        exception_class=Exception,
        display_name="test",
        id_field="missing_field",
    )

    entity_data = {"name": "Test"}

    # When: Entity ID is extracted
    entity_id = _when_entity_id_extracted(config, entity_data)

    # Then: It should fallback to "unknown"
    _then_entity_id_correct(entity_id, "unknown")


def test_get_entity_name_from_object() -> None:
    """Test extracting entity name from object."""
    # Given: A configuration with name field and an object with name
    config = GenericConverterConfig(
        entity_type="test",
        mapper_class=MockMapper,
        output_stix_type="test",
        exception_class=Exception,
        display_name="test",
        name_field="display_name",
    )

    class MockEntity:
        def __init__(self) -> None:
            """Initialize the mock entity."""
            self.display_name = "Test Entity"

    entity = MockEntity()

    # When: Entity name is extracted
    entity_name = _when_entity_name_extracted(config, entity)

    # Then: The correct name should be returned
    _then_entity_name_correct(entity_name, "Test Entity")


def test_get_entity_name_returns_none_when_no_field_configured() -> None:
    """Test that entity name returns None when no name field is configured."""
    # Given: A configuration without name field
    config = GenericConverterConfig(
        entity_type="test",
        mapper_class=MockMapper,
        output_stix_type="test",
        exception_class=Exception,
        display_name="test",
        name_field=None,
    )

    entity_data = {"name": "Test"}

    # When: Entity name is extracted
    entity_name = _when_entity_name_extracted(config, entity_data)

    # Then: None should be returned
    _then_entity_name_none(entity_name)


# Scenario: Input data validation


def test_validate_input_data_with_model_success() -> None:
    """Test successful input validation with Pydantic model."""
    # Given: A configuration with input model and valid data
    config = GenericConverterConfig(
        entity_type="test",
        mapper_class=MockMapper,
        output_stix_type="test",
        exception_class=Exception,
        display_name="test",
        input_model=UserTestModel,
    )

    valid_data = UserTestModel(id="test-001", name="Test", description="Test entity")

    # When: Input validation is performed
    exception = _when_input_validated(config, valid_data)

    # Then: Validation should pass without exception
    _then_validation_successful(exception)


def test_validate_input_data_with_model_failure() -> None:
    """Test input validation failure with invalid data."""
    # Given: A configuration with input model and invalid data
    config = GenericConverterConfig(
        entity_type="test",
        mapper_class=MockMapper,
        output_stix_type="test",
        exception_class=Exception,
        display_name="test",
        input_model=UserTestModel,
    )

    invalid_data = {"missing_required_fields": True}

    # When: Input validation is performed
    exception = _when_input_validated(config, invalid_data)

    # Then: Validation should fail with ValueError
    _then_validation_failed(exception, ValueError)


def test_validate_input_data_required_attributes_success() -> None:
    """Test successful validation of required attributes."""
    # Given: A configuration with required attributes and compliant data
    config = GenericConverterConfig(
        entity_type="test",
        mapper_class=MockMapper,
        output_stix_type="test",
        exception_class=Exception,
        display_name="test",
        required_attributes=["id", "name"],
    )

    valid_data = {"id": "test-001", "name": "Test", "extra": "field"}

    # When: Input validation is performed
    exception = _when_input_validated(config, valid_data)

    # Then: Validation should pass
    _then_validation_successful(exception)


def test_validate_input_data_required_attributes_failure() -> None:
    """Test validation failure with missing required attributes."""
    # Given: A configuration with required attributes and non-compliant data
    config = GenericConverterConfig(
        entity_type="test",
        mapper_class=MockMapper,
        output_stix_type="test",
        exception_class=Exception,
        display_name="test",
        required_attributes=["id", "name"],
    )

    invalid_data = {"id": "test-001"}  # Missing 'name'

    # When: Input validation is performed
    exception = _when_input_validated(config, invalid_data)

    # Then: Validation should fail
    _then_validation_failed(exception, ValueError)


def test_validate_input_data_skip_when_disabled() -> None:
    """Test that validation is skipped when disabled."""
    # Given: A configuration with validation disabled
    config = GenericConverterConfig(
        entity_type="test",
        mapper_class=MockMapper,
        output_stix_type="test",
        exception_class=Exception,
        display_name="test",
        input_model=UserTestModel,
        validate_input=False,
    )

    invalid_data = {"invalid": "data"}

    # When: Input validation is performed
    exception = _when_input_validated(config, invalid_data)

    # Then: Validation should be skipped
    _then_validation_successful(exception)


# Scenario: Output data validation


def test_validate_output_data_single_stix_object_success() -> None:
    """Test successful validation of single STIX object."""
    # Given: A configuration and valid STIX object
    config = GenericConverterConfig(
        entity_type="test",
        mapper_class=MockMapper,
        output_stix_type="test",
        exception_class=Exception,
        display_name="test",
    )

    valid_stix = MagicMock()
    valid_stix.type = "test-object"
    valid_stix.id = "test--123"

    # When: Output validation is performed
    exception = _when_output_validated(config, valid_stix)

    # Then: Validation should pass
    _then_validation_successful(exception)


def test_validate_output_data_list_of_stix_objects_success() -> None:
    """Test successful validation of list of STIX objects."""
    # Given: A configuration and valid list of STIX objects
    config = GenericConverterConfig(
        entity_type="test",
        mapper_class=MockMapper,
        output_stix_type="test",
        exception_class=Exception,
        display_name="test",
    )

    stix_obj1 = MagicMock()
    stix_obj1.type = "test-object"
    stix_obj1.id = "test--123"

    stix_obj2 = MagicMock()
    stix_obj2.type = "test-object"
    stix_obj2.id = "test--456"

    valid_stix_list = [stix_obj1, stix_obj2]

    # When: Output validation is performed
    exception = _when_output_validated(config, valid_stix_list)

    # Then: Validation should pass
    _then_validation_successful(exception)


def test_validate_output_data_none_output_failure() -> None:
    """Test validation failure with None output."""
    # Given: A configuration and None output
    config = GenericConverterConfig(
        entity_type="test",
        mapper_class=MockMapper,
        output_stix_type="test",
        exception_class=Exception,
        display_name="test",
    )

    # When: Output validation is performed
    exception = _when_output_validated(config, None)

    # Then: Validation should fail
    _then_validation_failed(exception, ValueError)


def test_validate_output_data_invalid_object_failure() -> None:
    """Test validation failure with invalid STIX object."""
    # Given: A configuration and invalid STIX object (missing ID)
    config = GenericConverterConfig(
        entity_type="test",
        mapper_class=MockMapper,
        output_stix_type="test",
        exception_class=Exception,
        display_name="test",
    )

    invalid_stix = MagicMock()
    invalid_stix.type = "test-object"
    # Missing ID attribute
    del invalid_stix.id

    # When: Output validation is performed
    exception = _when_output_validated(config, invalid_stix)

    # Then: Validation should fail
    _then_validation_failed(exception, ValueError)


def test_validate_output_data_skip_when_disabled() -> None:
    """Test that output validation is skipped when disabled."""
    # Given: A configuration with output validation disabled
    config = GenericConverterConfig(
        entity_type="test",
        mapper_class=MockMapper,
        output_stix_type="test",
        exception_class=Exception,
        display_name="test",
        validate_output=False,
    )

    # When: Output validation is performed with None
    exception = _when_output_validated(config, None)

    # Then: Validation should be skipped
    _then_validation_successful(exception)


# =====================
# GWT Helper Functions
# =====================

# --- WHEN: Execute the system under test ---


def _when_mapper_created(
    config: GenericConverterConfig, input_data: Any, **kwargs: Any
) -> Tuple[Any, Any]:
    """Create mapper and capture result and exception."""
    try:
        mapper = config.create_mapper(input_data, **kwargs)
        return mapper, None
    except Exception as e:
        return None, e


def _when_exception_created(
    config: GenericConverterConfig,
    message: str,
    entity_id: Optional[str] = None,
    entity_name: Optional[str] = None,
) -> Any:
    """Create exception using config's exception factory."""
    return config.create_exception(message, entity_id, entity_name)


def _when_entity_id_extracted(config: GenericConverterConfig, input_data: Any) -> str:
    """Extract entity ID from input data."""
    return config.get_entity_id(input_data)


def _when_entity_name_extracted(
    config: GenericConverterConfig, input_data: Any
) -> Optional[str]:
    """Extract entity name from input data."""
    return config.get_entity_name(input_data)


def _when_input_validated(
    config: GenericConverterConfig, input_data: Any
) -> Optional[Exception]:
    """Validate input data and capture exception."""
    try:
        config.validate_input_data(input_data)
        return None
    except Exception as e:
        return e


def _when_output_validated(
    config: GenericConverterConfig, output_data: Any
) -> Optional[Exception]:
    """Validate output data and capture exception."""
    try:
        config.validate_output_data(output_data)
        return None
    except Exception as e:
        return e


# --- THEN: Verify the expected outcomes ---


def _then_config_has_basic_properties(config: GenericConverterConfig) -> None:
    """Assert that basic configuration properties are set correctly."""
    assert config.entity_type == "test_entities"  # noqa: S101
    assert config.mapper_class == MockMapper  # noqa: S101
    assert config.output_stix_type == "test-object"  # noqa: S101
    assert config.exception_class == CustomError  # noqa: S101
    assert config.display_name == "test entities"  # noqa: S101


def _then_config_has_default_values(config: GenericConverterConfig) -> None:
    """Assert that default values are set correctly."""
    assert config.input_model is None  # noqa: S101
    assert config.display_name_singular == "test entitie"  # noqa: S101
    assert config.validate_input is True  # noqa: S101
    assert config.validate_output is True  # noqa: S101
    assert config.additional_dependencies == {}  # noqa: S101
    assert config.id_field == "id"  # noqa: S101
    assert config.name_field is None  # noqa: S101
    assert config.required_attributes == []  # noqa: S101
    assert config.preprocessing_function is None  # noqa: S101
    assert config.postprocessing_function is None  # noqa: S101


def _then_config_has_full_properties(config: GenericConverterConfig) -> None:
    """Assert that full configuration properties are set correctly."""
    assert config.entity_type == "full_entities"  # noqa: S101
    assert config.mapper_class == MockMapper  # noqa: S101
    assert config.output_stix_type == "full-object"  # noqa: S101
    assert config.exception_class == CustomError  # noqa: S101
    assert config.display_name == "full entities"  # noqa: S101
    assert config.input_model == UserTestModel  # noqa: S101
    assert config.display_name_singular == "full entity"  # noqa: S101
    assert config.validate_input is True  # noqa: S101
    assert config.validate_output is True  # noqa: S101
    assert config.additional_dependencies == {  # noqa: S101
        "organization": "test-org",
        "tlp_marking": "amber",
    }
    assert config.id_field == "custom_id"  # noqa: S101
    assert config.name_field == "custom_name"  # noqa: S101
    assert config.required_attributes == ["id", "name"]  # noqa: S101
    assert config.preprocessing_function is not None  # noqa: S101
    assert config.postprocessing_function is not None  # noqa: S101


def _then_singular_name_is_auto_generated(
    config: GenericConverterConfig, expected: str
) -> None:
    """Assert that singular name was auto-generated correctly."""
    assert config.display_name_singular == expected  # noqa: S101


def _then_singular_name_unchanged(
    config: GenericConverterConfig, expected: str
) -> None:
    """Assert that singular name remained unchanged."""
    assert config.display_name_singular == expected  # noqa: S101


def _then_singular_name_is_explicit(
    config: GenericConverterConfig, expected: str
) -> None:
    """Assert that explicit singular name was used."""
    assert config.display_name_singular == expected  # noqa: S101


def _then_mapper_created_successfully(
    mapper: Any, exception: Any, expected_type: type
) -> None:
    """Assert that mapper was created successfully."""
    assert exception is None  # noqa: S101
    assert mapper is not None  # noqa: S101
    assert isinstance(mapper, expected_type)  # noqa: S101


def _then_mapper_has_dependencies(
    mapper: MockMapper, expected_org: str, expected_tlp: str
) -> None:
    """Assert that mapper has expected dependencies."""
    assert mapper.organization == expected_org  # noqa: S101
    assert mapper.tlp_marking == expected_tlp  # noqa: S101


def _then_mapper_creation_failed(
    mapper: Any, exception: Any, expected_exception_type: type
) -> None:
    """Assert that mapper creation failed with expected exception."""
    assert mapper is None  # noqa: S101
    assert exception is not None  # noqa: S101
    assert isinstance(exception, expected_exception_type)  # noqa: S101


def _then_exception_created_with_full_params(
    exception: Any, expected_message: str, expected_id: str, expected_name: str
) -> None:
    """Assert that exception was created with full parameters."""
    assert isinstance(exception, CustomError)  # noqa: S101
    assert str(exception) == expected_message  # noqa: S101
    assert exception.entity_id == expected_id  # noqa: S101
    assert exception.entity_name == expected_name  # noqa: S101


def _then_exception_created_simple(exception: Any, expected_message: str) -> None:
    """Assert that exception was created with simple constructor."""
    assert isinstance(exception, SimpleError)  # noqa: S101
    assert str(exception) == expected_message  # noqa: S101


def _then_entity_id_correct(entity_id: str, expected: str) -> None:
    """Assert that entity ID extraction was correct."""
    assert entity_id == expected  # noqa: S101


def _then_entity_name_correct(entity_name: Optional[str], expected: str) -> None:
    """Assert that entity name extraction was correct."""
    assert entity_name == expected  # noqa: S101


def _then_entity_name_none(entity_name: Optional[str]) -> None:
    """Assert that entity name is None."""
    assert entity_name is None  # noqa: S101


def _then_validation_successful(exception: Optional[Exception]) -> None:
    """Assert that validation passed without exception."""
    assert exception is None  # noqa: S101


def _then_validation_failed(
    exception: Optional[Exception], expected_exception_type: type
) -> None:
    """Assert that validation failed with expected exception."""
    assert exception is not None  # noqa: S101
    assert isinstance(exception, expected_exception_type)  # noqa: S101
