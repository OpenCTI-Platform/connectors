"""Test module for GenericConverterFactory functionality."""

from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import MagicMock

import pytest
from connector.src.utils.converters.generic_converter import GenericConverter
from connector.src.utils.converters.generic_converter_config import (
    BaseMapper,
    GenericConverterConfig,
)
from connector.src.utils.converters.generic_converter_factory import (
    GenericConverterFactory,
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
            id=f"test--{entity_id}",
            name=entity_name,
        )


class ThreatMapper(BaseMapper):
    """Threat mapper for testing."""

    def __init__(
        self,
        input_data: Any,
        organization: Optional[str] = None,
        tlp_marking: Optional[str] = None,
    ):
        """Initialize the threat mapper."""
        self.input_data = input_data
        self.organization = organization
        self.tlp_marking = tlp_marking

    def to_stix(self) -> MockSTIXObject:
        """Convert the input data to a STIX object."""
        return MockSTIXObject(
            id=f"threat--{self.input_data.get('id', 'unknown')}",
            name=self.input_data.get("name", "Unknown"),
            type="threat-object",
        )


class MalwareMapper(BaseMapper):
    """Malware mapper for testing."""

    def __init__(
        self,
        input_data: Any,
        organization: Optional[str] = None,
        tlp_marking: Optional[str] = None,
    ):
        """Initialize the malware mapper."""
        self.input_data = input_data
        self.organization = organization
        self.tlp_marking = tlp_marking

    def to_stix(self) -> MockSTIXObject:
        """Convert the input data to a STIX object."""
        return MockSTIXObject(
            id=f"malware--{self.input_data.get('id', 'unknown')}",
            name=self.input_data.get("name", "Unknown"),
            type="malware-object",
        )


# =====================
# Test Exceptions
# =====================


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


class ThreatError(Exception):
    """Threat-specific exception for testing."""

    pass


class MalwareError(Exception):
    """Malware-specific exception for testing."""

    pass


# =====================
# Fixtures
# =====================


@pytest.fixture
def mock_logger() -> MagicMock:
    """Fixture for mocked logger."""
    return MagicMock()


@pytest.fixture
def global_dependencies() -> Dict[str, Any]:
    """Fixture for global dependencies."""
    return {
        "organization": "global-org",
        "tlp_marking": "amber",
    }


@pytest.fixture
def threat_config() -> GenericConverterConfig:
    """Fixture for threat converter configuration."""
    return GenericConverterConfig(
        entity_type="threats",
        mapper_class=ThreatMapper,
        output_stix_type="threat-object",
        exception_class=ThreatError,
        display_name="threats",
        input_model=UserTestModel,
    )


@pytest.fixture
def malware_config() -> GenericConverterConfig:
    """Fixture for malware converter configuration."""
    return GenericConverterConfig(
        entity_type="malware",
        mapper_class=MalwareMapper,
        output_stix_type="malware-object",
        exception_class=MalwareError,
        display_name="malware",
        input_model=UserTestModel,
    )


@pytest.fixture
def basic_factory(mock_logger: MagicMock) -> GenericConverterFactory:
    """Fixture for basic factory without global dependencies."""
    return GenericConverterFactory(logger=mock_logger)


@pytest.fixture
def full_factory(
    global_dependencies: Dict[str, Any], mock_logger: MagicMock
) -> GenericConverterFactory:
    """Fixture for factory with global dependencies."""
    return GenericConverterFactory(
        global_dependencies=global_dependencies,
        logger=mock_logger,
    )


@pytest.fixture
def populated_factory(
    full_factory: GenericConverterFactory,
    threat_config: GenericConverterConfig,
    malware_config: GenericConverterConfig,
) -> GenericConverterFactory:
    """Fixture for factory with registered configurations."""
    full_factory.register_config("threats", threat_config)
    full_factory.register_config("malware", malware_config)
    return full_factory


# =====================
# Test Cases
# =====================

# Scenario: Factory initialization and basic operations


def test_factory_initialization_basic(mock_logger: MagicMock) -> None:
    """Test factory initialization with minimal parameters."""
    # Given: Basic factory initialization parameters
    # When: A factory is created with minimal parameters
    factory = GenericConverterFactory(logger=mock_logger)

    # Then: Factory should be initialized with defaults
    _then_factory_initialized_correctly(factory, {}, mock_logger)


def test_factory_initialization_with_global_dependencies(
    global_dependencies: Dict[str, Any], mock_logger: MagicMock
) -> None:
    """Test factory initialization with global dependencies."""
    # Given: Global dependencies and logger
    # When: A factory is created with global dependencies
    factory = GenericConverterFactory(
        global_dependencies=global_dependencies,
        logger=mock_logger,
    )

    # Then: Factory should be initialized with provided values
    _then_factory_initialized_correctly(factory, global_dependencies, mock_logger)


def test_factory_initialization_defaults() -> None:
    """Test factory initialization with all defaults."""
    # Given: No parameters
    # When: A factory is created with defaults
    factory = GenericConverterFactory()

    # Then: Factory should be initialized with default values
    _then_factory_has_defaults(factory)


# Scenario: Configuration registration and retrieval


def test_register_single_config(
    basic_factory: GenericConverterFactory, threat_config: GenericConverterConfig
) -> None:
    """Test registering a single configuration."""
    # Given: A factory and a configuration to register
    config_name = "threats"

    # When: A configuration is registered
    _when_config_registered(basic_factory, config_name, threat_config)

    # Then: The configuration should be registered successfully
    _then_config_registered_successfully(basic_factory, config_name, threat_config)


def test_register_multiple_configs(
    basic_factory: GenericConverterFactory,
    threat_config: GenericConverterConfig,
    malware_config: GenericConverterConfig,
) -> None:
    """Test registering multiple configurations."""
    # Given: A factory and multiple configurations to register
    configs = {"threats": threat_config, "malware": malware_config}

    # When: Multiple configurations are registered
    for name, config in configs.items():
        _when_config_registered(basic_factory, name, config)

    # Then: All configurations should be registered
    _then_multiple_configs_registered(basic_factory, configs)


def test_register_batch_configs(
    basic_factory: GenericConverterFactory,
    threat_config: GenericConverterConfig,
    malware_config: GenericConverterConfig,
) -> None:
    """Test registering multiple configurations at once."""
    # Given: A factory and batch configurations
    configs = {"threats": threat_config, "malware": malware_config}

    # When: Batch configurations are registered
    _when_batch_configs_registered(basic_factory, configs)

    # Then: All configurations should be registered
    _then_multiple_configs_registered(basic_factory, configs)


def test_get_registered_configs(populated_factory: GenericConverterFactory) -> None:
    """Test retrieving all registered configurations."""
    # Given: A factory with registered configurations
    expected_configs = {
        "threats": populated_factory.get_registered_configs()["threats"],
        "malware": populated_factory.get_registered_configs()["malware"],
    }

    # When: Registered configurations are retrieved
    registered_configs = _when_get_registered_configs(populated_factory)

    # Then: All registered configurations should be returned
    _then_configs_retrieved_correctly(registered_configs, expected_configs)


def test_get_available_config_names(populated_factory: GenericConverterFactory) -> None:
    """Test retrieving available configuration names."""
    # Given: A factory with registered configurations
    expected_names = ["threats", "malware"]

    # When: Available configuration names are retrieved
    config_names = _when_get_config_names(populated_factory)

    # Then: Correct configuration names should be returned
    _then_config_names_correct(config_names, expected_names)


# Scenario: Creating converters from configurations


def test_create_converter_with_config(
    basic_factory: GenericConverterFactory, threat_config: GenericConverterConfig
) -> None:
    """Test creating a converter with a configuration object."""
    # Given: A factory and a configuration
    additional_deps = {"custom_dep": "value"}

    # When: A converter is created with the configuration
    converter = _when_converter_created_with_config(
        basic_factory, threat_config, additional_deps
    )

    # Then: The converter should be created successfully
    _then_converter_created_successfully(converter, threat_config)


def test_create_converter_by_name_success(
    populated_factory: GenericConverterFactory,
) -> None:
    """Test creating a converter by registered name."""
    # Given: A factory with registered configurations
    config_name = "threats"
    additional_deps = {"custom_dep": "test"}

    # When: A converter is created by name
    converter, exception = _when_converter_created_by_name(
        populated_factory, config_name, additional_deps
    )

    # Then: The converter should be created successfully
    _then_converter_created_by_name_successfully(converter, exception)


def test_create_converter_by_name_not_found(
    basic_factory: GenericConverterFactory,
) -> None:
    """Test creating a converter by unregistered name."""
    # Given: A factory without registered configurations
    config_name = "nonexistent"

    # When: A converter is created by unregistered name
    converter, exception = _when_converter_created_by_name(basic_factory, config_name)

    # Then: A ValueError should be raised
    _then_converter_creation_failed_not_found(converter, exception, config_name)


def test_create_simple_converter_minimal(
    basic_factory: GenericConverterFactory,
) -> None:
    """Test creating a simple converter with minimal parameters."""
    # Given: A factory and minimal converter parameters
    entity_type = "simple_entities"
    mapper_class = MockMapper
    output_stix_type = "simple-object"
    exception_class = CustomError
    display_name = "simple entities"

    # When: A simple converter is created
    converter = _when_simple_converter_created(
        basic_factory,
        entity_type,
        mapper_class,
        output_stix_type,
        exception_class,
        display_name,
    )

    # Then: The converter should be created with correct configuration
    _then_simple_converter_created_successfully(
        converter, entity_type, output_stix_type
    )


def test_create_simple_converter_with_options(
    basic_factory: GenericConverterFactory,
) -> None:
    """Test creating a simple converter with all parameters."""
    # Given: A factory and complete converter parameters
    params = {
        "entity_type": "advanced_entities",
        "mapper_class": MockMapper,
        "output_stix_type": "advanced-object",
        "exception_class": CustomError,
        "display_name": "advanced entities",
        "input_model": UserTestModel,
    }
    additional_deps = {"advanced_dep": "value"}

    # When: A simple converter is created with all parameters
    converter = _when_simple_converter_created_full(
        basic_factory, params, additional_deps
    )

    # Then: The converter should be created with all specified options
    _then_simple_converter_created_with_options(converter, params)


# Scenario: Creating multiple converters


def test_create_multiple_converters_success(
    populated_factory: GenericConverterFactory,
) -> None:
    """Test creating multiple converters from registered configurations."""
    # Given: A factory with registered configurations
    config_names = ["threats", "malware"]

    # When: Multiple converters are created
    converters, exception = _when_multiple_converters_created(
        populated_factory, config_names
    )

    # Then: All converters should be created successfully
    _then_multiple_converters_created_successfully(converters, exception, config_names)


def test_create_multiple_converters_partial_failure(
    populated_factory: GenericConverterFactory,
) -> None:
    """Test creating multiple converters with some invalid names."""
    # Given: A factory with some registered configurations
    config_names = ["threats", "nonexistent", "malware"]

    # When: Multiple converters are created with invalid name
    converters, exception = _when_multiple_converters_created(
        populated_factory, config_names
    )

    # Then: A ValueError should be raised for missing configuration
    _then_multiple_converters_creation_failed(converters, exception, "nonexistent")


def test_create_all_registered_converters(
    populated_factory: GenericConverterFactory,
) -> None:
    """Test creating converters for all registered configurations."""
    # Given: A factory with registered configurations
    expected_names = ["threats", "malware"]

    # When: Converters for all registered configurations are created
    converters = _when_all_converters_created(populated_factory)

    # Then: Converters should be created for all registered configurations
    _then_all_converters_created_successfully(converters, expected_names)


# Scenario: Conversion pipeline creation


def test_create_conversion_pipeline_success(
    populated_factory: GenericConverterFactory,
) -> None:
    """Test creating a conversion pipeline with registered configurations."""
    # Given: A factory with registered configurations
    converter_names = ["threats", "malware"]
    shared_deps = {"pipeline_dep": "shared"}

    # When: A conversion pipeline is created
    pipeline, exception = _when_conversion_pipeline_created(
        populated_factory, converter_names, shared_deps
    )

    # Then: The pipeline should be created successfully
    _then_conversion_pipeline_created_successfully(pipeline, exception, converter_names)


def test_create_conversion_pipeline_invalid_name(
    populated_factory: GenericConverterFactory,
) -> None:
    """Test creating a conversion pipeline with invalid configuration name."""
    # Given: A factory with some registered configurations
    converter_names = ["threats", "invalid_name"]

    # When: A conversion pipeline is created with invalid name
    pipeline, exception = _when_conversion_pipeline_created(
        populated_factory, converter_names
    )

    # Then: Pipeline creation should fail
    _then_conversion_pipeline_creation_failed(pipeline, exception, "invalid_name")


def test_create_conversion_pipeline_empty_list(
    populated_factory: GenericConverterFactory,
) -> None:
    """Test creating a conversion pipeline with empty converter list."""
    # Given: A factory with registered configurations
    converter_names: List[str] = []

    # When: A conversion pipeline is created with empty list
    pipeline, exception = _when_conversion_pipeline_created(
        populated_factory, converter_names
    )

    # Then: An empty pipeline should be created
    _then_conversion_pipeline_empty(pipeline, exception)


# Scenario: Dependency merging and injection


def test_dependency_merging_global_and_additional(
    global_dependencies: Dict[str, Any], mock_logger: MagicMock
) -> None:
    """Test merging of global and additional dependencies."""
    # Given: A factory with global dependencies
    factory = GenericConverterFactory(
        global_dependencies=global_dependencies,
        logger=mock_logger,
    )

    config = GenericConverterConfig(
        entity_type="test",
        mapper_class=MockMapper,
        output_stix_type="test",
        exception_class=Exception,
        display_name="test",
        additional_dependencies={"config_dep": "config_value"},
    )

    additional_deps = {"runtime_dep": "runtime_value"}

    # When: A converter is created with all dependency levels
    converter = factory.create_converter(config, additional_deps)

    # Then: Dependencies should be properly merged
    _then_dependencies_merged_correctly(
        converter.config,
        global_dependencies,
        {"config_dep": "config_value"},
        additional_deps,
    )


def test_dependency_precedence_order(mock_logger: MagicMock) -> None:
    """Test dependency precedence: global < config < additional."""
    # Given: A factory with overlapping dependencies at different levels
    global_deps = {"shared_key": "global_value", "global_only": "global"}

    factory = GenericConverterFactory(
        global_dependencies=global_deps,
        logger=mock_logger,
    )

    config = GenericConverterConfig(
        entity_type="test",
        mapper_class=MockMapper,
        output_stix_type="test",
        exception_class=Exception,
        display_name="test",
        additional_dependencies={"shared_key": "config_value", "config_only": "config"},
    )

    additional_deps = {
        "shared_key": "additional_value",
        "additional_only": "additional",
    }

    # When: A converter is created with overlapping dependencies
    converter = factory.create_converter(config, additional_deps)

    # Then: Additional dependencies should have highest precedence
    _then_dependency_precedence_correct(
        converter.config,
        {
            "shared_key": "additional_value",  # additional wins
            "global_only": "global",  # only in global
            "config_only": "config",  # only in config
            "additional_only": "additional",  # only in additional
        },
    )


def test_pipeline_shared_dependencies(
    populated_factory: GenericConverterFactory,
) -> None:
    """Test that pipeline shared dependencies are properly applied."""
    # Given: A factory and shared dependencies for pipeline
    converter_names = ["threats", "malware"]
    shared_deps = {"pipeline_org": "pipeline_value"}

    # When: A pipeline is created with shared dependencies
    pipeline, exception = _when_conversion_pipeline_created(
        populated_factory, converter_names, shared_deps
    )

    # Then: All converters in pipeline should have shared dependencies
    _then_pipeline_has_shared_dependencies(pipeline, shared_deps)


# =====================
# GWT Helper Functions
# =====================

# --- WHEN: Execute the system under test ---


def _when_config_registered(
    factory: GenericConverterFactory, name: str, config: GenericConverterConfig
) -> None:
    """Register a configuration with the factory."""
    factory.register_config(name, config)


def _when_batch_configs_registered(
    factory: GenericConverterFactory, configs: Dict[str, GenericConverterConfig]
) -> None:
    """Register batch configurations with the factory."""
    factory.register_batch_configs(configs)


def _when_get_registered_configs(
    factory: GenericConverterFactory,
) -> Dict[str, GenericConverterConfig]:
    """Get all registered configurations."""
    return factory.get_registered_configs()


def _when_get_config_names(factory: GenericConverterFactory) -> List[str]:
    """Get available configuration names."""
    return factory.get_available_config_names()


def _when_converter_created_with_config(
    factory: GenericConverterFactory,
    config: GenericConverterConfig,
    additional_deps: Optional[Dict[str, Any]] = None,
) -> GenericConverter:
    """Create a converter with a configuration."""
    return factory.create_converter(config, additional_deps)


def _when_converter_created_by_name(
    factory: GenericConverterFactory,
    name: str,
    additional_deps: Optional[Dict[str, Any]] = None,
) -> Tuple[Any, Any]:
    """Create a converter by name and capture result and exception."""
    try:
        converter = factory.create_converter_by_name(name, additional_deps)
        return converter, None
    except Exception as e:
        return None, e


def _when_simple_converter_created(
    factory: GenericConverterFactory,
    entity_type: str,
    mapper_class: type,
    output_stix_type: str,
    exception_class: type,
    display_name: str,
) -> GenericConverter:
    """Create a simple converter with minimal parameters."""
    return factory.create_simple_converter(
        entity_type=entity_type,
        mapper_class=mapper_class,
        output_stix_type=output_stix_type,
        exception_class=exception_class,
        display_name=display_name,
    )


def _when_simple_converter_created_full(
    factory: GenericConverterFactory,
    params: Dict[str, Any],
    additional_deps: Optional[Dict[str, Any]] = None,
) -> GenericConverter:
    """Create a simple converter with full parameters."""
    return factory.create_simple_converter(
        additional_dependencies=additional_deps,
        **params,
    )


def _when_multiple_converters_created(
    factory: GenericConverterFactory, config_names: List[str]
) -> Tuple[Any, Any]:
    """Create multiple converters and capture result and exception."""
    try:
        converters = factory.create_multiple_converters(config_names)
        return converters, None
    except Exception as e:
        return None, e


def _when_all_converters_created(
    factory: GenericConverterFactory,
) -> Dict[str, GenericConverter]:
    """Create converters for all registered configurations."""
    return factory.create_all_registered_converters()


def _when_conversion_pipeline_created(
    factory: GenericConverterFactory,
    converter_names: List[str],
    shared_deps: Optional[Dict[str, Any]] = None,
) -> Tuple[Any, Any]:
    """Create conversion pipeline and capture result and exception."""
    try:
        pipeline = factory.create_conversion_pipeline(converter_names, shared_deps)
        return pipeline, None
    except Exception as e:
        return None, e


# --- THEN: Verify the expected outcomes ---


def _then_factory_initialized_correctly(
    factory: GenericConverterFactory,
    expected_global_deps: Dict[str, Any],
    expected_logger: Optional[MagicMock] = None,
) -> None:
    """Assert that factory was initialized correctly."""
    assert factory.global_dependencies == expected_global_deps  # noqa: S101
    if expected_logger:
        assert factory.logger == expected_logger  # noqa: S101
    assert factory._converter_registry == {}  # noqa: S101


def _then_factory_has_defaults(factory: GenericConverterFactory) -> None:
    """Assert that factory has default values."""
    assert factory.global_dependencies == {}  # noqa: S101
    assert factory._converter_registry == {}  # noqa: S101
    assert factory.logger is not None  # noqa: S101


def _then_config_registered_successfully(
    factory: GenericConverterFactory,
    config_name: str,
    expected_config: GenericConverterConfig,
) -> None:
    """Assert that configuration was registered successfully."""
    registered_configs = factory.get_registered_configs()
    assert config_name in registered_configs  # noqa: S101
    assert registered_configs[config_name] == expected_config  # noqa: S101


def _then_multiple_configs_registered(
    factory: GenericConverterFactory,
    expected_configs: Dict[str, GenericConverterConfig],
) -> None:
    """Assert that multiple configurations were registered."""
    registered_configs = factory.get_registered_configs()
    for name, config in expected_configs.items():
        assert name in registered_configs  # noqa: S101
        assert registered_configs[name] == config  # noqa: S101


def _then_configs_retrieved_correctly(
    retrieved_configs: Dict[str, GenericConverterConfig],
    expected_configs: Dict[str, GenericConverterConfig],
) -> None:
    """Assert that configurations were retrieved correctly."""
    assert len(retrieved_configs) == len(expected_configs)  # noqa: S101
    for name, config in expected_configs.items():
        assert name in retrieved_configs  # noqa: S101
        assert retrieved_configs[name] == config  # noqa: S101


def _then_config_names_correct(
    config_names: List[str], expected_names: List[str]
) -> None:
    """Assert that configuration names are correct."""
    assert sorted(config_names) == sorted(expected_names)  # noqa: S101


def _then_converter_created_successfully(
    converter: GenericConverter, expected_config: GenericConverterConfig
) -> None:
    """Assert that converter was created successfully."""
    assert converter is not None  # noqa: S101
    assert isinstance(converter, GenericConverter)  # noqa: S101
    assert converter.config.entity_type == expected_config.entity_type  # noqa: S101


def _then_converter_created_by_name_successfully(
    converter: GenericConverter, exception: Any
) -> None:
    """Assert that converter was created by name successfully."""
    assert exception is None  # noqa: S101
    assert converter is not None  # noqa: S101
    assert isinstance(converter, GenericConverter)  # noqa: S101


def _then_converter_creation_failed_not_found(
    converter: Any, exception: Any, config_name: str
) -> None:
    """Assert that converter creation failed due to not found configuration."""
    assert converter is None  # noqa: S101
    assert exception is not None  # noqa: S101
    assert isinstance(exception, ValueError)  # noqa: S101
    assert config_name in str(exception)  # noqa: S101
    assert "No converter configuration registered" in str(exception)  # noqa: S101


def _then_simple_converter_created_successfully(
    converter: GenericConverter,
    expected_entity_type: str,
    expected_output_type: str,
) -> None:
    """Assert that simple converter was created successfully."""
    assert converter is not None  # noqa: S101
    assert isinstance(converter, GenericConverter)  # noqa: S101
    assert converter.config.entity_type == expected_entity_type  # noqa: S101
    assert converter.config.output_stix_type == expected_output_type  # noqa: S101


def _then_simple_converter_created_with_options(
    converter: GenericConverter, expected_params: Dict[str, Any]
) -> None:
    """Assert that simple converter was created with specified options."""
    assert converter is not None  # noqa: S101
    assert isinstance(converter, GenericConverter)  # noqa: S101
    assert converter.config.entity_type == expected_params["entity_type"]  # noqa: S101
    assert (  # noqa: S101
        converter.config.output_stix_type == expected_params["output_stix_type"]
    )
    assert converter.config.input_model == expected_params["input_model"]  # noqa: S101


def _then_multiple_converters_created_successfully(
    converters: Dict[str, GenericConverter],
    exception: Any,
    expected_names: List[str],
) -> None:
    """Assert that multiple converters were created successfully."""
    assert exception is None  # noqa: S101
    assert converters is not None  # noqa: S101
    assert len(converters) == len(expected_names)  # noqa: S101
    for name in expected_names:
        assert name in converters  # noqa: S101
        assert isinstance(converters[name], GenericConverter)  # noqa: S101


def _then_multiple_converters_creation_failed(
    converters: Any,
    exception: Any,
    invalid_name: str,
) -> None:
    """Assert that multiple converters creation failed due to invalid name."""
    assert converters is None  # noqa: S101
    assert exception is not None  # noqa: S101
    assert isinstance(exception, ValueError)  # noqa: S101
    assert invalid_name in str(exception)  # noqa: S101


def _then_all_converters_created_successfully(
    converters: Dict[str, GenericConverter],
    expected_names: List[str],
) -> None:
    """Assert that all registered converters were created successfully."""
    assert converters is not None  # noqa: S101
    assert len(converters) == len(expected_names)  # noqa: S101
    for name in expected_names:
        assert name in converters  # noqa: S101
        assert isinstance(converters[name], GenericConverter)  # noqa: S101


def _then_conversion_pipeline_created_successfully(
    pipeline: Dict[str, GenericConverter],
    exception: Any,
    expected_names: List[str],
) -> None:
    """Assert that conversion pipeline was created successfully."""
    assert exception is None  # noqa: S101
    assert pipeline is not None  # noqa: S101
    assert len(pipeline) == len(expected_names)  # noqa: S101
    for name in expected_names:
        assert name in pipeline  # noqa: S101
        assert isinstance(pipeline[name], GenericConverter)  # noqa: S101


def _then_conversion_pipeline_creation_failed(
    pipeline: Any,
    exception: Any,
    invalid_name: str,
) -> None:
    """Assert that conversion pipeline creation failed due to invalid name."""
    assert pipeline is None  # noqa: S101
    assert exception is not None  # noqa: S101
    assert isinstance(exception, ValueError)  # noqa: S101
    assert invalid_name in str(exception)  # noqa: S101


def _then_conversion_pipeline_empty(
    pipeline: Dict[str, GenericConverter],
    exception: Any,
) -> None:
    """Assert that conversion pipeline is empty."""
    assert exception is None  # noqa: S101
    assert pipeline is not None  # noqa: S101
    assert len(pipeline) == 0  # noqa: S101


def _then_dependencies_merged_correctly(
    config: GenericConverterConfig,
    global_deps: Dict[str, Any],
    config_deps: Dict[str, Any],
    additional_deps: Dict[str, Any],
) -> None:
    """Assert that dependencies were merged correctly."""
    expected_deps = {**global_deps, **config_deps, **additional_deps}
    assert config.additional_dependencies == expected_deps  # noqa: S101


def _then_dependency_precedence_correct(
    config: GenericConverterConfig,
    expected_deps: Dict[str, Any],
) -> None:
    """Assert that dependency precedence is correct."""
    assert config.additional_dependencies == expected_deps  # noqa: S101


def _then_pipeline_has_shared_dependencies(
    pipeline: Dict[str, GenericConverter],
    shared_deps: Optional[Dict[str, Any]],
) -> None:
    """Assert that pipeline converters have shared dependencies."""
    if shared_deps is not None:
        for converter in pipeline.values():
            for key, value in shared_deps.items():
                additional_deps = converter.config.additional_dependencies
                if additional_deps is not None:
                    assert key in additional_deps  # noqa: S101
                    assert additional_deps[key] == value  # noqa: S101
