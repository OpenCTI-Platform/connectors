"""Test module for GenericFetcherFactory functionality."""

from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import AsyncMock, MagicMock

import pytest
from connector.src.utils.api_engine.api_client import ApiClient
from connector.src.utils.fetchers.generic_fetcher import GenericFetcher
from connector.src.utils.fetchers.generic_fetcher_config import GenericFetcherConfig
from connector.src.utils.fetchers.generic_fetcher_factory import GenericFetcherFactory
from pydantic import BaseModel

# =====================
# Test Models
# =====================


class UserModel(BaseModel):
    """Test user model."""

    id: str
    name: str


class ProductModel(BaseModel):
    """Test product model."""

    id: str
    title: str


# =====================
# Test Exceptions
# =====================


class UserFetchError(Exception):
    """Custom exception for user fetching."""

    def __init__(self, message: str, endpoint: Optional[str] = None):
        """Initialize the UserFetchError.

        Args:
            message (str): The error message.
            endpoint (Optional[str]): The endpoint that caused the error.

        """
        super().__init__(message)
        self.endpoint = endpoint


class ProductFetchError(Exception):
    """Custom exception for product fetching."""

    pass


# =====================
# Fixtures
# =====================


@pytest.fixture
def mock_api_client() -> AsyncMock:
    """Fixture for mocked API client."""
    return AsyncMock(spec=ApiClient)


@pytest.fixture
def mock_logger() -> MagicMock:
    """Fixture for mocked logger."""
    return MagicMock()


@pytest.fixture
def base_headers() -> Dict[str, str]:
    """Fixture for base headers."""
    return {"Authorization": "Bearer token", "User-Agent": "TestAgent"}


@pytest.fixture
def user_config() -> GenericFetcherConfig:
    """Fixture for user fetcher configuration."""
    return GenericFetcherConfig(
        entity_type="users",
        endpoint="/api/users/{entity_id}",
        display_name="users",
        exception_class=UserFetchError,
        response_model=UserModel,
    )


@pytest.fixture
def product_config() -> GenericFetcherConfig:
    """Fixture for product fetcher configuration."""
    return GenericFetcherConfig(
        entity_type="products",
        endpoint="/api/products/{product_id}",
        display_name="products",
        exception_class=ProductFetchError,
        response_model=ProductModel,
        method="POST",
    )


@pytest.fixture
def basic_factory(
    mock_api_client: AsyncMock, mock_logger: MagicMock
) -> GenericFetcherFactory:
    """Fixture for basic factory without base headers."""
    return GenericFetcherFactory(
        api_client=mock_api_client,
        logger=mock_logger,
    )


@pytest.fixture
def full_factory(
    mock_api_client: AsyncMock, base_headers: Dict[str, str], mock_logger: MagicMock
) -> GenericFetcherFactory:
    """Fixture for factory with all dependencies."""
    return GenericFetcherFactory(
        api_client=mock_api_client,
        base_headers=base_headers,
        logger=mock_logger,
    )


@pytest.fixture
def populated_factory(
    full_factory: GenericFetcherFactory,
    user_config: GenericFetcherConfig,
    product_config: GenericFetcherConfig,
) -> GenericFetcherFactory:
    """Fixture for factory with registered configurations."""
    full_factory.register_config("users", user_config)
    full_factory.register_config("products", product_config)
    return full_factory


# =====================
# Test Cases
# =====================

# Scenario: Factory initialization and basic operations


def test_factory_initialization_basic(mock_api_client: AsyncMock) -> None:
    """Test factory initialization with minimal parameters."""
    # Given: Basic factory initialization parameters
    # When: A factory is created with minimal parameters
    factory = GenericFetcherFactory(api_client=mock_api_client)

    # Then: Factory should be initialized with defaults
    _then_factory_initialized_correctly(factory, mock_api_client, {})


def test_factory_initialization_full(
    mock_api_client: AsyncMock, base_headers: Dict[str, str], mock_logger: MagicMock
) -> None:
    """Test factory initialization with all parameters."""
    # Given: Complete factory initialization parameters
    # When: A factory is created with all parameters
    factory = GenericFetcherFactory(
        api_client=mock_api_client,
        base_headers=base_headers,
        logger=mock_logger,
    )

    # Then: Factory should be initialized with provided values
    _then_factory_initialized_correctly(
        factory, mock_api_client, base_headers, mock_logger
    )


# Scenario: Configuration registration and retrieval


def test_register_single_config(
    basic_factory: GenericFetcherFactory, user_config: GenericFetcherConfig
) -> None:
    """Test registering a single configuration."""
    # Given: A factory and a configuration to register
    config_name = "users"

    # When: A configuration is registered
    _when_config_registered(basic_factory, config_name, user_config)

    # Then: The configuration should be stored and retrievable
    _then_config_registered_successfully(basic_factory, config_name, user_config)


def test_register_multiple_configs(
    basic_factory: GenericFetcherFactory,
    user_config: GenericFetcherConfig,
    product_config: GenericFetcherConfig,
) -> None:
    """Test registering multiple configurations."""
    # Given: A factory and multiple configurations to register
    configs = {"users": user_config, "products": product_config}

    # When: Multiple configurations are registered
    for name, config in configs.items():
        _when_config_registered(basic_factory, name, config)

    # Then: All configurations should be stored and retrievable
    _then_multiple_configs_registered(basic_factory, configs)


def test_get_registered_configs(
    populated_factory: GenericFetcherFactory,
    user_config: GenericFetcherConfig,
    product_config: GenericFetcherConfig,
) -> None:
    """Test retrieving all registered configurations."""
    # Given: A factory with registered configurations
    expected_configs = {"users": user_config, "products": product_config}

    # When: All registered configurations are retrieved
    registered_configs = _when_get_registered_configs(populated_factory)

    # Then: All configurations should be returned
    _then_configs_retrieved_correctly(registered_configs, expected_configs)


def test_get_available_config_names(populated_factory: GenericFetcherFactory) -> None:
    """Test retrieving available configuration names."""
    # Given: A factory with registered configurations
    expected_names = ["users", "products"]

    # When: Available configuration names are retrieved
    config_names = _when_get_config_names(populated_factory)

    # Then: Correct configuration names should be returned
    _then_config_names_correct(config_names, expected_names)


# Scenario: Creating fetchers from configurations


def test_create_fetcher_with_config(
    full_factory: GenericFetcherFactory, user_config: GenericFetcherConfig
) -> None:
    """Test creating a fetcher with a configuration object."""
    # Given: A factory and a configuration
    additional_headers = {"X-Custom": "value"}

    # When: A fetcher is created with the configuration
    fetcher = _when_fetcher_created_with_config(
        full_factory, user_config, additional_headers
    )

    # Then: The fetcher should be created correctly
    _then_fetcher_created_successfully(fetcher, user_config)


def test_create_fetcher_by_name_success(
    populated_factory: GenericFetcherFactory,
) -> None:
    """Test creating a fetcher by registered name."""
    # Given: A factory with registered configurations
    config_name = "users"
    additional_headers = {"X-Test": "test"}

    # When: A fetcher is created by name
    fetcher, exception = _when_fetcher_created_by_name(
        populated_factory, config_name, additional_headers
    )

    # Then: The fetcher should be created successfully
    _then_fetcher_created_by_name_successfully(fetcher, exception)


def test_create_fetcher_by_name_not_found(basic_factory: GenericFetcherFactory) -> None:
    """Test creating a fetcher by unregistered name."""
    # Given: A factory without registered configurations
    config_name = "nonexistent"

    # When: A fetcher is created by unregistered name
    fetcher, exception = _when_fetcher_created_by_name(basic_factory, config_name)

    # Then: A ValueError should be raised
    _then_fetcher_creation_failed_not_found(fetcher, exception, config_name)


def test_create_simple_fetcher_minimal(basic_factory: GenericFetcherFactory) -> None:
    """Test creating a simple fetcher with minimal parameters."""
    # Given: A factory and minimal fetcher parameters
    entity_type = "test_entities"
    endpoint = "/api/test/{id}"
    display_name = "test entities"
    exception_class = Exception

    # When: A simple fetcher is created
    fetcher = _when_simple_fetcher_created(
        basic_factory, entity_type, endpoint, display_name, exception_class
    )

    # Then: The fetcher should be created with correct configuration
    _then_simple_fetcher_created_successfully(fetcher, entity_type, endpoint)


def test_create_simple_fetcher_full(basic_factory: GenericFetcherFactory) -> None:
    """Test creating a simple fetcher with all parameters."""
    # Given: A factory and complete fetcher parameters
    params: Dict[str, Any] = {
        "entity_type": "advanced_entities",
        "endpoint": "/api/advanced/{id}",
        "display_name": "advanced entities",
        "exception_class": UserFetchError,
        "response_model": UserModel,
        "method": "PUT",
        "timeout": 45.0,
    }
    additional_headers = {"X-Advanced": "true"}

    # When: A simple fetcher is created with all parameters
    fetcher = _when_simple_fetcher_created_full(
        basic_factory, params, additional_headers
    )

    # Then: The fetcher should be created with all specified options
    _then_simple_fetcher_created_with_options(fetcher, params)


# Scenario: Creating multiple fetchers


def test_create_multiple_fetchers_success(
    populated_factory: GenericFetcherFactory,
) -> None:
    """Test creating multiple fetchers from registered configurations."""
    # Given: A factory with registered configurations
    config_names = ["users", "products"]

    # When: Multiple fetchers are created
    fetchers, exception = _when_multiple_fetchers_created(
        populated_factory, config_names
    )

    # Then: All fetchers should be created successfully
    _then_multiple_fetchers_created_successfully(fetchers, exception, config_names)


def test_create_multiple_fetchers_partial_failure(
    populated_factory: GenericFetcherFactory,
) -> None:
    """Test creating multiple fetchers with some invalid names."""
    # Given: A factory with some registered configurations
    config_names = ["users", "nonexistent", "products"]

    # When: Multiple fetchers are created with invalid name
    fetchers, exception = _when_multiple_fetchers_created(
        populated_factory, config_names
    )

    # Then: A ValueError should be raised for the invalid name
    _then_multiple_fetchers_creation_failed(fetchers, exception, "nonexistent")


def test_create_all_registered_fetchers(
    populated_factory: GenericFetcherFactory,
) -> None:
    """Test creating fetchers for all registered configurations."""
    # Given: A factory with registered configurations
    expected_names = ["users", "products"]

    # When: Fetchers for all registered configurations are created
    fetchers = _when_all_fetchers_created(populated_factory)

    # Then: Fetchers should be created for all registered configurations
    _then_all_fetchers_created_successfully(fetchers, expected_names)


# Scenario: Header merging in factory-created fetchers


def test_header_merging_in_created_fetchers(
    mock_api_client: AsyncMock, mock_logger: MagicMock
) -> None:
    """Test that headers are properly merged in factory-created fetchers."""
    # Given: A factory with base headers and config with headers
    base_headers = {"Authorization": "Bearer token"}
    config_headers = {"Content-Type": "application/json"}
    additional_headers = {"X-Request-ID": "12345"}

    factory = GenericFetcherFactory(
        api_client=mock_api_client,
        base_headers=base_headers,
        logger=mock_logger,
    )

    config = GenericFetcherConfig(
        entity_type="test",
        endpoint="/api/test",
        display_name="test",
        exception_class=Exception,
        headers=config_headers,
    )

    # When: A fetcher is created with additional headers
    fetcher = factory.create_fetcher(config, additional_headers)

    # Then: All headers should be properly merged
    expected_headers = {
        "Authorization": "Bearer token",
        "Content-Type": "application/json",
        "X-Request-ID": "12345",
    }
    _then_fetcher_headers_merged_correctly(fetcher, expected_headers)


def test_header_precedence_in_factory(mock_api_client: AsyncMock) -> None:
    """Test header precedence: base < additional < config."""
    # Given: A factory with overlapping headers at different levels
    base_headers = {"Authorization": "Bearer base", "X-Source": "base"}
    additional_headers = {"Authorization": "Bearer additional", "X-Level": "additional"}
    config_headers = {"X-Source": "config"}

    factory = GenericFetcherFactory(
        api_client=mock_api_client,
        base_headers=base_headers,
    )

    config = GenericFetcherConfig(
        entity_type="test",
        endpoint="/api/test",
        display_name="test",
        exception_class=Exception,
        headers=config_headers,
    )

    # When: A fetcher is created with all header levels
    fetcher = factory.create_fetcher(config, additional_headers)

    # Then: Config headers should have highest precedence
    expected_headers = {
        "Authorization": "Bearer additional",  # additional overrides base
        "X-Source": "config",  # config overrides base
        "X-Level": "additional",  # only in additional
    }
    _then_fetcher_headers_merged_correctly(fetcher, expected_headers)


# =====================
# GWT Helper Functions
# =====================

# --- GIVEN: Setup conditions (covered by fixtures) ---

# --- WHEN: Execute the system under test ---


def _when_config_registered(
    factory: GenericFetcherFactory, name: str, config: GenericFetcherConfig
) -> None:
    """Register a configuration with the factory."""
    factory.register_config(name, config)


def _when_get_registered_configs(
    factory: GenericFetcherFactory,
) -> Dict[str, GenericFetcherConfig]:
    """Get all registered configurations."""
    return factory.get_registered_configs()


def _when_get_config_names(factory: GenericFetcherFactory) -> List[str]:
    """Get available configuration names."""
    return factory.get_available_config_names()


def _when_fetcher_created_with_config(
    factory: GenericFetcherFactory,
    config: GenericFetcherConfig,
    additional_headers: Optional[Dict[str, str]] = None,
) -> GenericFetcher:
    """Create a fetcher with a configuration."""
    return factory.create_fetcher(config, additional_headers)


def _when_fetcher_created_by_name(
    factory: GenericFetcherFactory,
    name: str,
    additional_headers: Optional[Dict[str, str]] = None,
) -> Tuple[Optional[GenericFetcher], Optional[Exception]]:
    """Create a fetcher by configuration name."""
    try:
        fetcher = factory.create_fetcher_by_name(name, additional_headers)
        return fetcher, None
    except Exception as e:
        return None, e


def _when_simple_fetcher_created(
    factory: GenericFetcherFactory,
    entity_type: str,
    endpoint: str,
    display_name: str,
    exception_class: type,
    additional_headers: Optional[Dict[str, str]] = None,
) -> GenericFetcher:
    """Create a simple fetcher."""
    return factory.create_simple_fetcher(
        entity_type=entity_type,
        endpoint=endpoint,
        display_name=display_name,
        exception_class=exception_class,
        additional_headers=additional_headers,
    )


def _when_simple_fetcher_created_full(
    factory: GenericFetcherFactory,
    params: Dict[str, Any],
    additional_headers: Optional[Dict[str, str]] = None,
) -> GenericFetcher:
    """Create a simple fetcher with full parameters."""
    return factory.create_simple_fetcher(
        additional_headers=additional_headers, **params
    )


def _when_multiple_fetchers_created(
    factory: GenericFetcherFactory, config_names: List[str]
) -> Tuple[Optional[Dict[str, GenericFetcher]], Optional[Exception]]:
    """Create multiple fetchers by configuration names."""
    try:
        fetchers = factory.create_multiple_fetchers(config_names)
        return fetchers, None
    except Exception as e:
        return None, e


def _when_all_fetchers_created(
    factory: GenericFetcherFactory,
) -> Dict[str, GenericFetcher]:
    """Create fetchers for all registered configurations."""
    return factory.create_all_registered_fetchers()


# --- THEN: Verify the outcomes ---


def _then_factory_initialized_correctly(
    factory: GenericFetcherFactory,
    expected_api_client: AsyncMock,
    expected_base_headers: Dict[str, str],
    expected_logger: Optional[MagicMock] = None,
) -> None:
    """Verify factory is initialized correctly."""
    assert factory.api_client == expected_api_client  # noqa: S101
    assert factory.base_headers == expected_base_headers  # noqa: S101
    if expected_logger:
        assert factory.logger == expected_logger  # noqa: S101


def _then_config_registered_successfully(
    factory: GenericFetcherFactory,
    config_name: str,
    expected_config: GenericFetcherConfig,
) -> None:
    """Verify configuration is registered successfully."""
    registered_configs = factory.get_registered_configs()
    assert config_name in registered_configs  # noqa: S101
    assert registered_configs[config_name] == expected_config  # noqa: S101


def _then_multiple_configs_registered(
    factory: GenericFetcherFactory, expected_configs: Dict[str, GenericFetcherConfig]
) -> None:
    """Verify multiple configurations are registered."""
    registered_configs = factory.get_registered_configs()
    for name, config in expected_configs.items():
        assert name in registered_configs  # noqa: S101
        assert registered_configs[name] == config  # noqa: S101


def _then_configs_retrieved_correctly(
    retrieved_configs: Dict[str, GenericFetcherConfig],
    expected_configs: Dict[str, GenericFetcherConfig],
) -> None:
    """Verify configurations are retrieved correctly."""
    assert retrieved_configs == expected_configs  # noqa: S101


def _then_config_names_correct(
    config_names: List[str], expected_names: List[str]
) -> None:
    """Verify configuration names are correct."""
    assert sorted(config_names) == sorted(expected_names)  # noqa: S101


def _then_fetcher_created_successfully(
    fetcher: GenericFetcher, expected_config: GenericFetcherConfig
) -> None:
    """Verify fetcher is created successfully."""
    assert fetcher is not None  # noqa: S101
    assert fetcher.config == expected_config  # noqa: S101


def _then_fetcher_created_by_name_successfully(
    fetcher: Optional[GenericFetcher], exception: Optional[Exception]
) -> None:
    """Verify fetcher is created by name successfully."""
    assert fetcher is not None  # noqa: S101
    assert exception is None  # noqa: S101


def _then_fetcher_creation_failed_not_found(
    fetcher: Optional[GenericFetcher], exception: Optional[Exception], config_name: str
) -> None:
    """Verify fetcher creation failed with not found error."""
    assert fetcher is None  # noqa: S101
    assert exception is not None  # noqa: S101
    assert isinstance(exception, ValueError)  # noqa: S101
    assert config_name in str(exception)  # noqa: S101


def _then_simple_fetcher_created_successfully(
    fetcher: GenericFetcher, entity_type: str, endpoint: str
) -> None:
    """Verify simple fetcher is created successfully."""
    assert fetcher is not None  # noqa: S101
    assert fetcher.config.entity_type == entity_type  # noqa: S101
    assert fetcher.config.endpoint == endpoint  # noqa: S101


def _then_simple_fetcher_created_with_options(
    fetcher: GenericFetcher, expected_params: Dict[str, Any]
) -> None:
    """Verify simple fetcher is created with all options."""
    assert fetcher is not None  # noqa: S101
    assert fetcher.config.entity_type == expected_params["entity_type"]  # noqa: S101
    assert fetcher.config.endpoint == expected_params["endpoint"]  # noqa: S101
    assert fetcher.config.display_name == expected_params["display_name"]  # noqa: S101
    assert (  # noqa: S101
        fetcher.config.exception_class == expected_params["exception_class"]
    )


def _then_multiple_fetchers_created_successfully(
    fetchers: Optional[Dict[str, GenericFetcher]],
    exception: Optional[Exception],
    expected_config_names: List[str],
) -> None:
    """Verify multiple fetchers are created successfully."""
    assert fetchers is not None  # noqa: S101
    assert exception is None  # noqa: S101
    assert len(fetchers) == len(expected_config_names)  # noqa: S101
    for name in expected_config_names:
        assert name in fetchers  # noqa: S101
        assert fetchers[name] is not None  # noqa: S101


def _then_multiple_fetchers_creation_failed(
    fetchers: Optional[Dict[str, GenericFetcher]],
    exception: Optional[Exception],
    invalid_name: str,
) -> None:
    """Verify multiple fetchers creation failed."""
    assert fetchers is None  # noqa: S101
    assert exception is not None  # noqa: S101
    assert isinstance(exception, ValueError)  # noqa: S101
    assert invalid_name in str(exception)  # noqa: S101


def _then_all_fetchers_created_successfully(
    fetchers: Dict[str, GenericFetcher], expected_config_names: List[str]
) -> None:
    """Verify all fetchers are created successfully."""
    assert len(fetchers) == len(expected_config_names)  # noqa: S101
    for name in expected_config_names:
        assert name in fetchers  # noqa: S101
        assert fetchers[name] is not None  # noqa: S101


def _then_fetcher_headers_merged_correctly(
    fetcher: GenericFetcher, expected_headers: Dict[str, str]
) -> None:
    """Verify fetcher headers are merged correctly."""
    assert fetcher.headers == expected_headers  # noqa: S101
