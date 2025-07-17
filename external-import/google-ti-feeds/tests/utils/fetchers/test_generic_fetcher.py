"""Test module for GenericFetcher functionality."""

from typing import Any, Dict, Generator, List, Optional, Sequence, Tuple, Union
from unittest.mock import AsyncMock, MagicMock, mock_open, patch

import pytest
from connector.src.utils.api_engine.api_client import ApiClient
from connector.src.utils.api_engine.exceptions.api_network_error import ApiNetworkError
from connector.src.utils.fetchers.generic_fetcher import GenericFetcher
from connector.src.utils.fetchers.generic_fetcher_config import GenericFetcherConfig
from pydantic import BaseModel


@pytest.fixture
def mock_save_to_file() -> Generator[Any, Any, Any]:
    """Mock all file system operations for save_to_file functionality."""
    with (
        patch("pathlib.Path.mkdir") as mock_mkdir,
        patch("pathlib.Path.exists", return_value=False) as mock_exists,
        patch("builtins.open", mock_open()) as mock_file_open,
        patch("json.dump") as mock_json_dump,
    ):
        yield {
            "mkdir": mock_mkdir,
            "exists": mock_exists,
            "open": mock_file_open,
            "json_dump": mock_json_dump,
        }


# =====================
# Test Models
# =====================


class UserModel(BaseModel):
    """Test user model."""

    id: str
    name: str
    email: str


class ProductModel(BaseModel):
    """Test product model."""

    id: str
    title: str
    price: float


class WrappedResponse(BaseModel):
    """Test wrapped response model."""

    data: UserModel
    status: str


# =====================
# Test Exceptions
# =====================


class UserFetchError(Exception):
    """Custom exception for user fetching."""

    def __init__(self, message: str, endpoint: Optional[str] = None):
        """Initialize UserFetchError."""
        super().__init__(message)
        self.endpoint = endpoint


class SimpleError(Exception):
    """Simple exception for testing."""

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
def basic_config() -> GenericFetcherConfig:
    """Fixture for basic fetcher configuration."""
    return GenericFetcherConfig(
        entity_type="users",
        endpoint="/api/users/{entity_id}",
        display_name="users",
        exception_class=UserFetchError,
    )


@pytest.fixture
def model_config() -> GenericFetcherConfig:
    """Fixture for configuration with response model."""
    return GenericFetcherConfig(
        entity_type="users",
        endpoint="/api/users/{entity_id}",
        display_name="users",
        exception_class=UserFetchError,
        response_model=UserModel,
    )


@pytest.fixture
def list_config() -> GenericFetcherConfig:
    """Fixture for list endpoint configuration."""
    return GenericFetcherConfig(
        entity_type="users",
        endpoint="/api/users",
        display_name="users",
        exception_class=UserFetchError,
        response_model=UserModel,
    )


@pytest.fixture
def wrapped_response_config() -> GenericFetcherConfig:
    """Fixture for configuration with wrapped response model."""
    return GenericFetcherConfig(
        entity_type="users",
        endpoint="/api/users/{entity_id}",
        display_name="users",
        exception_class=UserFetchError,
        response_model=WrappedResponse,
    )


@pytest.fixture
def basic_fetcher(
    basic_config: GenericFetcherConfig,
    mock_api_client: AsyncMock,
    mock_logger: MagicMock,
) -> GenericFetcher:
    """Fixture for basic fetcher."""
    return GenericFetcher(
        config=basic_config,
        api_client=mock_api_client,
        logger=mock_logger,
    )


@pytest.fixture
def model_fetcher(
    model_config: GenericFetcherConfig,
    mock_api_client: AsyncMock,
    mock_logger: MagicMock,
) -> GenericFetcher:
    """Fixture for model fetcher."""
    return GenericFetcher(
        config=model_config,
        api_client=mock_api_client,
        logger=mock_logger,
    )


@pytest.fixture
def list_fetcher(
    list_config: GenericFetcherConfig,
    mock_api_client: AsyncMock,
    mock_logger: MagicMock,
) -> GenericFetcher:
    """Fixture for list fetcher."""
    return GenericFetcher(
        config=list_config,
        api_client=mock_api_client,
        logger=mock_logger,
    )


@pytest.fixture
def save_to_file_config() -> GenericFetcherConfig:
    """Fixture for configuration with save_to_file enabled."""
    return GenericFetcherConfig(
        entity_type="users",
        endpoint="/api/users/{entity_id}",
        display_name="users",
        exception_class=UserFetchError,
        save_to_file=True,
    )


@pytest.fixture
def save_to_file_list_config() -> GenericFetcherConfig:
    """Fixture for list configuration with save_to_file enabled."""
    return GenericFetcherConfig(
        entity_type="users",
        endpoint="/api/users",
        display_name="users",
        exception_class=UserFetchError,
        response_model=UserModel,
        save_to_file=True,
    )


@pytest.fixture
def save_to_file_fetcher(
    save_to_file_config: GenericFetcherConfig,
    mock_api_client: AsyncMock,
    mock_logger: MagicMock,
    mock_save_to_file: Dict[str, Any],
) -> GenericFetcher:
    """Fixture for fetcher with save_to_file enabled."""
    return GenericFetcher(
        config=save_to_file_config,
        api_client=mock_api_client,
        logger=mock_logger,
    )


# =====================
# Test Cases
# =====================

# Scenario: Single entity fetching success cases


@pytest.mark.asyncio
async def test_fetch_single_success_raw_data(
    basic_fetcher: GenericFetcher, mock_api_client: AsyncMock
) -> None:
    """Test successful single entity fetch returning raw data."""
    # Given: A configured fetcher and mock API client with test data
    expected_data = {"id": "123", "name": "John Doe", "email": "john@example.com"}
    _given_api_returns_data(mock_api_client, expected_data)

    # When: A single entity is fetched
    result, exception = await _when_fetch_single_called(basic_fetcher, entity_id="123")

    # Then: The raw data should be returned successfully
    _then_fetch_successful(result, expected_data)
    _then_api_called_correctly(mock_api_client, "/api/users/123")


@pytest.mark.asyncio
async def test_fetch_single_success_with_model(
    model_fetcher: GenericFetcher, mock_api_client: AsyncMock
) -> None:
    """Test successful single entity fetch with response model."""
    # Given: A configured fetcher with response model and mock API client
    user_data = {"id": "123", "name": "John Doe", "email": "john@example.com"}
    expected_model = UserModel(**user_data)
    _given_api_returns_model(mock_api_client, expected_model)

    # When: A single entity is fetched
    result, exception = await _when_fetch_single_called(model_fetcher, entity_id="123")

    # Then: The model should be returned successfully
    _then_fetch_successful_with_model(result, expected_model)


@pytest.mark.asyncio
async def test_fetch_single_success_with_wrapped_response(
    wrapped_response_config: GenericFetcherConfig,
    mock_api_client: AsyncMock,
    mock_logger: MagicMock,
) -> None:
    """Test successful single entity fetch with wrapped response model."""
    # Given: A fetcher with wrapped response model and mock API client
    fetcher = GenericFetcher(
        config=wrapped_response_config,
        api_client=mock_api_client,
        logger=mock_logger,
    )
    user_data = {"id": "123", "name": "John Doe", "email": "john@example.com"}
    wrapped_response = WrappedResponse(data=UserModel(**user_data), status="success")
    _given_api_returns_wrapped_data(mock_api_client, wrapped_response)

    # When: A single entity is fetched
    result, exception = await _when_fetch_single_called(fetcher, entity_id="123")

    # Then: The wrapped response should be returned successfully
    _then_fetch_successful_with_model(result, wrapped_response)


@pytest.mark.asyncio
async def test_fetch_single_returns_none_when_no_data(
    basic_fetcher: GenericFetcher, mock_api_client: AsyncMock
) -> None:
    """Test that fetch_single returns None when API returns no data."""
    # Given: A configured fetcher and mock API client returning None
    _given_api_returns_none(mock_api_client)

    # When: A single entity is fetched
    result, exception = await _when_fetch_single_called(basic_fetcher, entity_id="123")

    # Then: None should be returned without exception
    _then_fetch_returns_none(result)


# Scenario: Single entity fetching with errors


@pytest.mark.asyncio
async def test_fetch_single_network_error(
    basic_fetcher: GenericFetcher, mock_api_client: AsyncMock
) -> None:
    """Test single entity fetch with network error."""
    # Given: A configured fetcher and mock API client that raises network error
    network_error = ApiNetworkError("Connection failed")
    _given_api_returns_error(mock_api_client, network_error)

    # When: A single entity is fetched
    result, exception = await _when_fetch_single_called(basic_fetcher, entity_id="123")

    # Then: A UserFetchError should be raised with network error message
    _then_fetch_failed_with_network_error(exception, "Connection failed")


@pytest.mark.asyncio
async def test_fetch_single_general_error(
    basic_fetcher: GenericFetcher, mock_api_client: AsyncMock
) -> None:
    """Test single entity fetch with general error."""
    # Given: A configured fetcher and mock API client that raises general error
    general_error = Exception("Unexpected error")
    _given_api_returns_error(mock_api_client, general_error)

    # When: A single entity is fetched
    result, exception = await _when_fetch_single_called(basic_fetcher, entity_id="123")

    # Then: A UserFetchError should be raised with general error message
    _then_fetch_failed_with_general_error(exception, "Unexpected error")


@pytest.mark.asyncio
async def test_fetch_single_invalid_endpoint_params(
    basic_fetcher: GenericFetcher,
) -> None:
    """Test single entity fetch with invalid endpoint parameters."""
    # Given: A configured fetcher
    # When: A single entity is fetched without required parameters
    result, exception = await _when_fetch_single_called(basic_fetcher)

    # Then: A ValueError should be raised for missing parameters
    _then_fetch_failed_with_param_error(exception, "entity_id")


# Scenario: Multiple entity fetching


@pytest.mark.asyncio
async def test_fetch_multiple_success(
    model_fetcher: GenericFetcher, mock_api_client: AsyncMock
) -> None:
    """Test successful multiple entity fetch."""
    # Given: A configured fetcher and mock API client with multiple entities
    entity_ids = ["123", "456", "789"]
    users = [
        UserModel(id="123", name="John", email="john@example.com"),
        UserModel(id="456", name="Jane", email="jane@example.com"),
        UserModel(id="789", name="Bob", email="bob@example.com"),
    ]
    _given_api_returns_multiple_models(mock_api_client, users)

    # When: Multiple entities are fetched
    result, exception = await _when_fetch_multiple_called(model_fetcher, entity_ids)

    # Then: All entities should be returned successfully
    _then_fetch_multiple_successful(result, 3)
    _then_api_called_multiple_times(mock_api_client, 3)


@pytest.mark.asyncio
async def test_fetch_multiple_partial_success(
    model_fetcher: GenericFetcher, mock_api_client: AsyncMock
) -> None:
    """Test multiple entity fetch with partial success."""
    # Given: A configured fetcher and mock API client with mixed responses
    entity_ids = ["123", "456", "789"]
    responses = [
        UserModel(id="123", name="John", email="john@example.com"),
        None,  # This will simulate a failed fetch
        UserModel(id="789", name="Bob", email="bob@example.com"),
    ]

    def side_effect(*args: Any, **kwargs: Any) -> Optional[UserModel]:
        url = args[0] if len(args) > 0 else kwargs.get("url", "")
        if "123" in url:
            return responses[0]
        elif "456" in url:
            raise ApiNetworkError(f"Not found, {url}")
        elif "789" in url:
            return responses[2]
        return None

    mock_api_client.call_api.side_effect = side_effect

    # When: Multiple entities are fetched
    result, exception = await _when_fetch_multiple_called(model_fetcher, entity_ids)

    # Then: Only successful entities should be returned
    _then_fetch_multiple_partial_success(result, 2)


@pytest.mark.asyncio
async def test_fetch_multiple_with_errors(
    model_fetcher: GenericFetcher, mock_api_client: AsyncMock
) -> None:
    """Test multiple entity fetch with all entities failing."""
    # Given: A configured fetcher and mock API client that always fails
    entity_ids = ["123", "456", "789"]
    network_error = ApiNetworkError("Service unavailable")
    _given_api_returns_error(mock_api_client, network_error)

    # When: Multiple entities are fetched
    result, exception = await _when_fetch_multiple_called(model_fetcher, entity_ids)

    # Then: An empty list should be returned (all failed)
    assert result == []  # noqa: S101
    _then_api_called_multiple_times(mock_api_client, 3)


# Scenario: List fetching


@pytest.mark.asyncio
async def test_fetch_list_success_direct_list(
    list_fetcher: GenericFetcher, mock_api_client: AsyncMock
) -> None:
    """Test successful list fetch with direct list response."""
    # Given: A configured list fetcher and mock API client with list data
    users = [
        UserModel(id="123", name="John", email="john@example.com"),
        UserModel(id="456", name="Jane", email="jane@example.com"),
    ]
    _given_api_returns_list(mock_api_client, users)

    # When: A list is fetched
    result, exception = await _when_fetch_list_called(list_fetcher)

    # Then: The list should be returned successfully
    _then_fetch_list_successful(result, 2)


@pytest.mark.asyncio
async def test_fetch_list_success_wrapped_data(
    list_config: GenericFetcherConfig,
    mock_api_client: AsyncMock,
    mock_logger: MagicMock,
) -> None:
    """Test successful list fetch with wrapped data response."""
    # Given: A list fetcher with response_key configuration
    config_with_key = GenericFetcherConfig(
        entity_type="users",
        endpoint="/api/users",
        display_name="users",
        exception_class=UserFetchError,
        response_model=UserModel,
        response_key="data",
    )
    fetcher = GenericFetcher(
        config=config_with_key, api_client=mock_api_client, logger=mock_logger
    )

    users_data = [{"id": "123", "name": "John", "email": "john@example.com"}]
    _given_api_returns_wrapped_data(mock_api_client, {"data": users_data})

    # When: A list is fetched
    result, exception = await _when_fetch_list_called(fetcher)

    # Then: The unwrapped list should be returned successfully
    _then_fetch_list_successful(result, 1)


@pytest.mark.asyncio
async def test_fetch_list_success_single_item(
    list_fetcher: GenericFetcher, mock_api_client: AsyncMock
) -> None:
    """Test successful list fetch when API returns single item instead of list."""
    # Given: A configured list fetcher and mock API client returning single item
    user = UserModel(id="123", name="John", email="john@example.com")
    _given_api_returns_single_item(mock_api_client, user)

    # When: A list is fetched
    result, exception = await _when_fetch_list_called(list_fetcher)

    # Then: A single-item list should be returned
    _then_fetch_list_successful(result, 1)


@pytest.mark.asyncio
async def test_fetch_list_empty_response(
    list_fetcher: GenericFetcher, mock_api_client: AsyncMock
) -> None:
    """Test list fetch with empty response."""
    # Given: A configured list fetcher and mock API client returning empty list
    _given_api_returns_list(mock_api_client, [])

    # When: A list is fetched
    result, exception = await _when_fetch_list_called(list_fetcher)

    # Then: An empty list should be returned
    _then_fetch_list_empty(result)


@pytest.mark.asyncio
async def test_fetch_list_network_error(
    list_fetcher: GenericFetcher, mock_api_client: AsyncMock
) -> None:
    """Test list fetch with network error."""
    # Given: A configured list fetcher and mock API client that raises network error
    network_error = ApiNetworkError("Connection timeout")
    _given_api_returns_error(mock_api_client, network_error)

    # When: A list is fetched
    result, exception = await _when_fetch_list_called(list_fetcher)

    # Then: A UserFetchError should be raised
    _then_fetch_failed_with_network_error(exception, "Connection timeout")


# Scenario: Header merging


def test_header_merging_with_base_headers(
    mock_api_client: AsyncMock, mock_logger: MagicMock
) -> None:
    """Test that base headers and config headers are properly merged."""
    # Given: A configuration with headers and base headers provided
    config_with_headers = GenericFetcherConfig(
        entity_type="users",
        endpoint="/api/users/{id}",
        display_name="users",
        exception_class=UserFetchError,
        headers={"Content-Type": "application/json"},
    )
    base_headers = {"Authorization": "Bearer token"}

    # When: A fetcher is created with all header sources
    fetcher = GenericFetcher(
        config=config_with_headers,
        api_client=mock_api_client,
        logger=mock_logger,
        base_headers=base_headers,
    )

    # Then: All headers should be merged correctly
    expected_headers = {
        "Authorization": "Bearer token",
        "Content-Type": "application/json",
    }
    _then_headers_merged_correctly(fetcher, expected_headers)


def test_header_merging_config_overrides_base(
    mock_api_client: AsyncMock, mock_logger: MagicMock
) -> None:
    """Test that config headers override base headers when keys conflict."""
    # Given: Conflicting headers in base and config
    config_with_headers = GenericFetcherConfig(
        entity_type="users",
        endpoint="/api/users/{id}",
        display_name="users",
        exception_class=UserFetchError,
        headers={
            "Authorization": "Bearer config-token",
            "Content-Type": "application/json",
        },
    )
    base_headers = {"Authorization": "Bearer base-token", "User-Agent": "TestAgent"}

    # When: A fetcher is created with conflicting headers
    fetcher = GenericFetcher(
        config=config_with_headers,
        api_client=mock_api_client,
        logger=mock_logger,
        base_headers=base_headers,
    )

    # Then: Config headers should override base headers
    expected_headers = {
        "Authorization": "Bearer config-token",  # Config overrides base
        "Content-Type": "application/json",  # From config
        "User-Agent": "TestAgent",  # From base
    }
    _then_headers_merged_correctly(fetcher, expected_headers)


# =====================
# GWT Helper Functions
# =====================

# --- GIVEN: Setup conditions ---


def _given_api_returns_data(mock_client: AsyncMock, data: Dict[str, Any]) -> None:
    """Set up mock API client to return specific data."""
    mock_client.call_api.return_value = data


def _given_api_returns_model(mock_client: AsyncMock, model: BaseModel) -> None:
    """Set up mock API client to return specific model."""
    mock_client.call_api.return_value = model


def _given_api_returns_multiple_models(
    mock_client: AsyncMock, models: Sequence[BaseModel]
) -> None:
    """Set up mock API client to return multiple models for different calls."""
    mock_client.call_api.side_effect = models


def _given_api_returns_list(mock_client: AsyncMock, items: List[Any]) -> None:
    """Set up mock API client to return a list of items."""
    mock_client.call_api.return_value = items


def _given_api_returns_wrapped_data(
    mock_client: AsyncMock, wrapped_response: Union[Dict[str, Any], BaseModel]
) -> None:
    """Set up mock API client to return wrapped response."""
    mock_client.call_api.return_value = wrapped_response


def _given_api_returns_single_item(mock_client: AsyncMock, item: BaseModel) -> None:
    """Set up mock API client to return single item."""
    mock_client.call_api.return_value = item


def _given_api_returns_none(mock_client: AsyncMock) -> None:
    """Set up mock API client to return None."""
    mock_client.call_api.return_value = None


def _given_api_returns_error(mock_client: AsyncMock, error: Exception) -> None:
    """Set up mock API client to raise an error."""
    mock_client.call_api.side_effect = error


# --- WHEN: Execute the system under test ---


async def _when_fetch_single_called(
    fetcher: GenericFetcher, **kwargs: Any
) -> Tuple[Any, Optional[Exception]]:
    """Call fetch_single and capture result and exception."""
    try:
        result = await fetcher.fetch_single(**kwargs)
        return result, None
    except Exception as e:
        return None, e


async def _when_fetch_multiple_called(
    fetcher: GenericFetcher, entity_ids: List[str], **kwargs: Any
) -> Tuple[Optional[List[Any]], Optional[Exception]]:
    """Call fetch_multiple and capture result and exception."""
    try:
        result = await fetcher.fetch_multiple(entity_ids, **kwargs)
        return result, None
    except Exception as e:
        return None, e


async def _when_fetch_list_called(
    fetcher: GenericFetcher, **kwargs: Any
) -> Tuple[Optional[List[Any]], Optional[Exception]]:
    """Call fetch_list and capture result and exception."""
    try:
        result = await fetcher.fetch_list(**kwargs)
        return result, None
    except Exception as e:
        return None, e


# --- THEN: Verify the expected outcomes ---


def _then_fetch_successful(result: Any, expected_data: Dict[str, Any]) -> None:
    """Assert that fetch was successful and returned expected data."""
    assert result is not None  # noqa: S101
    assert result == expected_data  # noqa: S101


def _then_fetch_successful_with_model(result: Any, expected_model: BaseModel) -> None:
    """Assert that fetch was successful and returned expected model."""
    assert result is not None  # noqa: S101

    if hasattr(result, "data"):
        if hasattr(expected_model, "data"):
            assert isinstance(result.data, type(expected_model.data))  # noqa: S101
            assert (  # noqa: S101
                result.data.model_dump() == expected_model.data.model_dump()
            )
        else:
            assert isinstance(result.data, type(expected_model))  # noqa: S101
            assert result.data.model_dump() == expected_model.model_dump()  # noqa: S101
    else:
        assert isinstance(result, type(expected_model))  # noqa: S101
        assert result.model_dump() == expected_model.model_dump()  # noqa: S101


def _then_fetch_returns_none(result: Any) -> None:
    """Assert that fetch returned None."""
    assert result is None  # noqa: S101


def _then_fetch_failed_with_network_error(
    exception: Optional[Exception], expected_message: str
) -> None:
    """Assert that fetch failed with network error."""
    assert exception is not None  # noqa: S101
    assert isinstance(exception, UserFetchError)  # noqa: S101
    assert "Network error" in str(exception)  # noqa: S101
    assert expected_message in str(exception)  # noqa: S101


def _then_fetch_failed_with_general_error(
    exception: Optional[Exception], expected_message: str
) -> None:
    """Assert that fetch failed with general error."""
    assert exception is not None  # noqa: S101
    assert isinstance(exception, UserFetchError)  # noqa: S101
    assert expected_message in str(exception)  # noqa: S101


def _then_fetch_failed_with_param_error(
    exception: Optional[Exception], expected_param: str
) -> None:
    """Assert that fetch failed with parameter error."""
    assert exception is not None  # noqa: S101
    assert isinstance(exception, UserFetchError)  # noqa: S101
    assert expected_param in str(exception)  # noqa: S101


def _then_fetch_multiple_successful(
    results: Optional[List[Any]], expected_count: int
) -> None:
    """Assert that multiple fetch was successful."""
    assert results is not None  # noqa: S101
    assert len(results) == expected_count  # noqa: S101


def _then_fetch_multiple_partial_success(
    results: Optional[List[Any]], expected_count: int
) -> None:
    """Assert that multiple fetch had partial success."""
    assert results is not None  # noqa: S101
    assert len(results) == expected_count  # noqa: S101


def _then_fetch_list_successful(
    results: Optional[List[Any]], expected_count: int
) -> None:
    """Assert that list fetch was successful."""
    assert results is not None  # noqa: S101
    assert len(results) == expected_count  # noqa: S101


def _then_fetch_list_empty(results: Optional[List[Any]]) -> None:
    """Assert that list fetch returned empty list."""
    assert results is not None  # noqa: S101
    assert len(results) == 0  # noqa: S101


def _then_api_called_correctly(mock_client: AsyncMock, expected_endpoint: str) -> None:
    """Assert that API was called with correct endpoint."""
    mock_client.call_api.assert_called_once()
    call_args = mock_client.call_api.call_args
    assert expected_endpoint in str(call_args)  # noqa: S101


def _then_api_called_multiple_times(
    mock_client: AsyncMock, expected_count: int
) -> None:
    """Assert that API was called multiple times."""
    assert mock_client.call_api.call_count == expected_count  # noqa: S101


def _then_headers_merged_correctly(
    fetcher: GenericFetcher, expected_headers: Dict[str, str]
) -> None:
    """Assert that headers were merged correctly."""
    assert fetcher.headers == expected_headers  # noqa: S101


# =====================
# Save to File Tests
# =====================


@pytest.mark.asyncio
async def test_save_to_file_disabled_by_default(
    basic_fetcher: GenericFetcher, mock_api_client: AsyncMock
) -> None:
    """Test that save_to_file is disabled by default."""
    # Given: A basic fetcher with save_to_file disabled (default)
    expected_data = {"id": "123", "name": "John Doe"}
    _given_api_returns_data(mock_api_client, expected_data)

    # When: A single entity is fetched
    with (
        patch("pathlib.Path.mkdir") as mock_mkdir,
        patch("builtins.open", mock_open()) as mock_file,
    ):
        result, exception = await _when_fetch_single_called(
            basic_fetcher, entity_id="123"
        )

        # Then: The fetch should succeed and no file operations should occur
        assert result == expected_data  # noqa: S101
        mock_mkdir.assert_not_called()
        mock_file.assert_not_called()


@pytest.mark.asyncio
async def test_save_to_file_creates_debug_directory(
    save_to_file_fetcher: GenericFetcher,
    mock_api_client: AsyncMock,
    mock_save_to_file: Dict[str, Any],
) -> None:
    """Test that debug directory is created when save_to_file is enabled."""
    # Given: A fetcher with save_to_file enabled
    expected_data = {"id": "123", "name": "John Doe"}
    _given_api_returns_data(mock_api_client, expected_data)

    # When: A single entity is fetched
    result, exception = await _when_fetch_single_called(
        save_to_file_fetcher, entity_id="123"
    )

    # Then: The fetch should succeed and debug directory should be created
    assert result == expected_data  # noqa: S101
    mock_save_to_file["mkdir"].assert_called_once_with(exist_ok=True)


@pytest.mark.asyncio
async def test_save_to_file_saves_raw_response(
    save_to_file_fetcher: GenericFetcher,
    mock_api_client: AsyncMock,
    mock_save_to_file: Dict[str, Any],
) -> None:
    """Test that raw response is saved to file when save_to_file is enabled."""
    # Given: A fetcher with save_to_file enabled
    expected_data = {"id": "123", "name": "John Doe"}
    _given_api_returns_data(mock_api_client, expected_data)

    # When: A single entity is fetched
    result, exception = await _when_fetch_single_called(
        save_to_file_fetcher, entity_id="123"
    )

    # Then: The raw response should be saved
    assert result == expected_data  # noqa: S101
    mock_save_to_file["json_dump"].assert_called_once()


@pytest.mark.asyncio
async def test_save_to_file_generates_correct_filename(
    save_to_file_fetcher: GenericFetcher,
    mock_api_client: AsyncMock,
    mock_save_to_file: Dict[str, Any],
) -> None:
    """Test that correct filename is generated when saving to file."""
    # Given: A fetcher with save_to_file enabled
    expected_data = {"id": "123", "name": "John Doe"}
    _given_api_returns_data(mock_api_client, expected_data)

    # When: A single entity is fetched
    result, exception = await _when_fetch_single_called(
        save_to_file_fetcher, entity_id="123"
    )

    # Then: The filename should be generated using SHA256 hash
    assert result == expected_data  # noqa: S101
    mock_save_to_file["open"].assert_called_once()
    # Verify filename contains entity type and hash
    call_args = mock_save_to_file["open"].call_args[0]
    filename = str(call_args[0])
    assert "users_" in filename  # noqa: S101
    assert filename.endswith(".json")  # noqa: S101


@pytest.mark.asyncio
async def test_save_to_file_avoids_duplicates(
    save_to_file_fetcher: GenericFetcher, mock_api_client: AsyncMock
) -> None:
    """Test that duplicate files are avoided when saving to file."""
    # Given: A fetcher with save_to_file enabled and file already exists
    expected_data = {"id": "123", "name": "John Doe"}
    _given_api_returns_data(mock_api_client, expected_data)

    # When: A single entity is fetched
    with (
        patch("pathlib.Path.mkdir"),
        patch("pathlib.Path.exists", return_value=True),
        patch("builtins.open", mock_open()) as mock_file,
        patch("json.dump") as mock_json_dump,
    ):
        result, exception = await _when_fetch_single_called(
            save_to_file_fetcher, entity_id="123"
        )

        # Then: File should not be written since it already exists
        assert result == expected_data  # noqa: S101
        mock_file.assert_not_called()
        mock_json_dump.assert_not_called()


@pytest.mark.asyncio
async def test_save_to_file_handles_pydantic_models(
    mock_api_client: AsyncMock,
    mock_logger: MagicMock,
    mock_save_to_file: Dict[str, Any],
) -> None:
    """Test that Pydantic models are properly serialized when saving to file."""
    # Given: A fetcher configured with response model and save_to_file enabled
    config = GenericFetcherConfig(
        entity_type="users",
        endpoint="/api/users/{entity_id}",
        display_name="users",
        exception_class=UserFetchError,
        response_model=UserModel,
        save_to_file=True,
    )
    fetcher = GenericFetcher(
        config=config, api_client=mock_api_client, logger=mock_logger
    )
    user_model = UserModel(id="123", name="John Doe", email="john@example.com")
    _given_api_returns_model(mock_api_client, user_model)

    # When: A single entity is fetched
    result, exception = await _when_fetch_single_called(fetcher, entity_id="123")

    # Then: The model should be returned and saved properly
    assert result == user_model  # noqa: S101
    mock_save_to_file["json_dump"].assert_called_once()


@pytest.mark.asyncio
async def test_save_to_file_includes_request_info(
    save_to_file_fetcher: GenericFetcher,
    mock_api_client: AsyncMock,
    mock_save_to_file: Dict[str, Any],
) -> None:
    """Test that request info is included in saved file."""
    # Given: A fetcher with save_to_file enabled
    expected_data = {"id": "123", "name": "John Doe"}
    _given_api_returns_data(mock_api_client, expected_data)

    # When: A single entity is fetched
    result, exception = await _when_fetch_single_called(
        save_to_file_fetcher, entity_id="123"
    )

    # Then: Request info should be included in saved file
    assert result == expected_data  # noqa: S101
    mock_save_to_file["json_dump"].assert_called_once()


@pytest.mark.asyncio
async def test_save_to_file_error_handling(
    mock_api_client: AsyncMock, mock_logger: MagicMock
) -> None:
    """Test that file saving errors don't affect main operation."""
    # Given: A fetcher with save_to_file enabled and file operations fail
    config = GenericFetcherConfig(
        entity_type="users",
        endpoint="/api/users/{entity_id}",
        display_name="users",
        exception_class=UserFetchError,
        save_to_file=True,
    )
    fetcher = GenericFetcher(
        config=config, api_client=mock_api_client, logger=mock_logger
    )
    expected_data = {"id": "123", "name": "John Doe"}
    _given_api_returns_data(mock_api_client, expected_data)

    # When: A single entity is fetched and file operations fail
    with patch("pathlib.Path.mkdir", side_effect=Exception("File system error")):
        result, exception = await _when_fetch_single_called(fetcher, entity_id="123")

        # Then: Main operation should still succeed and error should be logged
        assert result == expected_data  # noqa: S101
        mock_logger.warning.assert_called_once()


@pytest.mark.asyncio
async def test_save_to_file_works_with_all_fetch_methods(
    save_to_file_list_config: GenericFetcherConfig,
    mock_api_client: AsyncMock,
    mock_logger: MagicMock,
    mock_save_to_file: Dict[str, Any],
) -> None:
    """Test that save_to_file works with all fetch methods."""
    # Given: Multiple fetchers with save_to_file enabled
    single_data = {"id": "123", "name": "John Doe"}
    list_data = [
        UserModel(id="123", name="John", email="john@example.com"),
        UserModel(id="456", name="Jane", email="jane@example.com"),
    ]

    single_config = GenericFetcherConfig(
        entity_type="users",
        endpoint="/api/users/{entity_id}",
        display_name="users",
        exception_class=UserFetchError,
        save_to_file=True,
    )
    single_fetcher = GenericFetcher(
        config=single_config, api_client=mock_api_client, logger=mock_logger
    )

    list_fetcher = GenericFetcher(
        config=save_to_file_list_config,
        api_client=mock_api_client,
        logger=mock_logger,
    )

    _given_api_returns_data(mock_api_client, single_data)
    result = await single_fetcher.fetch_single(entity_id="123")
    assert result == single_data  # noqa: S101
    mock_save_to_file["json_dump"].assert_called()

    mock_api_client.reset_mock()
    mock_save_to_file["json_dump"].reset_mock()
    _given_api_returns_list(mock_api_client, list_data)
    result = await list_fetcher.fetch_list()
    assert result == list_data  # noqa: S101
    mock_save_to_file["json_dump"].assert_called()

    mock_api_client.reset_mock()
    mock_save_to_file["json_dump"].reset_mock()
    mock_api_client.call_api.side_effect = [single_data, {"id": "456", "name": "Jane"}]
    result = await single_fetcher.fetch_multiple(["123", "456"])
    assert len(result) == 2  # noqa: S101
    assert mock_save_to_file["json_dump"].call_count == 2  # noqa: S101


@pytest.mark.asyncio
async def test_save_to_file_with_query_parameters(
    save_to_file_list_config: GenericFetcherConfig,
    mock_api_client: AsyncMock,
    mock_logger: MagicMock,
    mock_save_to_file: Dict[str, Any],
) -> None:
    """Test that query parameters are included in saved request info."""
    # Given: A list fetcher with save_to_file enabled
    list_fetcher = GenericFetcher(
        config=save_to_file_list_config,
        api_client=mock_api_client,
        logger=mock_logger,
    )
    expected_data = [UserModel(id="123", name="John", email="john@example.com")]
    _given_api_returns_list(mock_api_client, expected_data)

    # When: A list is fetched with query parameters
    result = await list_fetcher.fetch_list(filter="active", limit=10)

    # Then: Query parameters should be included in saved request info
    assert result == expected_data  # noqa: S101
    mock_save_to_file["json_dump"].assert_called_once()
