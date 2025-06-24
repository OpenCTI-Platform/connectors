"""Module to test the API engine components."""

from typing import Any, Dict, Optional, Tuple, Type
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from connector.src.utils.api_engine.aio_http_client import AioHttpClient
from connector.src.utils.api_engine.api_client import ApiClient
from connector.src.utils.api_engine.circuit_breaker import CircuitBreaker
from connector.src.utils.api_engine.exceptions.api_error import ApiError
from connector.src.utils.api_engine.exceptions.api_timeout_error import ApiTimeoutError
from connector.src.utils.api_engine.interfaces.base_rate_limiter import BaseRateLimiter
from connector.src.utils.api_engine.rate_limiter import RateLimiterRegistry
from connector.src.utils.api_engine.retry_request_strategy import RetryRequestStrategy
from pydantic import BaseModel

# =====================
# Fixtures
# =====================


@pytest.fixture
def mock_aiohttp_client() -> AsyncMock:
    """Fixture for a mocked AioHttpClient that proxies .request → .get/.post."""
    mock = AsyncMock(spec=AioHttpClient)

    mock.get = AsyncMock(return_value={"success": True, "data": {"key": "value"}})
    mock.post = AsyncMock(return_value={"success": True, "id": "123"})

    async def _request(
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, str]] = None,
        json_payload: Optional[Dict[str, str]] = None,
        ssl: Optional[bool] = None,
        timeout: Optional[float] = None,
    ) -> Any:
        m = method.upper()
        if m == "GET":
            return await mock.get(
                url,
                params=params,
                headers=headers,
                data=data,
                json_payload=json_payload,
                ssl=ssl,
                timeout=timeout,
            )
        elif m == "POST":
            return await mock.post(
                url,
                params=params,
                headers=headers,
                data=data,
                json_payload=json_payload,
                ssl=ssl,
                timeout=timeout,
            )
        else:
            raise NotImplementedError(f"Test fixture doesn’t handle HTTP {method!r}")

    mock.request = AsyncMock(side_effect=_request)
    return mock


@pytest.fixture
def circuit_breaker() -> CircuitBreaker:
    """Fixture for a CircuitBreaker."""
    return CircuitBreaker(max_failures=3, cooldown_time=10)


@pytest_asyncio.fixture
async def rate_limiter() -> BaseRateLimiter:
    """Fixture for a RateLimiter."""
    return await RateLimiterRegistry.get("test_api", max_requests=5, period=1)


@pytest.fixture
def retry_strategy(
    mock_aiohttp_client: AsyncMock,
    circuit_breaker: CircuitBreaker,
    rate_limiter: BaseRateLimiter,
) -> RetryRequestStrategy:
    """Fixture for a RetryRequestStrategy."""
    return RetryRequestStrategy(
        http=mock_aiohttp_client,
        breaker=circuit_breaker,
        limiter=rate_limiter,
        max_retries=2,
        backoff=2,
    )


@pytest.fixture
def api_client(retry_strategy: RetryRequestStrategy) -> ApiClient:
    """Fixture for a ApiClient."""
    return ApiClient(retry_strategy)


class SimpleModel(BaseModel):
    """SimpleModel is a Pydantic model for testing."""

    key: str


class GitHubInfo(BaseModel):
    """GitHubInfo is a Pydantic model for testing GitHub API responses."""

    current_user_url: str
    user_url: str
    emails_url: str


# =====================
# Test Data Fixtures (if needed)
# =====================


@pytest.fixture(
    params=[
        {
            "url": "https://api.test.com/data",
            "response_data": {"key": "test_value"},
            "model": SimpleModel,
        },
        {
            "url": "https://api.github.com",
            "response_data": {
                "current_user_url": "url1",
                "user_url": "url2",
                "emails_url": "url3",
            },
            "model": GitHubInfo,
        },
    ]
)
def successful_get_scenario(request: Any) -> Any:
    """Fixture for successful GET request scenarios."""
    return request.param


@pytest.fixture(
    params=[
        {
            "url": "https://api.test.com/notfound",
            "status_code": 404,
            "error_message": "Not Found",
        },
    ]
)
def failed_get_scenario(request: Any) -> Any:
    """Fixture for failed GET request scenarios."""
    return request.param


# =====================
# Test Cases
# =====================

# Scenario: API client making successful requests


@pytest.mark.asyncio
async def test_api_client_successful_get_no_model(
    api_client: ApiClient,
    mock_aiohttp_client: AsyncMock,
) -> None:
    """Test successful GET request without a Pydantic model."""
    # Given: A mocked API client configured to return successful response data
    #        and a valid URL endpoint to request
    url = "https://api.test.com/data"
    expected_response_data = {"key": "value", "another_key": "another_value"}
    _given_mock_response(mock_aiohttp_client, method="get", data=expected_response_data)

    # When: The API client performs a GET request to the specified URL
    response, exception = await _when_api_get_called(api_client, url)

    # Then: The response should match the expected data
    #       and the request should be made with the correct parameters
    _then_response_is_successful(response, expected_response_data)
    mock_aiohttp_client.request.assert_awaited_once_with(
        "GET", url, headers=None, params=None, json_payload=None, timeout=None
    )


@pytest.mark.asyncio
async def test_api_client_successful_get_with_model(
    api_client: ApiClient,
    mock_aiohttp_client: AsyncMock,
    successful_get_scenario: Dict[str, Any],
) -> None:
    """Test successful GET request with a Pydantic model."""
    # Given: A mocked API client configured to return specific response data
    #        and a parameterized test scenario with URL and expected model type
    url = successful_get_scenario["url"]
    response_data = successful_get_scenario["response_data"]
    model = successful_get_scenario["model"]
    _given_mock_response(mock_aiohttp_client, method="get", data=response_data)

    # When: The API client performs a GET request with model validation
    response, exception = await _when_api_get_called(api_client, url, model=model)

    # Then: The response should be an instance of the expected model
    #       with data matching the expected response
    _then_response_is_successful(response, response_data, model_type=model)
    mock_aiohttp_client.request.assert_awaited_once_with(
        "GET", url, headers=None, params=None, json_payload=None, timeout=None
    )


# Scenario: API client handling error responses


@pytest.mark.asyncio
async def test_api_client_get_http_error(
    api_client: ApiClient,
    mock_aiohttp_client: AsyncMock,
    failed_get_scenario: Dict[str, Any],
) -> None:
    """Test GET request that results in an HTTP error (e.g., 404, 500)."""
    # Given: A mocked API client configured to fail with a specific HTTP status code
    #        and a parameterized scenario with URL and error details
    url = failed_get_scenario["url"]
    status_code = failed_get_scenario["status_code"]
    underlying_exception = Exception(f"Simulated HTTP {status_code} error")
    _given_mock_response(
        mock_aiohttp_client, method="get", raise_exception=underlying_exception
    )

    # When: The API client attempts to make a GET request to the specified URL
    response, exception = await _when_api_get_called(api_client, url)

    # Then: An appropriate exception should be raised with the expected error message
    expected_message = f"simulated http {status_code} error"
    _then_api_exception_is_raised(exception, expected_message_part=expected_message)


# Scenario: Testing retry mechanisms and failure handling


@pytest.mark.asyncio
async def test_retry_strategy_exhausts_retries(
    api_client: ApiClient, mock_aiohttp_client: AsyncMock
) -> None:
    """Test that the retry strategy gives up after exhausting retries."""
    # Given: A mocked API client configured to always fail with a timeout error
    #        and an API client with a specific maximum retry configuration
    url = "https://api.test.com/persistent-error"
    persistent_error = ApiTimeoutError("Simulated persistent error")
    mock_aiohttp_client.get.side_effect = persistent_error
    max_retries = api_client.strategy.max_retries  # type: ignore

    # When: The API client attempts to make a GET request that will fail repeatedly
    response, exception = await _when_api_get_called(api_client, url)

    # Then: An exception should be raised after exhausting all retry attempts
    #       and the request should have been attempted exactly (max_retries + 1) times
    _then_api_exception_is_raised(
        exception, expected_message_part="simulated persistent error"
    )
    assert mock_aiohttp_client.request.await_count == max_retries + 1  # noqa: S101


# Scenario: Circuit breaker pattern implementation


@pytest.mark.asyncio
async def test_circuit_breaker_opens_after_failures(
    mock_aiohttp_client: AsyncMock,
    circuit_breaker: CircuitBreaker,
    rate_limiter: BaseRateLimiter,
) -> None:
    """Test that the circuit breaker opens after consecutive failures."""
    # Given: A circuit breaker with a defined failure threshold
    #        and a client configured to always fail with a timeout error
    strategy = RetryRequestStrategy(
        http=mock_aiohttp_client,
        breaker=circuit_breaker,
        limiter=rate_limiter,
        max_retries=0,
    )
    client = ApiClient(strategy)

    url = "https://api.test.com/break-me"
    failure_exception = ApiTimeoutError("Failure to trigger breaker")
    mock_aiohttp_client.get.side_effect = failure_exception

    # When: Making API calls that fail enough times to exceed the failure threshold
    for _ in range(circuit_breaker.max_failures):
        try:
            await client.call_api(url)
        except ApiError:
            pass

    # Then: The circuit breaker should be in an open state
    #       and additional calls should fail immediately without hitting the actual API
    _then_circuit_breaker_is_open(circuit_breaker)

    with pytest.raises(ApiError):
        await client.call_api(url)

    assert (  # noqa: S101
        mock_aiohttp_client.get.await_count == circuit_breaker.max_failures + 1
    )


# =====================
# GWT Gherkin-style functions
# =====================


# --- GIVEN: Setup mock responses and test conditions ---
def _given_mock_response(
    mock_client: AsyncMock,
    method: str = "get",
    data: Dict[str, Any] | None = None,
    status: int = 200,
    raise_exception: Exception | None = None,
) -> None:
    """Set up the mock client's specified method to return data or raise an exception."""
    if raise_exception:
        getattr(mock_client, method).side_effect = raise_exception
    else:
        mock_response = AsyncMock()
        mock_response.json = AsyncMock(return_value=data)
        mock_response.status = status
        if 200 <= status < 300:
            getattr(mock_client, method).return_value = data
        else:
            http_error = Exception(f"HTTP Error {status}")
            if hasattr(getattr(mock_client, method), "side_effect"):
                getattr(mock_client, method).side_effect = http_error
            else:
                mock_actual_client_response = AsyncMock()
                mock_actual_client_response.status = status
                mock_actual_client_response.json = AsyncMock(return_value=data)
                pass


# --- WHEN: Execute the system under test ---
async def _when_api_get_called(
    client: ApiClient, url: str, model: Type[BaseModel] | None = None
) -> Tuple[Any, Exception | None]:
    """Call the get method of the ApiClient."""
    try:
        return await client.call_api(url, model=model), None
    except ApiError as e:
        return None, e
    except Exception as e:
        return None, e


# --- THEN: Verify the expected outcomes ---
def _then_response_is_successful(
    response: Any,
    expected_data: Dict[str, Any],
    model_type: Type[BaseModel] | None = None,
) -> None:
    """Assert that the API response is successful and matches expected data."""
    assert response is not None  # noqa: S101
    if model_type:
        assert isinstance(response, model_type)  # noqa: S101
        assert response.model_dump() == expected_data  # noqa: S101
    else:
        assert response == expected_data  # noqa: S101


def _then_api_exception_is_raised(
    exception: Exception | None,
    expected_message_part: str | None = None,
    expected_status_code: int | None = None,
) -> None:
    """Assert that an ApiError was raised."""
    assert exception is not None  # noqa: S101
    assert isinstance(exception, ApiError)  # noqa: S101
    if expected_message_part:
        assert expected_message_part in str(exception).lower()  # noqa: S101
    if expected_status_code and hasattr(exception, "status_code"):
        assert exception.status_code == expected_status_code  # noqa: S101


def _then_circuit_breaker_is_open(breaker: CircuitBreaker) -> None:
    """Assert that the circuit breaker is open."""
    assert breaker.is_open() is True  # noqa: S101


def _then_rate_limiter_called(
    limiter_mock: AsyncMock,
) -> None:
    """Assert that the rate limiter was called."""
    limiter_mock.acquire.assert_called()
