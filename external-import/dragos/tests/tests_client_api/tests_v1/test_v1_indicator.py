# isort:skip_file
# pragma: no cover
"""Provide tests for client_api.v1.indicator module.

- Responses: Test that extra parameters do not lead to an error but a warning.
- API client:
    - Test that missing mandatory parameters lead to DragosAPIError.
    - Test that invalid parameters lead to DragosAPIError.
    - Test that invalid request parameters lead to a ValueError.
    - Test that the retry mechanism is called.
    - Test that invalid response content leads to DragosAPIError.
"""

from datetime import datetime, timedelta, timezone
from aiohttp import ClientResponseError
from pydantic import SecretStr
import pytest
import warnings
from unittest.mock import MagicMock, patch, AsyncMock, Mock
from yarl import URL
import inspect

from client_api.errors import DragosAPIError
from client_api.v1.indicator import (
    IndicatorResponse,
    IndicatorsResponse,
    IndicatorClientAPIV1,
)
from client_api.warning import ValidationWarning

_valid_indicator_response = {
    "id": 1,
    "value": "indicator_value",
    "indicator_type": "sha256",
    "category": "category",
    "comment": "comment",
    "first_seen": "2023-10-01T00:00:00Z",
    "last_seen": "2023-10-01T00:00:00Z",
    "updated_at": "2023-10-01T00:00:00Z",
    "confidence": "high",
    "kill_chain": "kill_chain",
    "uuid": "uuid",
    "status": "released",
    "severity": "severity",
    "attack_techniques": ["technique1"],
    "ics_attack_techniques": ["ics_technique1"],
    "kill_chains": ["kill_chain1"],
    "pre_attack_techniques": ["pre_attack_technique1"],
    "threat_groups": ["threat_group1"],
    "products": [{"serial": "serial1"}],
}


@pytest.fixture
def valid_indicator_response():
    """Return a valid IndicatorResponse.

    Fixture used to be able to alterate the response in tests.
    """
    return _valid_indicator_response


_valid_indicators_response = {
    "indicators": [_valid_indicator_response],
    "total": 1,
    "page_size": 1,
    "total_pages": 1,
    "page": 1,
}


@pytest.fixture
def valid_indicators_response():
    """Return a valid IndicatorsResponse.

    Fixture used to be able to alterate the response in tests.
    """
    return _valid_indicators_response


@pytest.fixture
def valid_client():
    """Return an IndicatorClientAPIV1 instance."""
    return IndicatorClientAPIV1(
        base_url=URL("http://example.com"),
        token=SecretStr("my_token"),
        secret=SecretStr("my_secret"),
        timeout=timedelta(seconds=10),
        retry=3,
        backoff=timedelta(microseconds=1),  # No need to wait for test
    )


def test_indicator_response_with_correct_inputs_is_successfully_instantiated(
    valid_indicator_response,
):
    """Test that the IndicatorResponse is successfully instantiated with correct inputs."""
    # Given correct inputs
    # When instantiating the IndicatorResponse
    # Then attribute values are correctly set
    with warnings.catch_warnings():
        warnings.simplefilter("error", ValidationWarning)
        indicator_response = IndicatorResponse.model_validate(valid_indicator_response)
    assert indicator_response.id == 1  # noqa: S101 we indeed call assert during test


def test_indicators_response_with_correct_inputs_is_successfully_instantiated(
    valid_indicators_response,
):
    """Test that the IndicatorsResponse is successfully instantiated with correct inputs."""
    # Given correct inputs
    # When instantiating the IndicatorsResponse
    # Then attribute values are correctly set
    with warnings.catch_warnings():
        warnings.simplefilter("error", ValidationWarning)
        indicators_response = IndicatorsResponse.model_validate(
            valid_indicators_response
        )
    assert indicators_response.page == 1  # noqa: S101


@pytest.mark.parametrize(
    "parameter_name,incorrect_value",
    [
        pytest.param("page", 0, id="page_0"),
        pytest.param(
            "updated_after",
            datetime.now(timezone.utc) + timedelta(days=1),
            id="updated_after_in_future",
        ),
    ],
)
@patch("client_api.v1.indicator.BaseClientAPIV1.get")
@pytest.mark.asyncio
async def test_invalid_request_parameters_leads_to_value_error_when_calling_get_1_page(
    mock_get, parameter_name, incorrect_value, valid_client
):
    """Test that invalid request parameters lead to a ValueError."""
    # Given
    # A valid Client API
    client = valid_client
    # A mock get method
    _ = mock_get
    # When making a request with invalid request parameters
    params = {"page": 1, "page_size": 50}
    params[parameter_name] = incorrect_value
    # Then a ValueError is raised
    with pytest.raises(ValueError):
        _ = await client._get_1_page(**params)


@pytest.mark.parametrize(
    "method_name,parameters",
    [
        pytest.param("get_all_indicators", {}, id="get_all_indicators"),
        pytest.param("iter_indicators", {}, id="iter_indicators"),
    ],
)
@pytest.mark.asyncio
async def test_invalid_indicator_response_content_leads_to_dragos_api_error(
    method_name, parameters, valid_client
):
    """Test that invalid response content leads to DragosAPIError."""
    # Given
    # A valid Client API
    client = valid_client
    # A mock get method returning an invalid response
    client._get = AsyncMock()
    client._get.return_value = Mock()
    client._get.return_value.json = AsyncMock(
        return_value={"invalid_key": "invalid_value"}
    )

    # When making a request
    # Then a DragosAPIError is raised
    with pytest.raises(DragosAPIError):
        method = getattr(client, method_name)
        # if method is async_generator
        if inspect.isasyncgenfunction(method):
            async for _ in method(**parameters):
                pass
        else:  # else
            _ = await method(**parameters)


@pytest.mark.parametrize(
    "error_code",
    [
        pytest.param(400, id="400"),
        pytest.param(401, id="401"),
        pytest.param(403, id="403"),
        pytest.param(404, id="404"),
        pytest.param(429, id="429"),
    ],
)
@pytest.mark.parametrize(
    "method_name,parameters",
    [
        pytest.param("get_all_indicators", {}, id="get_all_indicators"),
        pytest.param("iter_indicators", {}, id="iter_indicators"),
    ],
)
@pytest.mark.asyncio
async def test_invalid_indicator_response_code_leads_to_dragos_api_error_and_retried(
    error_code, method_name, parameters, valid_client
):
    """Test that invalid response code leads to DragosAPIError and was retried N times before."""
    # Given
    # A valid Client API
    client = valid_client
    # A mock get method returning an invalid response
    client._get = AsyncMock()
    client._get.return_value = Mock()
    client._get.return_value.text = AsyncMock()
    client._get.return_value.raise_for_status = MagicMock(
        side_effect=ClientResponseError(
            request_info=Mock(),
            history=Mock(),
            status=error_code,
            message="Message",
            headers=Mock(),
        )
    )
    # When making a request
    # Then a DragosAPIError is raised after 3 retries
    with pytest.raises(DragosAPIError):
        method = getattr(client, method_name)
        # if method is async_generator
        if inspect.isasyncgenfunction(method):
            async for _ in method(**parameters):
                pass
        else:  # else
            _ = await method(**parameters)

    assert client._get.call_count == client._retry  # noqa: S101
