# isort:skip_file
# pragma: no cover
"""Provide tests for client_api.v1.product module.

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
from typing import AsyncIterator

from client_api.errors import DragosAPIError
from client_api.v1.product import (
    TagResponse,
    ProductResponse,
    ProductsResponse,
    ProductClientAPIV1,
)
from client_api.warning import ValidationWarning


# Define a dict to be reused in other responses containing it.
# A fixture cannot be called directly in another fixture.
_valid_tag_response = {  #
    "text": "my_text",
    "tag_type": "my_type",
}


@pytest.fixture
def valid_tag_response():
    """Return a valid TagResponse.

    Fixture used to be able to alterate the response in tests.
    """
    return _valid_tag_response


_valid_product_response = {
    "tags": [_valid_tag_response],
    "tlp_level": "amber",
    "title": "my_title",
    "executive_summary": "my_summary",
    "updated_at": "2023-10-01T00:00:00Z",
    "threat_level": 3,
    "serial": "12345",
    "ioc_count": 10,
    "release_date": "2023-10-01T00:00:00Z",
    "type": "report",
    "report_link": "http://example.com/report",
    "ioc_csv_link": "http://example.com/ioc.csv",
    "ioc_stix2_link": "http://example.com/ioc.stix2",
    "slides_link": "http://example.com/slides",
}


@pytest.fixture
def valid_product_response():
    """Return a valid ProductResponse.

    Fixture used to be able to alterate the response in tests.
    """
    return _valid_product_response


_valid_products_response = {
    "products": [_valid_product_response],
    "total": 1,
    "page_size": 1,
    "total_pages": 1,
    "page": 1,
}


@pytest.fixture
def valid_products_response():
    """Return a valid ProductsResponse.

    Fixture used to be able to alterate the response in tests.
    """
    return _valid_products_response


@pytest.fixture
def valid_client():
    """Return a ProductClientAPIV1 instance."""
    return ProductClientAPIV1(
        base_url=URL("http://example.com"),
        token=SecretStr("my_token"),
        secret=SecretStr("my_secret"),
        timeout=timedelta(seconds=10),
        retry=3,
        backoff=timedelta(microseconds=1),  # No need to wait for test
    )


def test_tag_response_with_correct_inputs_is_successfully_instantiated(
    valid_tag_response,
):
    """Test that the TagResponse is successfully instantiated with correct inputs."""
    # Given correct inputs
    # When instantiating the TagResponse
    # Then attribute values are correctly set
    with warnings.catch_warnings():
        warnings.simplefilter("error", ValidationWarning)
        tag_response = TagResponse.model_validate(valid_tag_response)
    assert (  # noqa: S101 we indeed call assert during test
        tag_response.text == "my_text" and tag_response.tag_type == "my_type"
    )


def test_product_response_with_correct_inputs_is_successfully_instantiated(
    valid_product_response,
):
    """Test that the ProductResponse is successfully instantiated with correct inputs."""
    # Given correct inputs
    # When instantiating the ProductResponse
    # Then attribute values are correctly set
    with warnings.catch_warnings():
        warnings.simplefilter("error", ValidationWarning)
        product_response = ProductResponse.model_validate(valid_product_response)
    assert product_response.tlp_level == "amber"  # noqa: S101
    # in fact we just check there is no error due to breaking changes


def test_products_response_with_correct_inputs_is_successfully_instantiated(
    valid_products_response,
):
    """Test that the ProductsResponse is successfully instantiated with correct inputs."""
    # Given correct inputs
    # When instantiating the ProductsResponse
    # Then attribute values are correctly set
    with warnings.catch_warnings():
        warnings.simplefilter("error", ValidationWarning)
        products_response = ProductsResponse.model_validate(valid_products_response)
    assert products_response.page == 1  # noqa: S101
    # in fact we just check there is no error due to breaking changes


@pytest.mark.parametrize(
    "parameter_name,incorrect_value",
    [
        pytest.param("page", 0, id="page_0"),
        pytest.param(
            "updated_after",
            datetime.now(timezone.utc) + timedelta(days=1),
            id="updated_after_in_future",
        ),
        pytest.param(
            "released_after",
            datetime.now(timezone.utc) + timedelta(days=1),
            id="released_after_in_future",
        ),
    ],
)
@patch("client_api.v1.product.BaseClientAPIV1.get")
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
        pytest.param("get_product", {"serial": "12345"}, id="get_product"),
        pytest.param("get_all_products", {}, id="get_all_products"),
        pytest.param("iter_products", {}, id="get_products"),
    ],
)
@pytest.mark.asyncio
async def test_invalid_product_response_content_leads_to_dragos_api_error(
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
        elif inspect.iscoroutinefunction(method):
            _ = await method(**parameters)
        else:
            result = method(**parameters)
            if isinstance(result, AsyncIterator):
                async for _ in result:
                    pass
            else:
                raise NotImplementedError


@pytest.mark.parametrize(
    "method_name,parameters",
    [
        pytest.param("sync_iter_products", {}, id="sync_iter_products"),
    ],  # TO BE EXTENDED
)
def test_synchrone_invalid_product_response_content_leads_to_dragos_api_error(
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
        iterator = method(**parameters)
        for item in iterator:
            _ = item


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
        pytest.param("get_product", {"serial": "12345"}, id="get_product"),
        pytest.param("get_all_products", {}, id="get_all_products"),
        pytest.param("iter_products", {}, id="get_products"),
        pytest.param("get_product_pdf", {"serial": "12345"}, id="get_product_pdf"),
    ],
)
@pytest.mark.asyncio
async def test_invalid_product_response_code_leads_to_dragos_api_error_and_retried(
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
    # When making a request
    # Then a DragosAPIError is raised
    with pytest.raises(DragosAPIError):
        method = getattr(client, method_name)
        # if method is async_generator
        if inspect.isasyncgenfunction(method):
            async for _ in method(**parameters):
                pass
        elif inspect.iscoroutinefunction(method):
            _ = await method(**parameters)
        else:
            result = method(**parameters)
            if isinstance(result, AsyncIterator):
                async for _ in result:
                    pass
            else:
                raise NotImplementedError

    assert client._get.call_count == client._retry  # noqa: S101
