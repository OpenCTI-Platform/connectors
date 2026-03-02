# isort:skip_file
"""Offer Common tools for the Dragos API V1 endpoints."""
import json
from abc import ABC
from logging import DEBUG, getLogger
from typing import TYPE_CHECKING, Any, Optional

from aiohttp import (
    ClientConnectionError,
    ClientResponseError,
    ClientSession,
    ClientTimeout,
    ContentTypeError,
)
from limiter import Limiter  # type: ignore[import-untyped]  # Limiter is not typed
from pydantic import Field, SecretStr, ValidationError
from tenacity import (
    AsyncRetrying,
    RetryError,
    after_log,
    retry_if_exception_type,
    stop_after_attempt,
    wait_fixed,
)
from yarl import URL

from client_api.errors import DragosAPIError
from client_api.warning import PermissiveBaseModel

if TYPE_CHECKING:
    from datetime import timedelta

    from aiohttp import ClientResponse


ResponseModel = PermissiveBaseModel  # Alias

logger = getLogger(__name__)


class BaseAPIV1BulkResponse(ResponseModel):
    """Base class for bulk responses."""

    total: int = Field(..., description="Total number of item available.")
    page: int = Field(..., description="Current page number in pagination.")
    page_size: int = Field(..., description="Number of item per page.")
    total_pages: int = Field(..., description="Total number of pages available.")


class BaseClientAPIV1(ABC):  # noqa: B024
    """Base class for the Dragos API v1 client."""

    def __init__(
        self: "BaseClientAPIV1",
        base_url: URL,
        token: "SecretStr",
        secret: "SecretStr",
        timeout: "timedelta",
        retry: int,
        backoff: "timedelta",
        rate_limiter: Optional[Limiter] = None,
    ) -> None:
        """Initialize the client.

        Args:
            base_url (URL): The base URL of the TAP API.
            token (SecretStr): The token to authenticate with the API.
            secret (SecretStr): The secret to authenticate with the API.
            timeout (timedelta): The timeout for the API requests.
            retry (int): The number of attempt to perform.
            backoff (timedelta): The backoff time between retries.
            rate_limiter (Limiter): Bucket rate limiter instance.

        """
        self._base_url = base_url / "api" / "v1"
        timeout_seconds: float = timeout.total_seconds()
        self._timeout = ClientTimeout(total=timeout_seconds)
        self._retry = retry
        self._backoff_seconds: float = backoff.total_seconds()
        self._headers = {"accept": "*/*", "API-Token": token, "API-Secret": secret}
        self._rate_limiter: Optional[Limiter] = rate_limiter

    def format_get_query(
        self: "BaseClientAPIV1", path: str, params: dict[str, Any] | None = None
    ) -> URL:
        """Format a query URL.

        Args:
            path (str): The path of the URL to be concatenate with the base_url.
            params (Optional[Dict[str, Any]]): The query parameters.

        Returns:
            URL: The URL object.

        """
        params = params or {}

        # jsonify bool value if any:
        for key, value in params.items():
            if isinstance(value, bool):
                params[key] = json.dumps(value)

        # filter to remove all None values
        params = {k: v for k, v in params.items() if v is not None}

        return (self._base_url / path).update_query(params)

    async def _process_raw_response(
        self: "BaseClientAPIV1", response: "ClientResponse"
    ) -> dict[str, Any]:
        """Process the response from the API.

        Args:
            response (ClientResponse): The raw response from the API.

        Returns:
            dict: The processed response.

        Raises:
            DragosAPIError: If the response is invalid.

        """
        try:
            data = await response.json()
        except ContentTypeError:
            try:
                text_data = await response.text()
                data = json.loads(text_data)
            except json.JSONDecodeError as e:
                logger.warning(f"Error while decoding JSON: {e}")
                raise DragosAPIError("Invalid response from the API") from e
        return dict(data)

    async def _get(self: "BaseClientAPIV1", query_url: URL) -> "ClientResponse":
        """Perform a GET request with retry logic."""
        # Explicit casting to str for typing
        headers: dict[str, str] = {
            str(k): str(v.get_secret_value()) if isinstance(v, SecretStr) else str(v)
            for k, v in self._headers.items()
        }
        async with ClientSession(
            headers=headers,
            timeout=self._timeout,
            trust_env=True,
        ) as session:
            async with session.get(query_url) as resp:
                _ = await resp.read()  # consume the response
                return resp

    async def _get_retry(self: "BaseClientAPIV1", query_url: URL) -> "ClientResponse":
        """Perform a GET request with retry logic."""
        try:
            async for attempt in AsyncRetrying(
                retry=retry_if_exception_type(
                    (ClientConnectionError, ClientResponseError)
                ),
                stop=stop_after_attempt(self._retry),
                wait=wait_fixed(self._backoff_seconds),
                after=after_log(logger, DEBUG),
            ):
                with attempt:
                    response = await self._get(query_url)
                    response.raise_for_status()
        except RetryError as e:
            try:
                e.reraise()
            except ClientResponseError as e:
                resp_text = await response.text()
                message = f"{e.message} - {resp_text} - query: {response.url}"
                raise DragosAPIError(message) from e
            except ClientConnectionError as e:
                message = f"Cannot connect to the API: {e}"
                raise DragosAPIError(message) from e
        return response

    async def get(
        self, query_url: URL, response_model: type[ResponseModel]
    ) -> ResponseModel:
        """Perform a GET request.

        You should use format_get_query to format the query URL.

        Args:
            query_url (str): The URL to query.
            response_model (type[T]): The model to validate the response.

        Returns:
            (BaseModel-like): The validated response.

        Raises:
            DragosAPIError: If the response is invalid.

        """
        if self._rate_limiter:  # rate_limiter is optional
            async with self._rate_limiter:
                response = await self._get_retry(query_url)
        else:
            response = await self._get_retry(query_url)
        data = await self._process_raw_response(response)
        try:
            return response_model.model_validate(data)
        except ValidationError as e:
            message = f"Invalid response from the API: {e}"
            logger.warning(message)
            raise DragosAPIError(message) from e
