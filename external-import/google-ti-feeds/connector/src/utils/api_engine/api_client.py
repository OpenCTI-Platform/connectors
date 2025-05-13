"""API Client will orchestrate API calls."""

from typing import Any, Dict, Optional, Type

from pydantic import BaseModel

from .api_request_model import ApiRequestModel
from .exceptions.api_error import ApiError
from .exceptions.api_http_error import ApiHttpError
from .exceptions.api_ratelimit_error import ApiRateLimitError
from .exceptions.api_timeout_error import ApiTimeoutError
from .exceptions.api_validation_error import ApiValidationError
from .interfaces.base_request_strategy import BaseRequestStrategy


class ApiClient:
    """Orchestrates API calls."""

    def __init__(self, strategy: BaseRequestStrategy) -> None:
        """Initialize the API client with a request strategy."""
        self.strategy = strategy

    async def call_api(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json_payload: Optional[Dict[str, Any]] = None,
        response_key: Optional[str] = None,
        model: Optional[Type[BaseModel]] = None,
        timeout: Optional[float] = None,
    ) -> Any:
        """Call the API using the provided strategy.

        Args:
            url (str): The URL to call.
            method (str): The HTTP method to use.
            headers (Optional[Dict[str, Any]]): The headers to include in the request.
            params (Optional[Dict[str, Any]]): The query parameters to include in the request.
            data (Optional[Dict[str, Any]]): The data to include in the request.
            json_payload (Optional[Dict[str, Any]]): The JSON data to include in the request.
            response_key (Optional[str]): The key to extract from the response.
            model (Optional[Type[BaseModel]]): The model to deserialize the response into.
            timeout (Optional[float]): The timeout for the request.

        Returns:
            Any: The response from the API.

        Raises:
            ApiError: If the API call fails.

        """
        try:
            api_request = ApiRequestModel(
                url=url,
                method=method,
                headers=headers,
                params=params,
                data=data,
                json_payload=json_payload,
                response_key=response_key,
                model=model,
                timeout=timeout,
            )
            response = await self.strategy.execute(api_request)

            return response
        except (
            ApiTimeoutError,
            ApiRateLimitError,
            ApiHttpError,
            ApiValidationError,
        ) as known_api_err:
            raise known_api_err
        except Exception as e:
            raise ApiError(f"Failed to call API: {e}") from e
