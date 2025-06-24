"""API Client will orchestrate API calls."""

import logging
from typing import TYPE_CHECKING, Any, Dict, Optional, Type

from pydantic import BaseModel

from .api_request_model import ApiRequestModel
from .exceptions.api_error import ApiError
from .exceptions.api_http_error import ApiHttpError
from .exceptions.api_network_error import ApiNetworkError
from .exceptions.api_ratelimit_error import ApiRateLimitError
from .exceptions.api_timeout_error import ApiTimeoutError
from .exceptions.api_validation_error import ApiValidationError
from .interfaces.base_request_strategy import BaseRequestStrategy

if TYPE_CHECKING:
    from logging import Logger

LOG_PREFIX = "[API Client]"


class ApiClient:
    """Orchestrates API calls."""

    def __init__(
        self, strategy: BaseRequestStrategy, logger: Optional["Logger"] = None
    ) -> None:
        """Initialize the API client with a request strategy."""
        self.strategy = strategy
        self._logger = logger or logging.getLogger(__name__)

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
        self._logger.debug(
            f"{LOG_PREFIX} Preparing to call API: {method} {url} (Model: {model.__name__ if model else 'No'}, "
            f"ResponseKey: {response_key}, Timeout: {timeout})"
        )
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
            self._logger.debug(f"{LOG_PREFIX} API call to {method} {url} successful.")
            return response
        except (
            ApiTimeoutError,
            ApiRateLimitError,
            ApiHttpError,
            ApiNetworkError,
            ApiValidationError,
        ) as known_api_err:
            error_type = type(known_api_err).__name__
            error_prefix = (
                "Network connectivity issue"
                if isinstance(known_api_err, ApiNetworkError)
                else "Known API error"
            )

            self._logger.error(
                f"{LOG_PREFIX} {error_prefix} during call_api for {method} {url}: {error_type} - {known_api_err}",
            )
            raise known_api_err
        except ApiError as api_err:
            self._logger.error(
                f"{LOG_PREFIX} API error during call_api for {method} {url}: {api_err}",
            )
            raise api_err
        except Exception as e:
            self._logger.error(
                f"{LOG_PREFIX} Unexpected failure in call_api for {method} {url}: {e}",
            )
            raise ApiError(f"Failed to call API {method} {url}: {e}") from e
