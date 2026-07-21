"""High-level API client facade."""

import logging
from typing import Any

from .interfaces.base_request_strategy import BaseRequestStrategy


class ApiClient:
    """Thin facade over a BaseRequestStrategy for fire-and-forget API calls."""

    def __init__(
        self,
        strategy: BaseRequestStrategy,
        logger: logging.Logger | None = None,
    ) -> None:
        """Initialise with the given request strategy and optional logger.

        Args:
            strategy: Request strategy to delegate calls to.
            logger: Optional logger; defaults to module logger.
        """
        self._strategy = strategy
        self._logger = logger or logging.getLogger(__name__)

    async def close(self) -> None:
        """Close the underlying HTTP session."""
        await self._strategy.close()

    async def call_api(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        response_key: str | None = None,
        response_model: type | None = None,
        timeout: int | None = None,
    ) -> Any:
        """Build an ApiRequestModel and delegate to the strategy.

        Args:
            url: Target URL.
            method: HTTP method (default 'GET').
            headers: Optional request headers.
            params: Optional query parameters.
            data: Optional form data payload.
            json_body: Optional JSON body payload.
            response_key: Optional key to extract from the response dict.
            response_model: Optional Pydantic model to validate the response.
            timeout: Optional request timeout in seconds.

        Returns:
            Parsed response, optionally validated against response_model.
        """
        from .api_request_model import ApiRequestModel

        request = ApiRequestModel(
            url=url,
            method=method,
            headers=headers,
            params=params,
            data=data,
            json_body=json_body,
            response_key=response_key,
            response_model=response_model,
            timeout=timeout,
        )
        return await self._strategy.execute(request)
