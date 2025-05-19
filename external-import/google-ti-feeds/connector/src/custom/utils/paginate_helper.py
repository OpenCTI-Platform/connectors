"""The module contains utility functions for paginated data fetching."""

import logging
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, Optional, Type

if TYPE_CHECKING:
    from logging import Logger

    from connector.src.utils.api_engine.api_client import ApiClient
    from pydantic import BaseModel

# mypy: disable-error-code="attr-defined"


async def _fetch_paginated_data(
    api_client: "ApiClient",
    model: Optional[Type["BaseModel"]],
    url: str,
    headers: Dict[str, str],
    params: Optional[Dict[str, Any]],
    data_processor: Callable[[Any, int, int], Awaitable[None]],
    logger: Optional["Logger"] = None,
) -> None:
    """Fetch paginated data and process it with the provided callback.

    Args:
        api_client: The API client to use for making requests
        model: The model class to use for deserializing the API response
        url: The initial URL to fetch data from
        headers: Headers to send with the request
        params: Query parameters for the initial request
        data_processor: Callback function to process the data from each page
        logger: Optional logger instance for logging purposes

    """
    _api_client = api_client
    _logger = logger or logging.getLogger(__name__)
    current_url: Optional[str] = url
    page_params: Optional[Dict[str, Any]] = params
    retrieved_data_count = 0
    total_data_count = 0
    while current_url:
        response = await _api_client.call_api(
            url=current_url,
            headers=headers,
            params=page_params,
            model=model,
            timeout=60,
        )
        page_params = None

        if not response:
            error_msg = "[Fetcher] API call to {url} did not return a valid response. Stopping pagination."
            if model:
                error_msg = f"[Fetcher] API call to {url} did not return a valid {model.__name__} object. Stopping pagination."
            _logger.error(error_msg)
            break

        if model:
            total_data_count = response.meta.count
            retrieved_data_count += len(response.data)

            if response.data:
                _logger.info(
                    f"[Fetcher] Received {len(response.data)} data over {total_data_count} total."
                )
                await data_processor(response, retrieved_data_count, total_data_count)
            else:
                _logger.info(f"[Fetcher] No data in the current page from {url}.")

            if (
                response.meta
                and response.meta.cursor
                and response.links
                and response.links.next
            ):
                current_url = response.links.next
                _logger.info("[Fetcher] Preparing to fetch next page.")
            else:
                _logger.info(
                    "[Fetcher] No more pages to fetch (cursor/next link criteria not met or end of data)."
                )
                current_url = None
        else:
            await data_processor(response, retrieved_data_count, total_data_count)

            _logger.debug("[Fetcher] Using raw response mode, no pagination handling.")
            current_url = None
