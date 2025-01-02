"""Offer common tools for the TAP API."""
import json
from logging import getLogger
from typing import TYPE_CHECKING, Any, Type, TypeVar
from urllib.parse import urlencode, urlparse, urlunparse

import aiohttp
from aiohttp_retry import RandomRetry, RetryClient

from proofpoint_tap.errors import ProofpointAPIError

if TYPE_CHECKING:
    from types import SimpleNamespace

    from pydantic import BaseModel

T = TypeVar('T', bound="BaseModel")
logger = getLogger(__name__)

class BaseTAPClient:
    """Base class for the TAP API client."""

    def __init__(
            self, 
            base_url: str, 
            principal: str, 
            secret: str, 
            timeout: int,
            retry:int,
            backoff:int,
        ) -> None:
        """Initialize the client.

        Args:
            base_url (str): The base URL of the TAP API.
            principal (str): The principal to authenticate with the API.
            secret (str): The secret to authenticate with the API.
            timeout (int): The timeout for the API requests in seconds.

        """
        scheme, netloc, _, _, _, _ = urlparse(base_url)
        self.base_url_scheme = scheme
        self.base_url_netloc = netloc
        self.auth = aiohttp.BasicAuth(principal, secret)
        self.connect_timeout = timeout
        self.timeout = 5*timeout
        self.retry = retry
        self.backoff = backoff

    def format_get_query(self, path: str, params: dict[str, Any] | None = None) -> str:
        """Format a query URL.

        Args:
            path (str): The path of the URL.
            params (dict): The query parameters.

        Returns:
            str: The formatted URL.

        """
        return urlunparse(
            (
                self.base_url_scheme,  # scheme
                self.base_url_netloc,  # netloc
                path,  # path
                "",  # params
                urlencode(params) if params is not None else "",  # query
                "",  # fragment
            )
        )


    async def get(self, query_url: str, response_model: Type[T]) -> T:
        async with aiohttp.ClientSession(
            auth=self.auth,
            timeout=aiohttp.ClientTimeout(total=self.timeout, sock_connect=self.connect_timeout),
        ) as session:
            # We use a random retry but with min and max the same.
            retry_options = RandomRetry(attempts=self.retry, min_timeout=self.backoff, max_timeout=self.backoff)

            async def _before_retry(
                session: aiohttp.ClientSession,
                trace_config_ctx: "SimpleNamespace",
                params: aiohttp.TraceRequestStartParams,
            ) -> None:
                """Inner method to log the retry attempt."""
                current_attempt = trace_config_ctx.trace_request_ctx['current_attempt']
                if current_attempt > 1:
                    logger.warning(f'Attempt {current_attempt} for {params.method} {params.url}')

            trace_config = aiohttp.TraceConfig()
            trace_config.on_request_start.append(_before_retry)
            async with RetryClient(client_session=session, retry_options=retry_options, trace_configs=[trace_config]) as retry_client:
                async with retry_client.get(query_url) as resp:
                    try:
                        resp.raise_for_status()
                    except aiohttp.ClientResponseError as e:
                        resp_text = await resp.text()
                        message = f"{e.message} - {resp_text} - query: {query_url}"
                        raise ProofpointAPIError(message) from e
                    try:
                        # Unfortunately sometime Content-Type Response is text/plain but content is still json
                        data = await resp.json()
                    except aiohttp.ContentTypeError:
                        data = json.loads(await resp.text())
                    return response_model.model_validate(data)
