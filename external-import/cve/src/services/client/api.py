import asyncio
import logging

import aiohttp
from src.services.utils.rate_limiter import AsyncRateLimiter

logger = logging.getLogger(__name__)


class CVEClient:
    """Async HTTP client for the NVD API (CVE & CPE Match)."""

    def __init__(
        self,
        api_key: str,
        helper,
        header: str,
        rate_limiter: AsyncRateLimiter,
    ):
        self.token = api_key
        self.helper = helper
        self._rate_limiter = rate_limiter
        self._headers = {"apiKey": api_key, "User-Agent": header}
        self._session: aiohttp.ClientSession | None = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=60)
            self._session = aiohttp.ClientSession(
                headers=self._headers,
                timeout=timeout,
            )
        return self._session

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    async def request(self, api_url: str, params: dict | None = None):
        """Make a rate-limited GET request with retry logic."""
        max_retries = 4
        backoff_factor = 6
        retryable_statuses = {429, 500, 502, 503, 504}

        for attempt in range(max_retries + 1):
            await self._rate_limiter.acquire()
            session = await self._get_session()

            try:
                async with session.get(api_url, params=params) as response:
                    if response.status == 200:
                        return await response.json()

                    if response.status == 404:
                        error_data = dict(response.headers)
                        if error_data.get("message") == "Invalid apiKey.":
                            raise Exception(
                                "[API] Invalid API Key provided. "
                                "Please check your configuration."
                            )
                        raise Exception(f"[API] Error: {error_data.get('message')}")

                    if response.status in retryable_statuses and attempt < max_retries:
                        wait = backoff_factor * (2**attempt)
                        self.helper.connector_logger.warning(
                            f"[API] Retryable status {response.status}, "
                            f"waiting {wait}s (attempt {attempt + 1}/{max_retries})"
                        )
                        await asyncio.sleep(wait)
                        continue

                    raise Exception(
                        f"[API] Request to {api_url} failed with status "
                        f"{response.status}"
                    )
            except aiohttp.ClientError as err:
                if attempt < max_retries:
                    wait = backoff_factor * (2**attempt)
                    self.helper.connector_logger.warning(
                        f"[API] Connection error, waiting {wait}s "
                        f"(attempt {attempt + 1}/{max_retries}): {err}"
                    )
                    await asyncio.sleep(wait)
                    continue
                raise

        raise Exception(
            "[API] Attempting to retrieve data failed. Wait for connector to re-run..."
        )

    async def get_complete_collection(self, api_url: str, params: dict | None = None):
        """Fetch a JSON collection from the given NVD API endpoint."""
        try:
            info_msg = f"[API] HTTP Get Request to endpoint for path ({api_url})"
            self.helper.connector_logger.debug(info_msg)

            data = await self.request(api_url, params)
            return data

        except Exception as err:
            self.helper.connector_logger.error(str(err), meta={"error": str(err)})
            return None
