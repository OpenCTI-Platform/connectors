import asyncio
import logging
import random

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
            # Use explicit read/connect phases and a larger budget than sync mode
            # to reduce false positives on slow NVD responses.
            timeout = aiohttp.ClientTimeout(
                total=180,
                connect=30,
                sock_connect=30,
                sock_read=120,
            )
            self._session = aiohttp.ClientSession(
                headers=self._headers,
                timeout=timeout,
            )
        return self._session

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    async def _reset_session(self) -> None:
        """Drop current session so next retry gets a fresh TCP connection."""
        if self._session and not self._session.closed:
            await self._session.close()
        self._session = None

    @staticmethod
    def _compute_retry_wait(attempt: int, backoff_factor: int) -> float:
        # Exponential backoff + jitter to avoid synchronized retry bursts.
        base_wait = backoff_factor * (2**attempt)
        return base_wait + random.uniform(0.0, 1.0)

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
                        retry_after = response.headers.get("Retry-After")
                        wait = self._compute_retry_wait(attempt, backoff_factor)
                        if retry_after:
                            try:
                                wait = max(wait, float(retry_after))
                            except ValueError:
                                pass
                        self.helper.connector_logger.warning(
                            f"[API] Retryable status {response.status}, "
                            f"waiting {wait:.2f}s (attempt {attempt + 1}/{max_retries})"
                        )
                        await self._reset_session()
                        await asyncio.sleep(wait)
                        continue

                    raise Exception(
                        f"[API] Request to {api_url} failed with status "
                        f"{response.status}"
                    )
            except (aiohttp.ClientError, TimeoutError) as err:
                # TimeoutError (asyncio.TimeoutError) is not a subclass of
                # aiohttp.ClientError, so it must be caught separately.
                if attempt < max_retries:
                    wait = self._compute_retry_wait(attempt, backoff_factor)
                    self.helper.connector_logger.warning(
                        f"[API] Transient error, waiting {wait}s "
                        f"(attempt {attempt + 1}/{max_retries}); "
                        f"{type(err).__name__}: {repr(err)}"
                    )
                    await self._reset_session()
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
