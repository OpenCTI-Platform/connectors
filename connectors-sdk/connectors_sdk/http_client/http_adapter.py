from datetime import timedelta
from typing import Any

import requests
from requests.adapters import HTTPAdapter, Retry
from limits import RateLimitItemPerSecond, storage, strategies

from connectors_sdk.http_client.exceptions import HttpClientRateLimitError


class RateLimit:
    def __init__(
        self,
        url: str,
        rate_limit: int = 0,
        rate_interval: timedelta = timedelta(seconds=0),
    ) -> None:
        if rate_limit <= 0 or rate_interval.total_seconds() <= 0:
            return

        limits_storage = storage.MemoryStorage()

        self._rate_limiter = strategies.FixedWindowRateLimiter(limits_storage)
        self._rate_limit = RateLimitItemPerSecond(
            rate_limit, int(rate_interval.total_seconds())
        )
        self._url = url

    def check(self) -> None:
        if not hasattr(self, "_rate_limiter") or not hasattr(self, "_rate_limit"):
            return

        if not self._rate_limiter.hit(self._rate_limit):
            raise HttpClientRateLimitError(
                f"Rate limit of {self._rate_limit.amount} exceeded for {self._url}"
            )


class RateLimitHTTPAdapter(HTTPAdapter):
    """HTTPAdapter that enforces a rate limit before every send attempt, including retries."""

    def __init__(
        self,
        rate_limit: RateLimit,
        max_retries: Retry | int = 0,
        **kwargs: Any,
    ) -> None:
        self._rate_limit = rate_limit
        super().__init__(max_retries=max_retries, **kwargs)

    def send(
        self, request: requests.PreparedRequest, **kwargs: Any
    ) -> requests.Response:
        self._rate_limit.check()
        return super().send(request, **kwargs)
