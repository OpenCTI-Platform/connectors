from typing import Any, Literal

import requests
from requests.adapters import HTTPAdapter, Retry
from limits import storage, strategies, parse

from connectors_sdk.http_client.exceptions import HttpClientRateLimitError
from pydantic import HttpUrl


class RateLimit:
    def __init__(
        self,
        url: HttpUrl | str,
        rate_limit: int | None = None,
        rate_expiry: (
            tuple[
                int,
                Literal[
                    "day",
                    "month",
                    "year",
                    "hour",
                    "minute",
                    "second",
                ],
            ]
            | None
        ) = None,
    ) -> None:
        if rate_limit and rate_expiry:
            # The `limits` library provides a `parse` method that expects a specific format
            # See https://limits.readthedocs.io/en/latest/quickstart.html#rate-limit-string-notation
            self._rate_limit = parse(
                f"{rate_limit} per {rate_expiry[0]} {rate_expiry[1]}"
            )
            self._rate_limiter = strategies.FixedWindowRateLimiter(
                storage.MemoryStorage()
            )
        else:
            self._rate_limit = None
            self._rate_limiter = None

        self._url = str(url)

    def check(self) -> None:
        if self._rate_limiter is None or self._rate_limit is None:
            return

        if not self._rate_limiter.hit(self._rate_limit, self._url):
            raise HttpClientRateLimitError(
                f"Requests on {self._url} exceeded rate limit of {self._rate_limit}(s)"
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
