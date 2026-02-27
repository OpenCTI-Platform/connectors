# isort:skip_file
"""Offer public classes and methods for the Dragos API V1 endpoints."""

from typing import TYPE_CHECKING, Optional


from .indicator import IndicatorClientAPIV1
from .product import ProductClientAPIV1

if TYPE_CHECKING:
    from datetime import timedelta

    from limiter import Limiter  # type: ignore[import-untyped]  # Limiter is not typed
    from pydantic import SecretStr
    from yarl import URL


class DragosClientAPIV1:
    """Client for the Dragos API V1 endpoints."""

    def __init__(
        self: "DragosClientAPIV1",
        base_url: "URL",
        token: "SecretStr",
        secret: "SecretStr",
        timeout: "timedelta",
        retry: int,
        backoff: "timedelta",
        rate_limiter: Optional["Limiter"] = None,
    ) -> None:
        """Initialize the Dragos API V1 client."""
        self.indicator = IndicatorClientAPIV1(
            base_url=base_url,
            token=token,
            secret=secret,
            timeout=timeout,
            retry=retry,
            backoff=backoff,
            rate_limiter=rate_limiter,
        )
        self.product = ProductClientAPIV1(
            base_url=base_url,
            token=token,
            secret=secret,
            timeout=timeout,
            retry=retry,
            backoff=backoff,
            rate_limiter=rate_limiter,
        )
