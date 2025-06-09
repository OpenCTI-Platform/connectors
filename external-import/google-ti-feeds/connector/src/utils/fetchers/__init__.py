"""Generic fetchers package for flexible API endpoint handling.

This package provides a configurable fetcher system that can work with any API
endpoint, response model, and exception handling requirements.
"""

from .generic_fetcher import GenericFetcher
from .generic_fetcher_config import GenericFetcherConfig
from .generic_fetcher_factory import GenericFetcherFactory

__all__ = [
    "GenericFetcher",
    "GenericFetcherConfig",
    "GenericFetcherFactory",
]
