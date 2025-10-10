"""Offer Exception handling tools to develop connectors."""

from .error import (
    ConfigError,
    ConfigNotFoundError,
    ConfigValidationError,
    DataRetrievalError,
    UseCaseError,
)

__all__ = [
    "ConfigError",
    "ConfigValidationError",
    "ConfigNotFoundError",
    "UseCaseError",
    "DataRetrievalError",
]
