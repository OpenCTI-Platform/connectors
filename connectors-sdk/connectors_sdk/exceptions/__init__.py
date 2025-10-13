"""Offer Exception handling tools to develop connectors."""

from .error import (
    ConfigError,
    ConfigValidationError,
    DataRetrievalError,
    UseCaseError,
)

__all__ = [
    "ConfigError",
    "ConfigValidationError",
    "UseCaseError",
    "DataRetrievalError",
]
