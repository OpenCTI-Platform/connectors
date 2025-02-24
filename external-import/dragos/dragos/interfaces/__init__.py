"""Provide the interface of the connector for configuration and dragos report."""

from .config import ConfigLoaderOCTI, ConfigRetrievalError
from .report import DataRetrievalError, Reports
from .report import _Report as Report

__all__ = [
    "ConfigRetrievalError",  # for error handling in application layer
    "ConfigLoaderOCTI",  # for typing purposes in application layer
    "DataRetrievalError",  # for error handling in application layer
    "Report",  # for typing purposes in application layer
    "Reports",  # for typing purposes in application layer
]
