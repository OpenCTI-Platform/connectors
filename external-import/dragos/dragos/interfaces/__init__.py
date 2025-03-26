"""Provide the interface of the connector for configuration and dragos report."""

from .config import ConfigLoader, ConfigRetrievalError
from .geocoding import Geocoding, GeocodingRetrievalError
from .report import ReportRetrievalError, Reports
from .report import _Report as Report

__all__ = [
    "ConfigRetrievalError",  # for error handling in application layer
    "ConfigLoader",  # for typing purposes in application layer
    "ReportRetrievalError",  # for error handling in application layer
    "Report",  # for typing purposes in application layer
    "Reports",  # for typing purposes in application layer
    "GeocodingRetrievalError",  # for error handling in application or usecase layers
    "Geocoding",  # for typing purposes in application layer
]
