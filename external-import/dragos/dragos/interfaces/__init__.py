"""Provide the interface of the connector for configuration and dragos report."""

from .common import DataRetrievalError
from .config import ConfigLoader, ConfigRetrievalError
from .geocoding import Geocoding, GeocodingRetrievalError
from .report import ReportRetrievalError, Reports
from .report import _Indicator as Indicator
from .report import _Report as Report
from .report import _Tag as Tag

__all__ = [
    "ConfigLoader",  # for typing purposes in application layer
    "ConfigRetrievalError",  # for error handling in application layer
    "DataRetrievalError",  # for error handling in application layer
    "Geocoding",  # for typing purposes in application layer
    "GeocodingRetrievalError",  # for error handling in application or usecase layers
    "Indicator",  # for typing purposes in application layer
    "Report",  # for typing purposes in application layer
    "ReportRetrievalError",  # for error handling in application layer
    "Reports",  # for typing purposes in application layer
    "Tag",  # for typing purposes in application layer
]
