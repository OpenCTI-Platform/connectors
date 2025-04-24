"""Provide the interface of the connector for configuration and dragos report."""

from .common import DataRetrievalError
from .geocoding import (
    Area,
    City,
    Country,
    Geocoding,
    GeocodingRetrievalError,
    Position,
    Region,
)
from .report import Indicator, Report, ReportRetrievalError, Reports, Tag

__all__ = [
    "Area",
    "City",
    "Country",
    "DataRetrievalError",  # for error handling in application layer
    "Geocoding",  # for typing purposes in application layer
    "GeocodingRetrievalError",  # for error handling in application or usecase layers
    "Indicator",  # for typing purposes in application layer
    "Position",
    "Region",
    "Report",  # for typing purposes in application layer
    "ReportRetrievalError",  # for error handling in application layer
    "Reports",  # for typing purposes in application layer
    "Tag",  # for typing purposes in application layer
]
