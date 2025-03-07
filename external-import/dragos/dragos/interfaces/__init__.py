"""Provide the interface of the connector for configuration and dragos report."""

from .config import ConfigLoader, ConfigRetrievalError
from .report import DataRetrievalError, Reports
from .report import _Indicator as Indicator
from .report import _Report as Report
from .report import _Tag as Tag

__all__ = [
    "ConfigRetrievalError",  # for error handling in application layer
    "ConfigLoader",  # for typing purposes in application layer
    "DataRetrievalError",  # for error handling in application layer
    "Indicator",  # for typing purposes in application layer
    "Report",  # for typing purposes in application layer
    "Reports",  # for typing purposes in application layer
    "Tags",  # for typing purposes in application layer
]
