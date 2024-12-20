"""Provide error classes for the Tenable Security Center integration."""


class DataRetrievalError(BaseException):
    """Base exception when an error occurs while retrieving data."""


class AssetRetrievalError(DataRetrievalError):
    """Raised when an error occurs while retrieving an asset."""


class FindingRetrievalError(DataRetrievalError):
    """Raised when an error occurs while retrieving a finding."""


class CVERetrievalError(DataRetrievalError):
    """Raised when an error occurs while retrieving an asset."""


class ConfigLoaderError(BaseException):
    """Exception for configuration loader errors."""
