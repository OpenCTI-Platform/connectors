"""
Custom exceptions designed to provide more context
in any fatal errors that occur.
"""


class StreamConnectorError(Exception):
    """
    Base Exception class for errors. All other
    classes inherit from this one.
    """

    pass


class SentinelOnePermissionError(StreamConnectorError):
    """Raised when there are permission/authentication issues."""

    pass


class ConnectorConfigurationError(StreamConnectorError):
    """Raised when there are configuration issues."""

    pass


class StixConversionError(StreamConnectorError):
    """Raised when there are STIX conversion issues."""

    pass


class APIError(StreamConnectorError):
    """Raised when there are API communication issues."""

    pass
