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
    pass


class ConnectorConfigurationError(StreamConnectorError):
    pass
