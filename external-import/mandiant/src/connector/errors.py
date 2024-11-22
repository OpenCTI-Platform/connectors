"""Provide Exceptions for the connector."""


class ConnectorError(BaseException):
    """Base class for all exceptions in the connector."""


class StateError(ConnectorError):
    """Error raised when the connector has an invalid state."""
