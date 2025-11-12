class ConnectorWarning(Exception):
    """Base class for all warnings raised by the Connector"""


class ConnectorError(Exception):
    """Base class for all errors raised by the Connector"""


class ConfigRetrievalError(ConnectorError):
    """Known errors wrapper for config loaders."""


class InvalidTlpLevelError(ConnectorError):
    """Error raised when the TLP level is invalid."""
