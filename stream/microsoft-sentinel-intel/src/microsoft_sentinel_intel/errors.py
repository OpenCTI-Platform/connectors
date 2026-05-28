class ConnectorError(Exception):
    def __init__(self, message: str, metadata: dict | None = None):
        self.message = message
        self.metadata = metadata


class ConnectorWarning(ConnectorError):
    pass


class ConnectorClientError(ConnectorError):
    pass


class ConnectorConfigError(ConnectorError):
    pass
