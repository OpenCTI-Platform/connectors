class ConnectorClientError(Exception):
    def __init__(self, message, metadata):
        self.message = message
        self.metadata = metadata
