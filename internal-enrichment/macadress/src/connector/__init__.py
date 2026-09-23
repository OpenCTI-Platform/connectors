from connector.settings import ConnectorSettings

__all__ = [
    "ConnectorSettings",
    "MacadressConnector",
]


def __getattr__(name: str):
    if name == "MacadressConnector":
        from connector.connector import MacadressConnector

        return MacadressConnector
    raise AttributeError(f"module 'connector' has no attribute {name!r}")
