from connector.settings import ConnectorSettings

__all__ = [
    "ConnectorSettings",
    "ModatConnector",
]


def __getattr__(name: str):
    if name == "ModatConnector":
        from connector.connector import ModatConnector

        return ModatConnector
    raise AttributeError(f"module 'connector' has no attribute {name!r}")
