"""PolySwarm Sandbox connector for OpenCTI."""


def __getattr__(name):
    """Lazy imports to avoid requiring connectors_sdk at import time."""
    if name == "ConnectorSettings":
        from connector.models.configs.settings import ConnectorSettings

        return ConnectorSettings
    if name == "PolySwarmSandboxConnector":
        from connector.polyswarm_connector import PolySwarmConnector

        return PolySwarmConnector
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["ConnectorSettings", "PolySwarmSandboxConnector"]
