__all__ = ["ConnectorSettings", "RansomwareAPIConnector"]


def __getattr__(name: str):
    if name == "ConnectorSettings":
        from ransomwarelive.settings import ConnectorSettings

        return ConnectorSettings
    if name == "RansomwareAPIConnector":
        from ransomwarelive.ransom_conn import RansomwareAPIConnector

        return RansomwareAPIConnector
    raise AttributeError(name)
