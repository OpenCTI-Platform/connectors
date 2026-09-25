"""Intel 471 Hunter connector package.

`ConnectorSettings` is re-exported here so the manager-supported config-schema
generator (`mise gs`), which imports it as `from src import ConnectorSettings`,
can discover the connector's Pydantic configuration model.
"""

from src.settings import ConnectorSettings

__all__ = ["ConnectorSettings"]
