"""DataDog external-import connector.

``ConnectorSettings`` is re-exported here so the manager-supported config
schema generator can import it with ``from src import ConnectorSettings``.
"""

from settings import ConnectorSettings

__all__ = ["ConnectorSettings"]
