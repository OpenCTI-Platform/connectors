"""Expose ``ConnectorSettings`` for the manager-supported config schema generator.

The schema generator imports the model via ``from src import ConnectorSettings``
(with a ``from src.main import ConnectorSettings`` fallback). Re-exporting it here
lets the generator discover the settings without changing the connector's layout.
"""

from import_doc_ai.settings import ConnectorSettings

__all__ = ["ConnectorSettings"]
