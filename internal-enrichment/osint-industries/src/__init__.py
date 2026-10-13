# -*- coding: utf-8 -*-
"""Package entry point of the OSINT Industries enrichment connector.

`ConnectorSettings` is re-exported here so the manager-supported config schema
generator can resolve it through `from src import ConnectorSettings`.
"""

from .osint_industries.settings import ConnectorSettings

__all__ = ["ConnectorSettings"]
