"""Expose ``ConnectorSettings`` to the manager-supported config schema generator.

At runtime the *contents* of ``src/`` are the working directory (see the
Dockerfile), so the connector imports its own modules top-level, e.g.
``from connector.settings import ConnectorSettings``.

The config schema generator instead runs from the connector root and imports
``from src import ConnectorSettings``. Adding this package's own directory to
``sys.path`` lets the connector's existing top-level import style resolve in
that context too, without changing any runtime behaviour.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from connector.settings import ConnectorSettings  # isort: skip

__all__ = ["ConnectorSettings"]
