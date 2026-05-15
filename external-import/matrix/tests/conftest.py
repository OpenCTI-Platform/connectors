"""Pytest configuration for the Matrix external-import connector tests.

The tests only exercise pure-Python helpers from ``src/main.py``
(``_resolve_tlp``, ``_TLP_MAP``, ``MatrixConnector._media_content_id``)
so we just put the connector ``src`` directory on ``sys.path`` and let
the modules import normally. ``pycti`` / ``stix2`` / ``matrix-nio`` are
pulled in through the test requirements file.
"""

import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
