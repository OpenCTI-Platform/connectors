"""Pytest configuration for the ``intel471-darknet`` connector tests.

The connector source lives in a flat ``src`` directory (``main.py``,
``settings.py`` and the ``lib`` package), so it is added to ``sys.path``
and the test modules can import ``main``, ``settings`` and
``lib.<module>`` directly.
"""

import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
