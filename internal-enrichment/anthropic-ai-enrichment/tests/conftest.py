"""Pytest configuration for the Anthropic AI Enrichment connector tests.

The connector ships at ``src/main.py``. Adding ``src`` to ``sys.path`` lets
the test modules ``import main`` directly, without the connector's container
entrypoint scaffolding.
"""

import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
