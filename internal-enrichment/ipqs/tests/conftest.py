"""Pytest configuration for the IPQS connector tests.

The connector ships at ``src/ipqs/`` and is normally imported as
``from ipqs.ipqs import IPQSConnector``. Adding ``src`` to ``sys.path``
lets the test modules ``from ipqs.<module> import <symbol>`` without
the connector's container entrypoint scaffolding.
"""

import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
