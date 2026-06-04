"""Pytest configuration for the ``intel471-darknet`` connector tests.

The connector's ``main.py`` imports ``pycti`` / ``stix2`` / ``bs4`` /
``requests`` and an Intel 471 specific helper module, none of which is
available on a minimal CI runner. The test suite therefore only
exercises the **dependency-free** helper modules under ``src/lib/``:

* ``lib.redaction`` (``test_redaction.py``) — query / fragment
  redaction for URLs included in connector log lines.

We simply add the connector ``src`` directory to ``sys.path`` so the
test modules can ``from lib.<module> import <symbol>`` without
pulling in ``pycti`` / ``stix2`` / ``requests`` / ``bs4``.
"""

import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
