"""Pytest configuration for the Matrix external-import connector tests.

The tests only exercise the dependency-free helpers under
``src/lib/helpers.py`` — ``TLP_MAP``, :func:`resolve_tlp` and
:func:`media_content_id` — plus a couple of small static helpers from
``src/main.py`` (channel / identity naming, timestamp coercion) that
have no ``matrix-nio`` / ``libolm`` dependency. We just put the
connector ``src`` directory on ``sys.path`` so the test modules can
``from lib.helpers import ...`` (and import the static helpers from
``main``) without pulling in the asyncio runtime or ``libolm``.

``pycti`` and ``stix2`` are pulled in through the test requirements
file; ``matrix-nio`` / ``libolm`` are deliberately **not** required so
the suite runs on a vanilla CI runner.
"""

import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
