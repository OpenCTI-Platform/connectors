"""Pytest configuration for the ``export-file-ods`` connector tests.

The connector's ``main.py`` imports ``unogenerator`` (which itself loads
the LibreOffice ``uno`` C extension and is not pip-installable on a
stock CI runner). The test suite therefore only exercises the
**dependency-free** helper modules under ``src/lib/``:

* ``lib.sanitization`` (``test_sanitize_cell.py``) — leading
  control-character stripping and formula-trigger escaping.
* ``lib.rendering`` (``test_render_dict_item.py``) — list-of-dict
  cell rendering strategies.

We just add the connector ``src`` directory to ``sys.path`` so the
test modules can ``from lib.sanitization import sanitize_cell`` /
``from lib.rendering import render_dict_item`` without pulling in
``unogenerator``.
"""

import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
