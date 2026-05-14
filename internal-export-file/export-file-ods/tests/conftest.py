"""Pytest configuration for the ``export-file-ods`` connector tests.

The connector's ``main.py`` imports ``unogenerator`` (which itself loads the
LibreOffice ``uno`` C extension and is not pip-installable on a stock CI
runner). Tests only exercise ``sanitize_cell`` from
``src/lib/sanitization.py``, which is dependency-free, so we just add the
``src`` directory to ``sys.path`` so the test modules can ``from
lib.sanitization import sanitize_cell``.
"""

import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
