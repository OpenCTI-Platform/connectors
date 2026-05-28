"""Pytest configuration for the pgl-yoyo connector tests."""

import sys
from pathlib import Path


def pytest_configure(config):
    """Pytest configuration hook to set up the test environment."""
    _ = config
    here = Path(__file__).resolve().parent
    src = here.parent / "src"
    src_path = str(src)
    if src_path not in sys.path:
        sys.path.insert(0, src_path)
