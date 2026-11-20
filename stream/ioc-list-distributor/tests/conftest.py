"""pytest: puts src/ on the import path (packages common, connector, ioc_distributor) and gives
every test the environment it started with, so settings set by one test file never leak into
another when they all run in one process."""

import os
import sys

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))


@pytest.fixture(autouse=True)
def _restore_environment():
    saved = dict(os.environ)
    yield
    os.environ.clear()
    os.environ.update(saved)
