"""
Pytest configuration for Sublime Security connector tests.
"""

import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

src_dir = str(Path(__file__).parent.parent.joinpath("src").absolute())
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)


@pytest.fixture
def mock_helper():
    """Return a mock OpenCTI helper."""
    helper = Mock()
    helper.connector_logger = Mock()
    helper.api = Mock()
    helper.api.work = Mock()
    helper.stix2_create_bundle = Mock(return_value='{"type": "bundle", "objects": []}')
    helper.send_stix2_bundle = Mock()
    return helper
