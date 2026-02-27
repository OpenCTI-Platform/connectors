import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

src_dir = str(Path(__file__).parent.parent.joinpath("src").absolute())
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)


@pytest.fixture
def mock_helper():
    helper = Mock()
    helper.connector_logger = Mock()
    return helper


@pytest.fixture
def mock_config_api_key():
    config = Mock()
    config.api_key = "test-key"
    config.client_id = None
    config.client_secret = None
    config.api_base_url = "https://api.threatvision.org/"
    return config


@pytest.fixture
def mock_config_oauth():
    config = Mock()
    config.api_key = None
    config.client_id = "cid"
    config.client_secret = "csecret"
    config.api_base_url = "https://api.threatvision.org/"
    return config
