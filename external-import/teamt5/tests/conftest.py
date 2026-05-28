import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

src_dir = str(Path(__file__).parent.parent.joinpath("src").absolute())
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)


def _secret(value):
    """Tiny stand-in for a Pydantic ``SecretStr`` that the client only ever calls ``.get_secret_value()`` on."""
    secret = Mock()
    secret.get_secret_value.return_value = value
    return secret


@pytest.fixture
def mock_helper():
    helper = Mock()
    helper.connector_logger = Mock()
    return helper


@pytest.fixture
def mock_config_api_key():
    """Config exposing only the deprecated static API key path."""
    config = Mock()
    config.teamt5.api_key = _secret("test-key")
    config.teamt5.client_id = None
    config.teamt5.client_secret = None
    config.teamt5.api_base_url = "https://api.threatvision.org/"
    return config


@pytest.fixture
def mock_config_oauth():
    """Config exposing only the OAuth 2.0 client-credentials path."""
    config = Mock()
    config.teamt5.api_key = None
    config.teamt5.client_id = _secret("cid")
    config.teamt5.client_secret = _secret("csecret")
    config.teamt5.api_base_url = "https://api.threatvision.org/"
    return config


@pytest.fixture
def mock_config_both():
    """Config exposing both paths — OAuth should take precedence."""
    config = Mock()
    config.teamt5.api_key = _secret("legacy-key")
    config.teamt5.client_id = _secret("cid")
    config.teamt5.client_secret = _secret("csecret")
    config.teamt5.api_base_url = "https://api.threatvision.org/"
    return config
