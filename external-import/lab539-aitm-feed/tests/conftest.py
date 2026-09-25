"""Shared test fixtures for the Lab539 AiTM Feed connector tests."""

import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

src_dir = str(Path(__file__).parent.parent.joinpath("src").absolute())
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)


def _secret(value):
    """Stand-in for a Pydantic SecretStr."""
    secret = Mock()
    secret.get_secret_value.return_value = value
    return secret


@pytest.fixture
def mock_helper():
    """Mock OpenCTIConnectorHelper."""
    helper = Mock()
    helper.connector_logger = Mock()
    helper.connect_id = "test-connector-id"
    helper.connect_name = "Lab539 AiTM Feed"
    return helper


@pytest.fixture
def mock_config():
    """Mock ConnectorSettings."""
    config = Mock()
    config.connector.name = "Lab539 AiTM Feed"
    config.connector.duration_period = "PT15M"
    config.aitm_feed.api_key = _secret("test-api-key")
    config.aitm_feed.api_base_url = "https://aitm.lab539.io/v1.0"
    config.aitm_feed.tlp_level = "amber"
    config.aitm_feed.first_run_lookback_days = 7
    return config


@pytest.fixture
def sample_record():
    """A representative AiTM feed record."""
    return {
        "hostname": "app.hometryst.link",
        "domain": "app.hometryst.link",
        "ip": "104.21.33.42",
        "rdns": "",
        "asn": "Cloudflare, Inc.",
        "frontend": True,
        "backend": False,
        "active": True,
        "timestamp": 1778919394,
        "detected": 1778919394,
        "confidence": "medium",
        "country": "CA",
        "eventid": "e140ee76-e0a7-4cbb-b971-02dc39c23b06",
    }
