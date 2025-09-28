import os
import sys
import uuid
from pathlib import Path
from unittest.mock import MagicMock

import pytest

TEST_DIR = Path(__file__).parent
SRC_DIR = TEST_DIR.parent / "src"
SRC_DIR_STR = str(SRC_DIR.absolute())

if SRC_DIR_STR not in sys.path:
    sys.path.append(SRC_DIR_STR)

DEFAULT_WARNINGLISTS_SLOW_SEARCH = False
DEFAULT_ENRICH_SUBDOMAINS = False
DEFAULT_LABEL_NAME = "hygiene"
DEFAULT_LABEL_COLOR = "#fc0341"
DEFAULT_LABEL_PARENT_NAME = "hygiene_parent"


@pytest.fixture
def mock_config():
    config = MagicMock()
    config.hygiene.warninglists_slow_search = DEFAULT_WARNINGLISTS_SLOW_SEARCH
    config.hygiene.enrich_subdomains = DEFAULT_ENRICH_SUBDOMAINS
    config.hygiene.label_name = DEFAULT_LABEL_NAME
    config.hygiene.label_color = DEFAULT_LABEL_COLOR
    config.hygiene.label_parent_name = DEFAULT_LABEL_PARENT_NAME
    config.hygiene.label_parent_color = DEFAULT_LABEL_COLOR
    config.hygiene.max_workers = 100  # Add default max_workers for ThreadPoolExecutor
    return config


@pytest.fixture
def mock_helper():
    return MagicMock()


@pytest.fixture(name="mock_opencti")
def mock_opencti_env(mocker):
    """
    Mocks the environment variables for testing.
    Yields a dictionary containing the original environment variables,
    allowing restoration after the test completes.
    """
    mocker.patch("pycti.OpenCTIApiClient.health_check", lambda x: True)
    mocker.patch("pycti.OpenCTIApiConnector.ping")
    mocker.patch("pycti.OpenCTIApiConnector.register")
    mocker.patch(
        "pycti.entities.opencti_label.Label.read_or_create_unchecked",
        lambda *args, **kwargs: {"value": "hygiene-label"},
    )
    mocker.patch(
        "pycti.connector.opencti_connector_helper.OpenCTIConnectorHelper.send_stix2_bundle",
        lambda *args, **kwargs: [],
    )
    original_env = dict(os.environ)
    try:
        # Modify the environment variables here
        os.environ = dict()
        os.environ["OPENCTI_TOKEN"] = uuid.uuid4().hex
        os.environ["OPENCTI_URL"] = "https://localhost:8080"
        os.environ["CONNECTOR_TYPE"] = "INTERNAL_ENRICHMENT"
        yield dict(os.environ)  # Provide the fixture value
    finally:
        # Restore the original environment variables
        os.environ.clear()
        os.environ.update(original_env)


@pytest.fixture(scope="session")
def sample_config_path() -> Path:
    """Sample Configuration file Path."""
    return SRC_DIR / "config.yml.sample"


@pytest.fixture(scope="session")
def mock_config_path() -> Path:
    """Sample Configuration file Path."""
    return TEST_DIR / "mock_config.yaml"
