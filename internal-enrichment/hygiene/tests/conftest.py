import os
import sys
import uuid
from pathlib import Path

import pytest
from pytest_mock.plugin import MockerFixture

TEST_DIR = Path(__file__).parent
SRC_DIR = TEST_DIR.parent / "src"
SRC_DIR_STR = str(SRC_DIR.absolute())

if SRC_DIR_STR not in sys.path:
    sys.path.append(SRC_DIR_STR)


@pytest.fixture(name="mock_opencti")
def mock_opencti_env(mocker: MockerFixture):
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
