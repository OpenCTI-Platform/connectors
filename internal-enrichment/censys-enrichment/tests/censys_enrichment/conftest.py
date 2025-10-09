from unittest.mock import MagicMock, Mock

import pytest
from pycti import OpenCTIConnectorHelper
from pytest_mock import MockerFixture


@pytest.fixture(name="mock_config")
def fixture_mock_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENCTI_URL", "http://test")
    monkeypatch.setenv("OPENCTI_TOKEN", "test")
    monkeypatch.setenv("CONNECTOR_SCOPE", "IPv4-Addr")
    monkeypatch.setenv("CONNECTOR_LOG_LEVEL", "error")
    monkeypatch.setenv("CENSYS_ENRICHMENT_ORGANISATION_ID", "organisation_id")
    monkeypatch.setenv("CENSYS_ENRICHMENT_TOKEN", "token")


@pytest.fixture(name="mocked_helper")
def fixture_mocked_helper(mocker: MockerFixture) -> Mock:
    mocked_helper = mocker.patch("pycti.OpenCTIConnectorHelper")
    mocked_helper.stix2_create_bundle = MagicMock(
        side_effect=OpenCTIConnectorHelper.stix2_create_bundle
    )
    mocked_helper.check_max_tlp = OpenCTIConnectorHelper.check_max_tlp

    return mocked_helper
