import os
import sys
from dataclasses import asdict
from unittest.mock import MagicMock, Mock, patch

import pytest
from censys_platform import (
    HostAsset,
    ResponseEnvelopeHostAsset,
    V3GlobaldataAssetHostResponse,
)
from pycti import OpenCTIConnectorHelper
from pytest_mock import MockerFixture

from .factories import HostFactory, Ipv4EnrichmentFactory

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))


@pytest.fixture(name="mock_config")
def fixture_mock_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENCTI_URL", "http://test")
    monkeypatch.setenv("OPENCTI_TOKEN", "opencti-token")
    monkeypatch.setenv("CENSYS_ENRICHMENT_ORGANISATION_ID", "censys-organisation_id")
    monkeypatch.setenv("CENSYS_ENRICHMENT_TOKEN", "censys-token")


@pytest.fixture(name="mocked_helper")
def fixture_mocked_helper(mocker: MockerFixture) -> Mock:
    mocked_helper = mocker.patch("pycti.OpenCTIConnectorHelper")
    mocked_helper.stix2_create_bundle = MagicMock(
        side_effect=OpenCTIConnectorHelper.stix2_create_bundle
    )
    mocked_helper.check_max_tlp = OpenCTIConnectorHelper.check_max_tlp
    return mocked_helper


@pytest.fixture
def get_host():
    with patch("censys_platform.global_data.GlobalData.get_host") as mock_get_host:
        host = HostFactory()
        result = V3GlobaldataAssetHostResponse(
            headers={},
            result=ResponseEnvelopeHostAsset(
                result=HostAsset(
                    extensions={},
                    resource=host,
                )
            ),
        )
        mock_get_host.return_value = result
        yield host


@pytest.fixture
def ipv4_enrichment_message():
    yield asdict(Ipv4EnrichmentFactory())
