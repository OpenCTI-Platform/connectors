# pragma: no cover  # do not test coverage of tests...
# isort: skip_file
# type: ignore
"""Provide unit tests for the use case."""

import pytest
from unittest.mock import Mock

from datetime import datetime

from stix2 import TLP_WHITE

from tenable_security_center.domain.use_case import ConverterToStix
from tenable_security_center.ports.asset import AssetsChunkPort, AssetPort


def _mock_helper():
    return Mock()


@pytest.fixture()
def mock_helper():
    return _mock_helper()


class MockAsset(AssetPort):
    @property
    def id(self):
        return "1234"

    @property
    def uuid(self):
        return "1234"

    @property
    def name(self):
        return "name"

    @property
    def first_seen(self):
        return datetime.fromisoformat("1970-01-01T00:00:00Z")

    @property
    def last_seen(self):
        return datetime.fromisoformat("1970-01-01T00:00:00Z")

    @property
    def created_time(self):
        return datetime.fromisoformat("1970-01-01T00:00:00Z")

    @property
    def modified_time(self):
        return datetime.fromisoformat("1970-01-01T00:00:00Z")

    @property
    def ip_address(self):
        return "192.0.0.1"

    @property
    def repository_id(self):
        return "1"

    @property
    def findings(self):
        return []

    @property
    def mac_address(self):
        return None

    @property
    def operating_systems(self):
        return None

    @property
    def tenable_uuid(self):
        return "1234"


class MockAssetsChunk(AssetsChunkPort):
    @property
    def assets(self):
        return [MockAsset()]


@pytest.fixture()
def mock_assets_chunk():
    return MockAssetsChunk()


def test_constructor(mock_helper):
    # Given a mock helper and a mock config
    helper = mock_helper
    # When creating a new ConverterToStix
    converter = ConverterToStix(helper=helper, tlp_marking=TLP_WHITE)
    # Then the converter should be correctly initialized with an Author
    assert converter._author is not None


def test_converter_should_process_an_asset_chunk(mock_helper, mock_assets_chunk):
    # Given a mock helper and a mock config
    helper = mock_helper

    # a ConverterToStix Instance
    converter = ConverterToStix(helper=helper, tlp_marking=TLP_WHITE)
    # an assets_chunk
    assets_chunk = mock_assets_chunk

    # When processing an asset chunk
    results = converter.process_assets_chunk(
        assets_chunk=assets_chunk, process_systems_without_vulnerabilities=True
    )
    # Then the results should contain at least a author, a system and an ipadress pointing to the system
    print(results)
    assert any(
        value.get("identity_class") == "organization" for _, value in results.items()
    )
    assert any(value.get("identity_class") == "system" for _, value in results.items())
    assert any(value["type"] == "ipv4-addr" for _, value in results.items())
    assert any(
        (
            value["type"] == "relationship"
            and value.get("source_ref", "").startswith("identity--")
            and value.get("target_ref", "").startswith("ipv4-addr--")
        )
        for _, value in results.items()
    )
