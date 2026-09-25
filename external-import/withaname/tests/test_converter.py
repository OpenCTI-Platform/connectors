from unittest.mock import MagicMock

import pytest
from connector.converter_to_stix import ConverterToStix
from pycti import OpenCTIConnectorHelper


class TestConverterToStix:
    @pytest.fixture
    def mock_helper(self):
        return MagicMock(spec=OpenCTIConnectorHelper)

    @pytest.fixture
    def converter(self, mock_helper):
        return ConverterToStix(helper=mock_helper, tlp_level="green")

    def test_create_domain(self, converter):
        domain = converter.create_domain("example.com")
        assert domain.value == "example.com"
        assert domain.markings[0].level == "green"

    def test_create_ipv4(self, converter):
        ip = converter.create_ipv4("1.2.3.4")
        assert ip.value == "1.2.3.4"
        assert ip.markings[0].level == "green"

    def test_create_resolves_to_relationship(self, converter):
        domain = converter.create_domain("example.com")
        ip = converter.create_ipv4("1.2.3.4")
        rel = converter.create_resolves_to_relationship(domain, ip)

        assert rel.type == "resolves-to"
        assert rel.source == domain
        assert rel.target == ip

    def test_create_note_for_host(self, converter):
        domain = converter.create_domain("example.com")
        targets = [{"host": "example.com", "ip": "1.2.3.4"}]
        note = converter.create_note_for_host(
            domain=domain,
            cfg_id="cfg_1",
            cfg_ts=123456.0,
            host="example.com",
            targets=targets,
        )

        assert "cfg_1" in note.content
        assert "123456.0" in note.content
        assert "example.com" in note.content
        assert domain in note.objects
