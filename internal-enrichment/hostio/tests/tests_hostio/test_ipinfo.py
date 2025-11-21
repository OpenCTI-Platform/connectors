import logging
from unittest.mock import Mock, patch

import pytest
from hostio.hostio_utils import create_author, get_tlp_marking
from hostio.ipinfo import IPInfo
from stix2 import (
    AutonomousSystem,
    DomainName,
    Identity,
    IPv4Address,
    IPv6Address,
    Location,
    Relationship,
)

from .constants import generate_random_token, load_fixture

LOGGER = logging.getLogger(__name__)
AUTHOR = create_author()


class TestIPInfo:
    valid_token = generate_random_token()
    invalid_token = "invalid_token"
    valid_ip = "8.8.8.8"  # Example of a valid IP
    valid_ipv6 = "2607:fb91:2a0:80af:11ad:f056:42f2:b8c2"
    invalid_ip = "invalid_ip"
    fixture = "ipinfo_{}.json"
    license_dict = {
        "free": {
            "count": 9,
            "keys": [
                "ip",
                "hostname",
                "anycast",
                "city",
                "region",
                "country",
                "loc",
                "org",
                "postal",
                "timezone",
            ],  # Updated keys
            "stix_objects": [Location, Relationship, DomainName, AutonomousSystem],
        },
        "base": {
            "count": 9,
            "keys": [
                "ip",
                "hostname",
                "anycast",
                "city",
                "region",
                "country",
                "loc",
                "org",
                "postal",
                "timezone",
                "asn",
            ],  # Updated keys
            "stix_objects": [Location, Relationship, AutonomousSystem, DomainName],
        },
        "standard": {
            "count": 11,
            "keys": [
                "ip",
                "hostname",
                "anycast",
                "city",
                "region",
                "country",
                "loc",
                "org",
                "postal",
                "timezone",
                "asn",
                "company",
                "privacy",
            ],  # Updated keys
            "stix_objects": [
                Location,
                Relationship,
                AutonomousSystem,
                Identity,
                DomainName,
            ],
        },
        "business": {
            "count": 17,
            "keys": [
                "ip",
                "hostname",
                "anycast",
                "city",
                "region",
                "country",
                "loc",
                "postal",
                "timezone",
                "asn",
                "company",
                "privacy",
                "abuse",
                "domains",
            ],  # Updated keys
            "stix_objects": [
                Location,
                Relationship,
                AutonomousSystem,
                Identity,
                DomainName,
            ],
        },
    }
    ipinfo_entity = IPv4Address(value=valid_ip)
    ipinfo_entity_ipv6 = IPv6Address(value=valid_ipv6)
    marking_refs = "TLP:WHITE"

    @patch("hostio.ipinfo.getHandler")
    def test_init_valid_token_and_ip_ipv6(self, mock_get_handler):
        """Test initialization with valid token and IP."""
        mock_handler = Mock()
        mock_handler.getDetails.return_value.all = load_fixture(
            self.fixture.format("ipv6")
        )
        mock_get_handler.return_value = mock_handler
        ip_info = IPInfo(
            token=self.valid_token,
            ip=self.valid_ipv6,
            author=AUTHOR,
            marking_refs=self.marking_refs,
            entity_id=self.ipinfo_entity_ipv6.get("id"),
        )
        assert ip_info.ip == self.valid_ipv6
        assert ip_info.get_details() == load_fixture(self.fixture.format("ipv6"))
        mock_get_handler.assert_called_once_with(token=self.valid_token)
        mock_handler.getDetails.assert_called_once_with(self.valid_ipv6)

    @patch("hostio.ipinfo.getHandler")
    def test_init_valid_token_and_ip(self, mock_get_handler):
        """Test initialization with valid token and IP."""
        mock_handler = Mock()

        for license in self.license_dict:
            LOGGER.info(f"Testing license: {license}")
            mock_handler.getDetails.return_value.all = load_fixture(
                self.fixture.format(license)
            )
            mock_get_handler.return_value = mock_handler
            ip_info = IPInfo(
                token=self.valid_token,
                ip=self.valid_ip,
                author=AUTHOR,
                marking_refs=self.marking_refs,
                entity_id=self.ipinfo_entity.get("id"),
            )
            assert ip_info.ip == self.valid_ip
            assert ip_info.get_details() == load_fixture(self.fixture.format(license))
            for key in self.license_dict.get(license).get("keys"):
                assert key in ip_info.get_details().keys()
            mock_get_handler.assert_called_once_with(token=self.valid_token)
            mock_handler.getDetails.assert_called_once_with(self.valid_ip)
            mock_handler.reset_mock()
            mock_get_handler.reset_mock()

            # Test that the correct number of STIX objects are returned
            stix_objects = ip_info.get_stix_objects()
            assert stix_objects is not None
            assert len(stix_objects) == self.license_dict.get(license).get("count")

            # # Tested types
            type_list = list(self.license_dict.get(license).get("stix_objects"))
            pop_list = list(self.license_dict.get(license).get("stix_objects"))

            # Test that all objects are of the correct type
            for stix_obj in stix_objects:
                LOGGER.info(f"Testing STIX object: {stix_obj}")
                assert type(stix_obj) in type_list
                if type(stix_obj) in pop_list:
                    LOGGER.info(f"Removing STIX object: {type(stix_obj)}")
                    pop_list.pop(pop_list.index(type(stix_obj)))
                assert stix_obj.object_marking_refs
                if stix_obj.object_marking_refs:
                    assert (
                        get_tlp_marking(self.marking_refs).get("id")
                        is stix_obj.object_marking_refs[0]
                    )
            assert pop_list == []

            # Test that the correct number of labels are returned
            if license == "business":
                assert ip_info.get_labels()
                assert len(ip_info.get_labels()) == 5

            # Test that the correct note content is returned
            assert ip_info.get_note_content()
            assert len(ip_info.get_note_content()) > 0

    def test_init_invalid_token(self):
        """Test initialization with invalid token."""
        with pytest.raises(ValueError) as exc_info:
            IPInfo(
                token=self.invalid_token,
                ip=self.valid_ip,
                author=AUTHOR,
                marking_refs=self.marking_refs,
                entity_id=self.ipinfo_entity.get("id"),
            )

        assert "Invalid API token provided." in str(exc_info.value)

    def test_init_invalid_ip(self):
        """Test initialization with invalid IP."""
        with pytest.raises(ValueError) as exc_info:
            IPInfo(
                token=self.valid_token,
                ip=self.invalid_ip,
                author=AUTHOR,
                marking_refs=self.marking_refs,
                entity_id=self.ipinfo_entity.get("id"),
            )

        assert f"Invalid IP address: {self.invalid_ip}" in str(exc_info.value)
