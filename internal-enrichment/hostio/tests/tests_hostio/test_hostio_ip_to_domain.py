import json
import os
import random

import pytest
from hostio.hostio_ip_to_domain import HostIOIPtoDomain
from hostio.hostio_utils import create_author
from stix2 import DomainName, IPv4Address, Relationship

DEFAULT_IP = "8.8.8.8"
DEFAULT_FIXTURE = "8.8.8.8.json"
DEFAULT_LIMIT = 5
DEFAULT_TOTAL = 14
DEFAULT_IP_ENTITY = IPv4Address(value=DEFAULT_IP)
AUTHOR = create_author()


def load_fixture(filename):
    """Load a fixture file and return its content."""
    filepath = os.path.join(os.path.dirname(__file__), "fixtures", filename)
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Fixture {filename} not found.")
    with open(filepath, "r") as file:
        content = file.read()
        if not content.strip():
            raise ValueError(f"Fixture {filename} is empty.")
        return json.loads(content)


def generate_random_token():
    """Generate a random token."""
    return random._urandom(14).hex()[:14]


class TestHostIOIPToDomain:
    @pytest.fixture
    def hostio_ip(self):
        """Create a Host IO instance with a mock token."""
        # Use a mock token for testing
        return HostIOIPtoDomain(
            token=generate_random_token(),
            ip=DEFAULT_IP,
            limit=DEFAULT_LIMIT,
            author=AUTHOR,
            entity_id=DEFAULT_IP_ENTITY.get("id"),
            marking_refs="TLP:WHITE",
        )

    def test_request_ip_success(self, hostio_ip, mocker):
        """Test successful fetching of data for valid dataset keys."""
        # Patch the _request_data method to return mock data. The mock will be applied
        # for all iterations in the loop.
        mock_request = mocker.patch.object(hostio_ip, "_request_data")
        mock_request.return_value = load_fixture(f"{DEFAULT_FIXTURE}.0")
        hostio_ip.request_ip_to_domain()
        assert hostio_ip.ip == DEFAULT_IP
        assert hostio_ip.domains is not []
        assert len(hostio_ip.domains) == DEFAULT_LIMIT
        assert hostio_ip.total == DEFAULT_TOTAL
        assert hostio_ip.has_next is True
        assert hostio_ip.limit == DEFAULT_LIMIT
        stix_objects = hostio_ip.get_stix_objects()
        assert stix_objects is not None
        assert len(stix_objects) == 10
        # Tested types
        type_list = [Relationship, DomainName]
        pop_list = [Relationship, DomainName]

        # Test that all objects are of the correct type
        for stix_obj in stix_objects:
            assert type(stix_obj) in type_list
            if type(stix_obj) in pop_list:
                pop_list.pop(pop_list.index(type(stix_obj)))
        assert pop_list == []

    def test_request_ip_info_invalid_ip(self, hostio_ip, mocker):
        INVALID_IP = "INVALID_IP"
        mock_request = mocker.patch.object(hostio_ip, "_request_data")
        mock_request.return_value = None
        hostio_ip.ip = INVALID_IP
        hostio_ip.request_ip_to_domain()
        assert hostio_ip.ip == INVALID_IP
        assert hostio_ip.domains == []
        assert hostio_ip.total == 0
        assert hostio_ip.has_next is False
        assert hostio_ip.limit == DEFAULT_LIMIT

    def test_request_ip_info_invalid_response(self, hostio_ip, mocker):
        mock_request = mocker.patch.object(hostio_ip, "_request_data")
        mock_request.return_value = {}
        hostio_ip.request_ip_to_domain()
        assert hostio_ip.ip == DEFAULT_IP
        assert hostio_ip.domains == []
        assert hostio_ip.total == 0
        assert hostio_ip.has_next is False
        assert hostio_ip.limit == DEFAULT_LIMIT

    def test_request_ip_info_success_multi_pages(self, hostio_ip, mocker):
        """Test successful fetching of data for valid dataset keys."""
        # Patch the _request_data method to return mock data. The mock will be applied
        # for all iterations in the loop.
        mock_request = mocker.patch.object(hostio_ip, "_request_data")
        total_records = 0
        test_page = 0
        while hostio_ip.has_next:
            # Test page is incrementing.
            assert hostio_ip.page == test_page
            mock_request.return_value = load_fixture(f"{DEFAULT_FIXTURE}.{test_page}")
            domains = hostio_ip.request_next_page()
            # Test the value of domains is less than the limit.
            assert len(domains) <= DEFAULT_LIMIT
            # Increment records, page, and mock new request.
            total_records = len(domains) + total_records
            test_page += 1
        # Test the total records is equal to the total records in the fixture.
        assert total_records == DEFAULT_TOTAL

    def test_request_no_ip_found(self, hostio_ip, mocker):
        """Test successful fetching of data for valid dataset keys."""
        # Patch the _request_data method to return mock data. The mock will be applied
        # for all iterations in the loop.
        mock_request = mocker.patch.object(hostio_ip, "_request_data")
        mock_request.return_value = load_fixture("ip_error.json")
        hostio_ip.request_ip_to_domain()
        assert hostio_ip.has_next is False
        assert hostio_ip.domains == []
