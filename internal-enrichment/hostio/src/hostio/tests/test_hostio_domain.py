import json
import logging
import os
import random

import pytest
from hostio import HostIODomain
from hostio.hostio_utils import create_author
from stix2 import TLP_GREEN, DomainName, IPv4Address, IPv6Address, Relationship

LOGGER = logging.getLogger(__name__)

DEFAULT_DOMAIN = "google.com"
DEFAULT_FIXTURE = "google.json"
DEFAULT_MARKING_REFS = "TLP:WHITE"
AUTHOR = create_author()

DEFAULT_DOMAIN_ENTITY = DomainName(
    value=DEFAULT_DOMAIN,
    object_marking_refs=[TLP_GREEN],
)


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


class TestHostioDomain:
    @pytest.fixture
    def domain(self):
        """Create a Host IO instance with a mock token."""
        # Use a mock token for testing
        return HostIODomain(
            token=generate_random_token(),
            domain=DEFAULT_DOMAIN,
            author=AUTHOR,
            entity_id=DEFAULT_DOMAIN_ENTITY.get("id"),
            marking_refs=DEFAULT_MARKING_REFS,
        )

    def test_request_full_domain_info_success(self, domain, mocker):
        """Test successful fetching of data for valid dataset keys."""
        # Patch the _request_data method to return mock data. The mock will be applied
        # for all iterations in the loop.
        mock_request = mocker.patch.object(domain, "_request_data")
        mock_request.return_value = load_fixture(DEFAULT_FIXTURE)
        domain.request_full_domain_info()
        assert domain.domain == DEFAULT_DOMAIN
        assert domain.ipinfo is not {}
        assert domain.dns is not {}
        assert domain.web is not {}
        assert domain.related is not {}

    def test_request_full_domain_get_stix_objects(self, domain, mocker):
        """Test successful fetching of data for valid dataset keys."""
        # Patch the _request_data method to return mock data. The mock will be applied
        mock_request = mocker.patch.object(domain, "_request_data")
        mock_request.return_value = load_fixture(DEFAULT_FIXTURE)
        domain.request_full_domain_info()
        LOGGER.info(domain)
        stix_objects = domain.get_stix_objects()
        assert stix_objects is not None
        assert len(stix_objects) == 10

        # Tested types
        type_list = [Relationship, IPv4Address, IPv6Address]
        pop_list = [Relationship, IPv4Address, IPv6Address]

        # Test that all objects are of the correct type
        for stix_obj in stix_objects:
            assert type(stix_obj) in type_list
            if type(stix_obj) in pop_list:
                pop_list.pop(pop_list.index(type(stix_obj)))
        assert pop_list == []

        assert domain.get_note_content()
        assert len(domain.get_note_content()) > 0

    def test_request_full_domain_info_invalid_domain(self, domain, mocker):
        INVALID_DOMAIN = "INVALID_DOMAIN"
        mock_request = mocker.patch.object(domain, "_request_data")
        mock_request.return_value = None
        domain.domain = INVALID_DOMAIN
        domain.request_full_domain_info()
        assert domain.domain == INVALID_DOMAIN
        assert domain.ipinfo == {}
        assert domain.dns == {}
        assert domain.web == {}
        assert domain.related == {}

    def test_request_full_domain_info_invalid_response(self, domain, mocker):
        mock_request = mocker.patch.object(domain, "_request_data")
        mock_request.return_value = {}
        domain.request_full_domain_info()
        assert domain.domain == DEFAULT_DOMAIN
        assert domain.ipinfo == {}
        assert domain.dns == {}
        assert domain.web == {}
        assert domain.related == {}

    def test_request_full_domain_info_empty_response(self, domain, mocker):
        mock_request = mocker.patch.object(domain, "_request_data")
        mock_request.return_value = ""
        domain.request_full_domain_info()
        assert domain.domain == DEFAULT_DOMAIN
        assert domain.ipinfo == {}
        assert domain.dns == {}
        assert domain.web == {}
        assert domain.related == {}
