import pytest
from hostio import (
    BaseStixTransformation,
    HostIODomainStixTransformation,
    HostIOIPtoDomainStixTransform,
)
from hostio.hostio_domain import HostIODomain
from hostio.hostio_utils import create_author
from stix2 import (
    TLP_GREEN,
    TLP_WHITE,
    AutonomousSystem,
    DomainName,
    IPv4Address,
    IPv6Address,
    Relationship,
)
from stix2.exceptions import InvalidValueError

from .constants import generate_random_token, load_fixture

VALID_DOMAIN = "example.com"
VALID_IP = "8.8.8.8"
VALID_IP_STIX = IPv4Address(value=VALID_IP)
DEFAULT_FIXTURE = "google.json"
DEFAULT_DOMAIN_ENTITY = DomainName(
    value=VALID_DOMAIN,
    object_marking_refs=[TLP_GREEN],
)
AUTHOR = create_author()


class TestTransformToStix:
    @pytest.fixture
    def domain(self):
        """Create a Host IO instance with a mock token."""
        # Use a mock token for testing
        return HostIODomain(
            token=generate_random_token(),
            author=AUTHOR,
            domain=VALID_DOMAIN,
            entity_id=DEFAULT_DOMAIN_ENTITY.get("id"),
            marking_refs="TLP:WHITE",
        )

    def test_hostio_ip_to_domain_stix_transform(self):
        """Test creation of STIX DomainName object."""
        hostio_domain_stix_transform = HostIOIPtoDomainStixTransform(
            author=AUTHOR, domain=VALID_DOMAIN, entity_id=VALID_IP_STIX.get("id")
        )
        assert hostio_domain_stix_transform.domain == VALID_DOMAIN
        assert hostio_domain_stix_transform.marking_refs == [TLP_WHITE]
        assert hostio_domain_stix_transform.entity_id == VALID_IP_STIX.get("id")
        assert len(hostio_domain_stix_transform.stix_objects) == 2
        assert hostio_domain_stix_transform.stix_objects[0].type == "relationship"
        assert hostio_domain_stix_transform.stix_objects[0].object_marking_refs == [
            TLP_WHITE.get("id")
        ]

    def test_hostio_ip_to_domain_stix_transform_marking_refs(self):
        """Test creation of STIX DomainName object with different marking refs."""
        hostio_domain_stix_transform = HostIOIPtoDomainStixTransform(
            author=AUTHOR,
            domain=VALID_DOMAIN,
            marking_refs="TLP:GREEN",
            entity_id=VALID_IP_STIX.get("id"),
        )
        assert hostio_domain_stix_transform.domain == VALID_DOMAIN
        assert hostio_domain_stix_transform.marking_refs == [TLP_GREEN]
        assert hostio_domain_stix_transform.entity_id == VALID_IP_STIX.get("id")
        assert len(hostio_domain_stix_transform.stix_objects) == 2
        assert isinstance(hostio_domain_stix_transform.stix_objects[0], Relationship)
        assert hostio_domain_stix_transform.stix_objects[0].type == "relationship"
        assert hostio_domain_stix_transform.stix_objects[0].object_marking_refs == [
            TLP_GREEN.get("id")
        ]

    def test_hostio_ip_to_domain_stix_transform_invalid_domain(self):
        """Test creation of STIX DomainName object with invalid domain."""
        with pytest.raises(ValueError):
            HostIOIPtoDomainStixTransform(
                author=AUTHOR, domain="invalid", entity_id=VALID_IP_STIX.get("id")
            )
            assert False

    def test_hostio_ip_to_domain_stix_transform_invalid_marking_refs(self):
        """Test creation of STIX DomainName object with invalid marking refs."""
        with pytest.raises(ValueError):
            HostIOIPtoDomainStixTransform(
                author=AUTHOR,
                domain=VALID_DOMAIN,
                marking_refs="invalid",
                entity_id=VALID_IP_STIX.get("id"),
            )
            assert False

    def test_hostio_ip_to_domain_stix_transform_invalid_entity_id(self):
        """Test creation of STIX DomainName object with invalid entity id."""
        with pytest.raises(InvalidValueError):
            HostIOIPtoDomainStixTransform(
                author=AUTHOR, domain=VALID_DOMAIN, entity_id="invalid"
            )
            assert False

    def test_hostio_domain_stix_transformation(self, domain, mocker):
        """Test creation of STIX DomainName object."""
        mock_request = mocker.patch.object(domain, "_request_data")
        mock_request.return_value = load_fixture(DEFAULT_FIXTURE)
        domain.request_full_domain_info()
        hostio_domain_stix_transform = HostIODomainStixTransformation(
            author=AUTHOR, domain_object=domain, entity_id=VALID_IP_STIX.get("id")
        )
        assert hostio_domain_stix_transform.marking_refs == [TLP_WHITE]
        assert hostio_domain_stix_transform.entity_id == VALID_IP_STIX.get("id")
        assert len(hostio_domain_stix_transform.stix_objects) == 10
        for stix_obj in hostio_domain_stix_transform.get_stix_objects():
            assert isinstance(
                stix_obj,
                (DomainName, IPv4Address, IPv6Address, Relationship, AutonomousSystem),
            )

    def test_base_stix_trasformation(self):
        """Test creation of STIX DomainName object."""
        base_stix_transform = BaseStixTransformation(
            author=AUTHOR, marking_refs="TLP:WHITE", entity_id=VALID_IP_STIX.get("id")
        )
        assert base_stix_transform.marking_refs == [TLP_WHITE]
        assert base_stix_transform.entity_id == VALID_IP_STIX.get("id")
        assert len(base_stix_transform.stix_objects) == 0
        assert base_stix_transform.get_stix_objects() == []
        # assert isinstance(base_stix_transform._create_relationships(VALID_IP_STIX.get("id")), Relationship)
