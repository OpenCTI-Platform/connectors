import pytest
from stix2 import TLP_GREEN, TLP_WHITE, DomainName, IPv4Address
from stix2.exceptions import InvalidValueError

from hostio.transform_to_stix import HostIOIPtoDomainStixTransform, HostIODomainStixTransformation

VALID_DOMAIN = "example.com"
VALID_IP = "8.8.8.8"
VALID_IP_STIX = IPv4Address(value=VALID_IP)


def test_hostio_ip_to_domain_stix_transform():
    """Test creation of STIX DomainName object."""
    hostio_domain_stix_transform = HostIOIPtoDomainStixTransform(
        domain=VALID_DOMAIN, entity_id=VALID_IP_STIX.get("id")
    )
    assert hostio_domain_stix_transform.domain == VALID_DOMAIN
    assert hostio_domain_stix_transform.marking_refs == [TLP_WHITE]
    assert hostio_domain_stix_transform.entity_id == VALID_IP_STIX.get("id")
    assert len(hostio_domain_stix_transform.stix_objects) == 2
    assert hostio_domain_stix_transform.stix_objects[0].type == "domain-name"
    assert hostio_domain_stix_transform.stix_objects[0].value == VALID_DOMAIN
    assert hostio_domain_stix_transform.stix_objects[0].resolves_to_refs == [
        VALID_IP_STIX.get("id")
    ]
    assert hostio_domain_stix_transform.stix_objects[0].object_marking_refs == [
        TLP_WHITE.get("id")
    ]


def test_hostio_ip_to_domain_stix_transform_marking_refs():
    """Test creation of STIX DomainName object with different marking refs."""
    hostio_domain_stix_transform = HostIOIPtoDomainStixTransform(
        domain=VALID_DOMAIN, marking_refs="TLP:GREEN", entity_id=VALID_IP_STIX.get("id")
    )
    assert hostio_domain_stix_transform.domain == VALID_DOMAIN
    assert hostio_domain_stix_transform.marking_refs == [TLP_GREEN]
    assert hostio_domain_stix_transform.entity_id == VALID_IP_STIX.get("id")
    assert len(hostio_domain_stix_transform.stix_objects) == 2
    assert isinstance(hostio_domain_stix_transform.stix_objects[0], DomainName)
    assert hostio_domain_stix_transform.stix_objects[0].type == "domain-name"
    assert hostio_domain_stix_transform.stix_objects[0].value == VALID_DOMAIN
    assert hostio_domain_stix_transform.stix_objects[0].resolves_to_refs == [
        VALID_IP_STIX.get("id")
    ]
    assert hostio_domain_stix_transform.stix_objects[0].object_marking_refs == [
        TLP_GREEN.get("id")
    ]


def test_hostio_ip_to_domain_stix_transform_invalid_domain():
    """Test creation of STIX DomainName object with invalid domain."""
    with pytest.raises(ValueError):
        HostIOIPtoDomainStixTransform(domain="invalid", entity_id=VALID_IP_STIX.get("id"))
        assert False


def test_hostio_ip_to_domain_stix_transform_invalid_marking_refs():
    """Test creation of STIX DomainName object with invalid marking refs."""
    with pytest.raises(ValueError):
        HostIOIPtoDomainStixTransform(
            domain=VALID_DOMAIN,
            marking_refs="invalid",
            entity_id=VALID_IP_STIX.get("id"),
        )
        assert False


def test_hostio_ip_to_domain_stix_transform_invalid_entity_id():
    """Test creation of STIX DomainName object with invalid entity id."""
    with pytest.raises(InvalidValueError):
        HostIOIPtoDomainStixTransform(domain=VALID_DOMAIN, entity_id="invalid")
        assert False

def test_hostio_domain_stix_transformation():
    """Test creation of STIX DomainName object."""
    hostio_domain_stix_transform = HostIODomainStixTransformation(
        domain=VALID_DOMAIN, entity_id=VALID_IP_STIX.get("id")
    )
    assert hostio_domain_stix_transform.domain == VALID_DOMAIN
    assert hostio_domain_stix_transform.marking_refs == [TLP_WHITE]
    assert hostio_domain_stix_transform.entity_id == VALID_IP_STIX.get("id")
    assert len(hostio_domain_stix_transform.stix_objects) == 2
    assert hostio_domain_stix_transform.stix_objects[0].type == "domain-name"
    assert hostio_domain_stix_transform.stix_objects[0].value == VALID_DOMAIN
    assert hostio_domain_stix_transform.stix_objects[0].resolves_to_refs == [
        VALID_IP_STIX.get("id")
    ]
    assert hostio_domain_stix_transform.stix_objects[0].object_marking_refs == [
        TLP_WHITE.get("id")
    ]

