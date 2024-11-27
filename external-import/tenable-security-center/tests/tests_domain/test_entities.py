# pragma: no cover  # do not test coverage of tests...
# isort: skip_file
# type: ignore
"""Provide unit tests for the entities module."""

import pytest

from tenable_security_center.domain.entities import (
    Author,
    System,
    MACAddress,
    IPAddress,
    DomainName,
    Hostname,
    Software,
    OperatingSystem,
    Vulnerability,
)

from pydantic import ValidationError


CONSTRUCTORS = {
    "author": {
        "class": Author,
        "minimal": {
            "name": "name",
        },
        "full": {
            "name": "name",
            "description": "description",
            "contact_information": "a@exmaple.com",
            "confidence": 50,
            "x_opencti_organization_type": "vendor",
            "x_opencti_reliability": "reliability",
            "x_opencti_aliases": ["Alias"],
        },
    },
    "system": {
        "class": System,
        "minimal": {
            "name": "name",
        },
        "full": {
            "author": {"name": "name"},
            "name": "name",
            "created": "1970-01-01T00:00:00Z",
            "modified": "1970-01-01T00:00:00Z",
            "description": "description",
            "object_marking_refs": [
                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
            ],
        },
    },
    "mac_adresse": {
        "class": MACAddress,
        "minimal": {
            "author": {"name": "name"},
            "value": "00:00:00:00:00:00",
        },
        "full": {
            "author": {"name": "name"},
            "value": "00:00:00:00:00:00",
            "object_marking_refs": [
                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
            ],
        },
    },
    "ip_address": {
        "class": IPAddress,
        "minimal": {"author": {"name": "name"}, "value": "192.0.0.1", "version": "v4"},
        "full": {
            "author": {"name": "name"},
            "value": "192.0.0.1",
            "version": "v4",
            "resolves_to_mac_addresses": [
                {"author": {"name": "name"}, "value": "00:00:00:00:00:00"}
            ],
            "object_marking_refs": [
                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
            ],
        },
    },
    "domain_name": {
        "class": DomainName,
        "minimal": {
            "author": {"name": "name"},
            "value": "example.com",
        },
        "full": {
            "author": {"name": "name"},
            "value": "example.com",
            "object_marking_refs": [
                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
            ],
        },
    },
    "hostname": {
        "class": Hostname,
        "minimal": {
            "author": {"name": "name"},
            "value": "hostname",
        },
        "full": {
            "author": {"name": "name"},
            "value": "hostname",
            "object_marking_refs": [
                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
            ],
        },
    },
    "software": {
        "class": Software,
        "minimal": {
            "author": {"name": "name"},
            "name": "software",
            "vendor": "vendor",
            "cpe": "cpe:/a:software:version",
        },
        "full": {
            "author": {"name": "name"},
            "name": "software",
            "vendor": "vendor",
            "cpe": "cpe:/a:software:version",
            "object_marking_refs": [
                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
            ],
        },
    },
    "operating_system": {
        "class": OperatingSystem,
        "minimal": {
            "author": {"name": "name"},
            "name": "operating_system",
        },
        "full": {
            "author": {"name": "name"},
            "name": "operating_system",
            "object_marking_refs": [
                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
            ],
        },
    },
    "vulnerability": {
        "class": Vulnerability,
        "minimal": {
            "author": {"name": "name"},
            "created": "1970-01-01T00:00:00Z",
            "modified": "1970-01-01T00:00:00Z",
            "name": "vulnerability",
        },
        "full": {
            "author": {"name": "name"},
            "created": "1970-01-01T00:00:00Z",
            "modified": "1970-01-01T00:00:00Z",
            "name": "vulnerability",
            "description": "description",
            "confidence": 50,
            "object_marking_refs": [
                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
            ],
            "cvss3_score": 5.0,
            "cvss3_severity": "High",
            "cvss3_attack_vector": "N",
            "cvss3_integrity_impact": "H",
            "cvss3_availability_impact": "H",
            "cvss3_confidentiality_impact": "H",
        },
    },
}


@pytest.mark.parametrize(
    "constructor,min_params",
    [
        pytest.param(CONSTRUCTORS[key]["class"], CONSTRUCTORS[key]["minimal"], id=key)
        for key in CONSTRUCTORS.keys()
    ],
)
def test_minimal_constructor(constructor, min_params):
    # Given correct parameters to constructor
    constructor = constructor
    correct_params = min_params
    # When object is created
    entity = constructor[0](**correct_params)
    # Then object is created correctly
    assert entity.id is not None


@pytest.mark.parametrize(
    "constructor,full_params",
    [
        pytest.param(CONSTRUCTORS[key]["class"], CONSTRUCTORS[key]["full"], id=key)
        for key in CONSTRUCTORS.keys()
    ],
)
def test_full_constructor(constructor, full_params):
    # Given correct parameters to constructor
    constructor = constructor
    # When object is created
    entity = constructor[0](**full_params)
    # Then object is created correctly
    assert entity.id is not None


@pytest.mark.parametrize(
    "constructor,min_params",
    [
        pytest.param(CONSTRUCTORS[key]["class"], CONSTRUCTORS[key]["minimal"], id=key)
        for key in CONSTRUCTORS.keys()
    ],
)
def test_entity_id_is_deterministic(constructor, min_params):
    # Given correct parameters to constructor
    constructor = constructor
    # When 2 Entity objects are created
    entity_1 = constructor(**min_params)
    entity_2 = constructor(**min_params)
    # Then object.id are the same
    assert entity_1.id == entity_2.id


@pytest.mark.parametrize(
    "constructor,min_params",
    [
        pytest.param(CONSTRUCTORS[key]["class"], CONSTRUCTORS[key]["minimal"], id=key)
        for key in CONSTRUCTORS.keys()
    ],
)
def test_entity_can_be_converted_to_stix2_objects(constructor, min_params):
    # Given correct parameters to constructor
    constructor = constructor
    # When object is created
    entity = constructor(**min_params)
    # Then object can be converted to stix object
    assert entity.to_stix2_object() is not None


@pytest.mark.parametrize(
    "constructor,min_params",
    [
        pytest.param(CONSTRUCTORS[key]["class"], CONSTRUCTORS[key]["minimal"], id=key)
        for key in CONSTRUCTORS.keys()
    ],
)
def test_entity_should_not_accept_extra_args(constructor, min_params):
    # Given correct parameters to constructor
    constructor = constructor
    # When extra args are given
    with pytest.raises(ValidationError):
        _ = constructor(**min_params, extra_arg="extra")
