"""
Test Connector entities.
"""

import sys
from datetime import datetime
from pathlib import Path

import stix2

sys.path.append(str((Path(__file__).resolve().parent.parent.parent / "src")))

import pytest
from pydantic import ValidationError
from tenable_vuln_management.models.opencti import (
    Author,
    DomainName,
    Hostname,
    IPAddress,
    MACAddress,
    RelatedToRelationship,
    Software,
    System,
    Vulnerability,
)


# Valid Input Test
@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "name": "Author Name",
                "description": "A description of the author.",
                "contact_information": "contact@organization.com",
                "x_opencti_organization_type": "vendor",
                "x_opencti_reliability": "A",
                "x_opencti_aliases": ["Alias1", "Alias2"],
            },
            id="valid_full_data",
        ),
        pytest.param({"name": "Minimal Author"}, id="valid_minimal_data"),
    ],
)
def test_author_class_should_accept_valid_input(input_data):
    # Given: Valid input params
    input_data_dct = dict(input_data)

    # When: We create an Author instance with valid input data
    author = Author(**input_data_dct)

    # Then: The Author instance should be created successfully
    assert author.name == input_data_dct.get("name")
    assert author.description == input_data_dct.get("description")
    assert author.contact_information == input_data_dct.get("contact_information")
    assert author.confidence == input_data_dct.get("confidence")
    assert author.x_opencti_organization_type == input_data_dct.get(
        "x_opencti_organization_type"
    )
    assert author.x_opencti_reliability == input_data_dct.get("x_opencti_reliability")
    assert author.x_opencti_aliases == input_data_dct.get("x_opencti_aliases")
    assert (
        author.to_stix2_object() is not None
    )  # Ensure the STIX2 object generation works


# Invalid Input Test
@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "description": "Missing name field",
            },
            "name",
            id="missing_name_field",
        ),
        pytest.param(
            {
                "name": "Author Name",
                "confidence": 150,
            },
            "confidence",
            id="invalid_confidence_value",
        ),
        pytest.param(
            {
                "name": "Author Name",
                "x_opencti_organization_type": "invalid_type",
            },
            "x_opencti_organization_type",
            id="invalid_x_opencti_organization_type",
        ),
        pytest.param(
            {
                "name": "Author Name",
                "x_opencti_aliases": "not_a_list",
            },
            "x_opencti_aliases",
            id="invalid_x_opencti_aliases_type",
        ),
    ],
)
def test_author_class_should_not_accept_invalid_input(input_data, error_field):
    # Given: Invalid input params
    input_data_dct = dict(input_data)

    # When: We try to create an Author instance with invalid data
    # Then: A ValidationError should be raised, and the error field should be in the error message
    with pytest.raises(ValidationError) as err:
        Author(**input_data_dct)
    assert str(error_field) in str(err)


# Valid and Invalid test cases for the System class


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "name": "Valid System",
            },
            id="Valid with only name",
        ),
        pytest.param(
            {
                "name": "System with Author",
                "author": Author(name="Valid Author"),
                "created": datetime(1970, 1, 1),
                "modified": datetime(1970, 1, 1),
                "description": "System Description",
                "object_marking_refs": [stix2.TLP_RED],
            },
            id="Valid with author and timestamps",
        ),
    ],
)
def test_system_class_should_accept_valid_inputs(input_data):
    # Given: valid input data for the System class
    input_data_dct = dict(input_data)
    # When: we create a System instance
    system = System(**input_data_dct)

    # Then: the System instance should be created successfully
    assert system.name == input_data_dct["name"]
    assert system.author == input_data_dct.get("author")
    assert system.created == input_data_dct.get("created")
    assert system.modified == input_data_dct.get("modified")
    assert system.description == input_data_dct.get("description")
    assert system.object_marking_refs == input_data_dct.get("object_marking_refs")
    assert (
        system.to_stix2_object() is not None
    )  # Ensure the STIX2 object generation works


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "name": None,
            },
            id="Invalid - missing name",
        ),
        pytest.param(
            {
                "name": "",
            },
            id="Invalid - empty name",
        ),
        pytest.param(
            {
                "name": "System with Author",
                "author": "Invalid Author",
            },
            id="Invalid - invalid author type",
        ),
        pytest.param(
            {
                "name": "Invalid Timestamps",
                "created": "Invalid Datetime",
                "modified": "Invalid Datetime",
            },
            id="Invalid - invalid date format",
        ),
    ],
)
def test_system_class_should_not_accept_invalid_inputs(input_data):
    # Given: valid input data for the System class
    input_data_dct = dict(input_data)
    # When: we try to create a System instance
    # Then: a ValidationError should be raised
    with pytest.raises(ValidationError):
        System(**input_data_dct)


# Test cases for the Observable subclasses (MACAddress, IPAddress, DomainName, Hostname, Software, OperatingSystem)
# Valid and Invalid test cases for the Observable subclasses


@pytest.mark.parametrize(
    "input_data, observable_cls",
    [
        pytest.param(
            {
                "value": "00:1B:44:11:3A:B7",
                "object_marking_refs": [stix2.TLP_GREEN],
            },
            MACAddress,
            id="valid_mac_address",
        ),
        pytest.param(
            {
                "value": "192.168.1.1",
                "version": "v4",
                "object_marking_refs": [stix2.TLP_GREEN],
            },
            IPAddress,
            id="valid_ipv4_address",
        ),
        pytest.param(
            {
                "value": "example.com",
                "object_marking_refs": [stix2.TLP_GREEN],
            },
            DomainName,
            id="valid_domain_name",
        ),
        pytest.param(
            {
                "value": "hostname.local",
                "object_marking_refs": [stix2.TLP_GREEN],
            },
            Hostname,
            id="valid_hostname",
        ),
        pytest.param(
            {
                "name": "Software Name",
                "cpe": "cpe:/a:vendor:software:1.0",
                "vendor": "Vendor Name",
                "object_marking_refs": [stix2.TLP_GREEN],
            },
            Software,
            id="valid_software",
        ),
    ],
)
def test_observable_class_should_accept_valid_inputs(input_data, observable_cls):
    # Given:
    # A valid input data and an observable class
    input_data_dct = dict(input_data)

    # When: we create an instance of the observable class
    observable = observable_cls(**input_data_dct)  # noqa

    # Then: the instance should be created successfully
    assert (
        observable.to_stix2_object() is not None
    )  # Ensure STIX2 object generation works
    for key, value in input_data_dct.items():
        assert getattr(observable, key) == value


@pytest.mark.parametrize(
    "input_data, observable_cls, error_field",
    [
        pytest.param(
            {
                "value": "Invalid MAC",
                "object_marking_refs": [stix2.TLP_GREEN],
            },
            MACAddress,
            "value",
            id="invalid_mac_address",
        ),
        pytest.param(
            {
                "value": "256.256.256.256",
                "version": "v4",
                "object_marking_refs": [stix2.TLP_GREEN],
            },
            IPAddress,
            "value",
            id="invalid_ipv4_address",
        ),
        pytest.param(
            {
                "value": "",
                "object_marking_refs": [stix2.TLP_GREEN],
            },
            DomainName,
            "value",
            id="invalid_empty_domain_name",
        ),
        pytest.param(
            {
                "value": 1234,
                "object_marking_refs": [stix2.TLP_GREEN],
            },
            Hostname,
            "value",
            id="invalid_hostname_type",
        ),
        pytest.param(
            {
                "name": "Software Name",
                "cpe": "invalid_cpe_format",
                "vendor": "Vendor Name",
                "object_marking_refs": [stix2.TLP_GREEN],
            },
            Software,
            "cpe",
            id="invalid_software_cpe",
        ),
    ],
)
def test_observable_class_should_not_accept_invalid_inputs(
    input_data, observable_cls, error_field
):
    # Given: invalid input data for an observable class
    input_data_dct = dict(input_data)

    # When: we try to create an instance of the observable class
    # Then: a ValidationError should be raised, and the error field should be in the error message
    with pytest.raises(ValidationError) as err:
        observable_cls(**input_data_dct)
    assert str(error_field) in str(err)


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "author": Author(name="Valid Author"),
                "created": datetime(2023, 1, 1),
                "modified": datetime(2023, 1, 2),
                "name": "CVE-2023-1234",
                "description": "A critical vulnerability.",
                "confidence": 90,
                "object_marking_refs": [stix2.TLP_RED],
            },
            id="valid_vulnerability",
        ),
    ],
)
def test_vulnerability_class_should_accept_valid_inputs(input_data):
    # Given: valid input data for the Vulnerability class
    input_data_dct = dict(input_data)

    # When: we create a Vulnerability instance
    vulnerability = Vulnerability(**input_data_dct)

    # Then: the Vulnerability instance should be created successfully
    assert (
        vulnerability.to_stix2_object() is not None
    )  # Ensure STIX2 object generation works
    for key, value in input_data_dct.items():
        assert getattr(vulnerability, key) == value


@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "author": Author(name="Valid Author"),
                "created": datetime(2023, 1, 1),
                "modified": datetime(2023, 1, 2),
                "name": "",
                "description": "A critical vulnerability.",
                "confidence": 90,
            },
            "name",
            id="invalid_empty_vulnerability_name",
        ),
        pytest.param(
            {
                "author": Author(name="Valid Author"),
                "created": datetime(2023, 1, 1),
                "modified": datetime(2023, 1, 2),
                "name": "CVE-2023-1234",
                "description": "A critical vulnerability.",
                "confidence": 150,
            },
            "confidence",
            id="invalid_confidence_value_vulnerability",
        ),
    ],
)
def test_vulnerability_class_should_not_accept_invalid_inputs(input_data, error_field):
    # Given: invalid input data for the Vulnerability class
    input_data_dct = dict(input_data)

    # When: we try to create a Vulnerability instance
    # Then: a ValidationError should be raised, and the error field should be in the error message
    with pytest.raises(ValidationError) as err:
        Vulnerability(**input_data_dct)
    assert str(error_field) in str(err)


# Valid input test cases for the RelatedToRelationship class
@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "author": Author(name="Minimal Author"),
                "created": datetime(2023, 1, 1),
                "modified": datetime(2023, 1, 2),
                "description": "This object is related to another object.",
                "source_ref": "vulnerability--6cfc1763-04a9-4652-8331-0ed2aa3660bb",
                "target_ref": "vulnerability--3f5d8868-7343-4a96-81fd-93188d835eeb",
                "start_time": datetime(2023, 1, 1),
                "stop_time": datetime(2023, 1, 2),
                "confidence": 80,
                "object_marking_refs": [stix2.TLP_AMBER],
            },
            id="valid_full_data",
        ),
        pytest.param(
            {
                "author": Author(name="Minimal Author"),
                "source_ref": "vulnerability--6cfc1763-04a9-4652-8331-0ed2aa3660bb",
                "target_ref": "vulnerability--3f5d8868-7343-4a96-81fd-93188d835eeb",
            },
            id="valid_minimal_data",
        ),
    ],
)
def test_related_to_relationship_should_accept_valid_inputs(input_data):
    # Given: Valid input data for RelatedToRelationship class
    input_data_dct = dict(input_data)

    # When: We create an instance of RelatedToRelationship
    relationship = RelatedToRelationship(**input_data_dct)

    # Then: The instance should be created successfully
    assert relationship.source_ref == input_data_dct["source_ref"]
    assert relationship.target_ref == input_data_dct["target_ref"]
    assert relationship.author == input_data_dct["author"]
    assert relationship.confidence == input_data_dct.get("confidence")
    assert (
        relationship.to_stix2_object() is not None
    )  # Ensure the STIX2 object is generated


# Invalid input test cases for the RelatedToRelationship class
@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "created": datetime(2023, 1, 1),
                "modified": datetime(2023, 1, 2),
                "source_ref": "source-entity-id",
                "target_ref": "target-entity-id",
            },
            "author",
            id="missing_author_field",
        ),
        pytest.param(
            {
                "author": Author(name="Invalid Date Format Author"),
                "source_ref": "vulnerability--6cfc1763-04a9-4652-8331-0ed2aa3660bb",
                "target_ref": "vulnerability--3f5d8868-7343-4a96-81fd-93188d835eeb",
                "start_time": "Invalid Date",
            },
            "start_time",
            id="invalid_start_time_format",
        ),
        pytest.param(
            {
                "author": Author(name="Invalid Source"),
                "target_ref": "target-entity-id",
            },
            "source_ref",
            id="missing_source_ref",
        ),
        pytest.param(
            {
                "author": Author(name="Invalid Target"),
                "source_ref": "source-entity-id",
            },
            "target_ref",
            id="missing_target_ref",
        ),
    ],
)
def test_related_to_relationship_should_not_accept_invalid_inputs(
    input_data, error_field
):
    # Given: Invalid input data for the RelatedToRelationship class
    input_data_dct = dict(input_data)

    # When: We try to create an instance of RelatedToRelationship
    # Then: A ValidationError should be raised, and the error field should be in the error message
    with pytest.raises(ValidationError) as err:
        RelatedToRelationship(**input_data_dct)
    assert str(error_field) in str(err)
