import sys
from datetime import datetime
from pathlib import Path

import stix2

sys.path.append(str((Path(__file__).resolve().parent.parent.parent / "src")))

import pytest
from connector.models.opencti import Author, Incident
from pydantic import ValidationError


def mock_valid_author():
    return Author(name="Valid Author", identity_class="organization")


# Valid Input Test
@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "name": "Author Name",
                "description": "A description of the author.",
                "identity_class": "organization",
            },
            id="full_valid_data",
        ),
        pytest.param(
            {"name": "Minimal Author", "identity_class": "organization"},
            id="minimal_valid_data",
        ),
    ],
)
def test_author_class_should_accept_valid_input(input_data):
    # Given: Valid input params
    input_data_dict = dict(input_data)

    # When: We create an Author instance with valid input data
    author = Author(**input_data_dict)

    # Then: The Author instance should be created successfully
    assert author.name == input_data_dict.get("name")
    assert author.description == input_data_dict.get("description")
    assert (
        author.to_stix2_object() is not None
    )  # Ensure the STIX2 object generation works


# Invalid Input Test
@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {"description": "Missing name field", "identity_class": "organization"},
            "name",
            id="missing_name_field",
        ),
        pytest.param(
            {
                "name": ["Author Name"],
                "description": "A description of the author.",
                "identity_class": "organization",
            },
            "name",
            id="invalid_name_type",
        ),
        pytest.param(
            {
                "name": "Author Name",
                "identity_class": "organization",
                "extra_field": "extra_value",
            },
            "extra_field",
            id="invalid_extra_field",
        ),
    ],
)
def test_author_class_should_not_accept_invalid_input(input_data, error_field):
    # Given: Invalid input params
    input_data_dict = dict(input_data)

    # When: We try to create an Author instance with invalid data
    # Then: A ValidationError should be raised, and the error field should be in the error message
    with pytest.raises(ValidationError) as err:
        Author(**input_data_dict)
    assert str(error_field) in str(err)


# Valid Input Tests
@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "name": "Incident with Author",
                "description": "Incident Description",
                "source": "Unknown",
                "severity": "low",
                "incident_type": "data-breach",
                "author": mock_valid_author(),
                "created_at": datetime(1970, 1, 1),
                "updated_at": datetime(1970, 1, 1),
                "object_marking_refs": [stix2.TLP_RED],
            },
            id="full_valid_data",
        ),
        pytest.param(
            {
                "name": "Valid Incident",
                "source": "Unknown",
                "severity": "low",
                "incident_type": "data-breach",
                "author": mock_valid_author(),
                "created_at": datetime(1970, 1, 1),
                "updated_at": datetime(1970, 1, 1),
                "object_marking_refs": [stix2.TLP_RED],
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_incident_class_should_accept_valid_input(input_data):
    # Given: valid input data for the Incident class
    input_data_dict = dict(input_data)
    # When: we create a Incident instance
    incident = Incident(**input_data_dict)

    # Then: the Incident instance should be created successfully
    assert incident.name == input_data_dict["name"]
    assert incident.description == input_data_dict.get("description")
    assert incident.author == input_data_dict.get("author")
    assert incident.created_at == input_data_dict.get("created_at")
    assert incident.updated_at == input_data_dict.get("updated_at")
    assert incident.object_marking_refs == input_data_dict.get("object_marking_refs")
    assert (
        incident.to_stix2_object() is not None
    )  # Ensure the STIX2 object generation works


# Invalid Input Tests
@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "description": "Incident description",
                "source": "Unknown",
                "severity": "low",
                "incident_type": "data-breach",
                "author": mock_valid_author(),
                "created_at": datetime(1970, 1, 1),
                "updated_at": datetime(1970, 1, 1),
                "object_marking_refs": [stix2.TLP_WHITE],
            },
            "name",
            id="invalid_missing_name",
        ),
        pytest.param(
            {
                "name": "",
                "description": "Incident description",
                "source": "Unknown",
                "severity": "low",
                "incident_type": "data-breach",
                "author": mock_valid_author(),
                "created_at": datetime(1970, 1, 1),
                "updated_at": datetime(1970, 1, 1),
                "object_marking_refs": [stix2.TLP_WHITE],
            },
            "name",
            id="invalid_empty_name",
        ),
        pytest.param(
            {
                "name": "Incident name",
                "description": "Incident description",
                "source": "Unknown",
                "severity": "low",
                "incident_type": "data-breach",
                "author": "Invalid author",
                "created_at": datetime(1970, 1, 1),
                "updated_at": datetime(1970, 1, 1),
                "object_marking_refs": [stix2.TLP_WHITE],
            },
            "author",
            id="invalid_author_type",
        ),
        pytest.param(
            {
                "name": "Incident name",
                "description": "Incident description",
                "source": "Unknown",
                "severity": "low",
                "incident_type": "data-breach",
                "author": mock_valid_author(),
                "created_at": "01/01/1970",
                "updated_at": datetime(1970, 1, 1),
                "object_marking_refs": [stix2.TLP_RED],
            },
            "created_at",
            id="invalid_date_format",
        ),
        pytest.param(
            {
                "name": "Incident with Author",
                "description": "Incident Description",
                "source": "Unknown",
                "severity": "invalid value",
                "incident_type": "data-breach",
                "author": mock_valid_author(),
                "created_at": datetime(1970, 1, 1),
                "updated_at": datetime(1970, 1, 1),
                "object_marking_refs": [stix2.TLP_RED],
            },
            "severity",
            id="invalid_severity_value",
        ),
        pytest.param(
            {
                "name": "Incident with Author",
                "description": "Incident Description",
                "source": "Unknown",
                "severity": "low",
                "incident_type": "data-breach",
                "author": mock_valid_author(),
                "created_at": datetime(1970, 1, 1),
                "updated_at": datetime(1970, 1, 1),
                "object_marking_refs": [stix2.TLP_RED],
                "extra_field": "extra_value",
            },
            "extra_field",
            id="invalid_extra_field",
        ),
    ],
)
def test_incident_class_should_not_accept_invalid_input(input_data, error_field):
    # Given: valid input data for the Incident class
    input_data_dict = dict(input_data)

    # When: we try to create a Incident instance
    # Then: a ValidationError should be raised
    with pytest.raises(ValidationError) as err:
        Incident(**input_data_dict)
    assert str(error_field) in str(err)
