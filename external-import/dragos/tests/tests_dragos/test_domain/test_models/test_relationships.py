"""Offer tests for the relationships module."""

from datetime import datetime, timezone

import pytest
import stix2
from dragos.domain.models.octi import (
    ExternalReference,
    IndicatorBasedOnObservable,
    OrganizationAuthor,
    TLPMarking,
    Url,
)
from dragos.domain.models.octi.enums import TLPLevel
from pydantic import ValidationError


def fake_valid_organization_author():
    """Return a valid Organization Author."""
    return OrganizationAuthor(name="Valid Author")


def fake_valid_tlp_marking():
    """Return a valid TLP Marking."""
    return TLPMarking(level=TLPLevel.RED.value)


def fake_external_reference():
    """Return a valid External Reference."""
    return ExternalReference(
        source_name="Test Source",
        description="Test Description",
        url="http://example.com",
        external_id="test_id",
    )


def fake_valid_url_observable():
    """Return a valid Url Observable."""
    return Url(
        value="http://example.com",
        description="Test Url Observable",
        author=fake_valid_organization_author(),
        markings=[fake_valid_tlp_marking()],
    )


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "source": fake_valid_url_observable().to_indicator(),
                "target": fake_valid_url_observable(),
                "description": "Test Indicator description",
                "start_time": datetime(1970, 1, 1, tzinfo=timezone.utc),
                "stop_time": datetime.now(tz=timezone.utc),
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
                "external_references": [fake_external_reference()],
            },
            id="full_valid_data",
        ),
        pytest.param(
            {
                "source": fake_valid_url_observable().to_indicator(),
                "target": fake_valid_url_observable(),
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_relationship_based_on_observable_should_accept_valid_input(input_data):
    """Test that IndicatorBasedOnObservable.model_validate accepts valid input data."""
    # Given: Valid relationship input data
    # When: Creating an relationship object
    relationship = IndicatorBasedOnObservable.model_validate(input_data)

    # Then: The relationship object should be valid
    assert relationship.id is not None  # noqa S101
    assert relationship.source == input_data.get("source")  # noqa S101
    assert relationship.target == input_data.get("target")  # noqa S101
    assert relationship.description == input_data.get("description")  # noqa S101
    assert relationship.start_time == input_data.get("start_time")  # noqa S101
    assert relationship.stop_time == input_data.get("stop_time")  # noqa S101
    assert relationship.author == input_data.get("author")  # noqa S101
    assert relationship.external_references == input_data.get(  # noqa S101
        "external_references"
    )
    assert relationship.markings == input_data.get("markings")  # noqa S101


@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "source": fake_valid_organization_author(),
                "target": fake_valid_url_observable(),
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "source",
            id="invalid_source_type",
        ),
        pytest.param(
            {
                "source": fake_valid_url_observable().to_indicator(),
                "target": fake_valid_organization_author(),
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "target",
            id="invalid_target_type",
        ),
        # pytest.param(
        #     {
        #        "source": fake_valid_url_observable().to_indicator(),
        #        "target": fake_valid_url_observable(),
        #        "markings": [fake_valid_tlp_marking()],
        #     },
        #     "author",
        #     id="missing_author",
        # ),
    ],
)
def test_relationship_based_on_observable_should_not_accept_invalid_input(
    input_data, error_field
):
    """Test that IndicatorBasedOnObservable.model_validate does not accept invalid input data."""
    # Given: Invalid input data for the Indicator class
    # When: Trying to create a Indicator instance
    # Then: A ValidationError should be raised
    with pytest.raises(ValidationError) as err:
        IndicatorBasedOnObservable.model_validate(input_data)
    assert str(error_field) in str(err)  # noqa: S101


def test_relationship_to_stix2_object_returns_valid_stix_object():
    """Test that IndicatorBasedOnObservable.to_stix2_object returns a valid STIX2.1 Indicator."""
    # Given: A valid relationship
    input_data = {
        "source": fake_valid_url_observable().to_indicator(),
        "target": fake_valid_url_observable(),
        "description": "Test Indicator description",
        "start_time": datetime(1970, 1, 1, tzinfo=timezone.utc),
        "stop_time": datetime.now(tz=timezone.utc),
        "author": fake_valid_organization_author(),
        "markings": [fake_valid_tlp_marking()],
        "external_references": [fake_external_reference()],
    }
    relationship = IndicatorBasedOnObservable.model_validate(input_data)

    # When: calling to_stix2_object method
    stix2_obj = relationship.to_stix2_object()

    # Then: A valid STIX2.1 Indicator is returned
    assert isinstance(stix2_obj, stix2.Relationship) is True  # noqa: S101
    assert stix2_obj.id is not None  # noqa: S101
    assert stix2_obj.source_ref == input_data.get("source").id  # noqa: S101
    assert stix2_obj.target_ref == input_data.get("target").id  # noqa: S101
    assert stix2_obj.description == input_data.get("description")  # noqa: S101
    assert stix2_obj.start_time == input_data.get("start_time")  # noqa: S101
    assert stix2_obj.stop_time == input_data.get("stop_time")  # noqa: S101
