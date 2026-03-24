from datetime import datetime, timezone

import pytest
from connectors_sdk.models import (
    ExternalReference,
    Indicator,
    Organization,
    OrganizationAuthor,
    Reference,
    TLPMarking,
)
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.sighting import Sighting
from pydantic import ValidationError
from stix2.v21 import Sighting as Stix2Sighting


def test_sighting_is_a_base_identified_entity() -> None:
    """Test that Sighting is a BaseIdentifiedEntity."""
    # Given the Sighting class
    # When checking its type
    # Then it should be a subclass of BaseIdentifiedEntity
    assert issubclass(Sighting, BaseIdentifiedEntity)


def test_sighting_class_should_not_accept_invalid_input(
    fake_valid_organization_author: OrganizationAuthor,
) -> None:
    """Test that Sighting class should not accept invalid input."""
    # Given: An invalid input data for Sighting
    input_data = {
        "sighting_of": fake_valid_organization_author,
        "where_sighted": [fake_valid_organization_author],
        "invalid_key": "invalid_value",
    }
    # When validating the sighting
    # Then: It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        Sighting.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_sighting_class_should_not_accept_empty_where_sighted(
    fake_valid_organization_author: OrganizationAuthor,
) -> None:
    """Test that Sighting should not accept an empty where_sighted list."""
    # Given: A Sighting with an empty where_sighted
    # When validating
    # Then: It should raise a ValidationError (min_length=1)
    with pytest.raises(ValidationError):
        Sighting(
            sighting_of=fake_valid_organization_author,
            where_sighted=[],
        )


def test_sighting_class_should_not_accept_negative_count(
    fake_valid_organization_author: OrganizationAuthor,
) -> None:
    """Test that Sighting should not accept a negative count."""
    # Given: A Sighting with count=-1
    # When validating
    # Then: It should raise a ValidationError (ge=0)
    with pytest.raises(ValidationError):
        Sighting(
            sighting_of=fake_valid_organization_author,
            where_sighted=[fake_valid_organization_author],
            count=-1,
        )


def test_sighting_to_stix2_object_returns_valid_stix_object(
    fake_valid_organization_author: OrganizationAuthor,
    fake_valid_external_references: list[ExternalReference],
    fake_valid_tlp_markings: list[TLPMarking],
) -> None:
    """Test that Sighting to_stix2_object method returns a valid STIX2.1 Sighting."""
    # Given: A valid Sighting instance with all optional fields
    indicator = Indicator(
        name="Test Indicator",
        pattern="[ipv4-addr:value = '1.2.3.4']",
        pattern_type="stix",
        valid_from="2026-01-01T00:00:00Z",
    )
    sighting = Sighting(
        sighting_of=indicator,
        where_sighted=[fake_valid_organization_author],
        first_seen=datetime(2026, 1, 1, tzinfo=timezone.utc),
        last_seen=datetime(2026, 3, 1, tzinfo=timezone.utc),
        count=5,
        description="Sighted 5 times in Q1 2026.",
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
    )
    # When: calling to_stix2_object method
    stix2_obj = sighting.to_stix2_object()
    # Then: A valid STIX2.1 Sighting is returned with correct fields
    assert isinstance(stix2_obj, Stix2Sighting)
    assert stix2_obj.sighting_of_ref == indicator.id
    assert stix2_obj.where_sighted_refs == [fake_valid_organization_author.id]
    assert stix2_obj.count == 5
    assert stix2_obj.description == "Sighted 5 times in Q1 2026."
    assert str(stix2_obj.first_seen) == "2026-01-01 00:00:00+00:00"
    assert str(stix2_obj.last_seen) == "2026-03-01 00:00:00+00:00"


def test_sighting_to_stix2_object_minimal(
    fake_valid_organization_author: OrganizationAuthor,
) -> None:
    """Test that Sighting works with minimal required fields only."""
    # Given: A Sighting with only required fields
    sighting = Sighting(
        sighting_of=fake_valid_organization_author,
        where_sighted=[fake_valid_organization_author],
    )
    # When: calling to_stix2_object method
    stix2_obj = sighting.to_stix2_object()
    # Then: A valid STIX2.1 Sighting is returned
    assert isinstance(stix2_obj, Stix2Sighting)
    assert stix2_obj.sighting_of_ref == fake_valid_organization_author.id


def test_sighting_to_stix2_object_has_deterministic_id(
    fake_valid_organization_author: OrganizationAuthor,
) -> None:
    """Test that Sighting produces a deterministic STIX ID."""
    # Given: Two identical Sighting instances
    kwargs = dict(
        sighting_of=fake_valid_organization_author,
        where_sighted=[fake_valid_organization_author],
        first_seen=datetime(2026, 1, 1, tzinfo=timezone.utc),
        last_seen=datetime(2026, 3, 1, tzinfo=timezone.utc),
    )
    sighting_a = Sighting(**kwargs)
    sighting_b = Sighting(**kwargs)
    # When: converting both to STIX objects
    stix_a = sighting_a.to_stix2_object()
    stix_b = sighting_b.to_stix2_object()
    # Then: They should have the same deterministic ID
    assert stix_a.id == stix_b.id
    assert stix_a.id.startswith("sighting--")


def test_sighting_to_stix2_object_with_reference_objects() -> None:
    """Test that Sighting works with Reference objects for sighting_of and where_sighted."""
    # Given: Reference objects instead of concrete entities
    indicator_ref = Reference(id="indicator--fe6ebd9d-1a4a-4c2b-8ae9-dac8918f52a9")
    identity_ref = Reference(id="identity--ae6ebd9d-1a4a-4c2b-8ae9-dac8918f52a9")
    # When: creating a Sighting with References
    sighting = Sighting(
        sighting_of=indicator_ref,
        where_sighted=[identity_ref],
    )
    stix2_obj = sighting.to_stix2_object()
    # Then: The ref fields should resolve to the Reference IDs
    assert isinstance(stix2_obj, Stix2Sighting)
    assert stix2_obj.sighting_of_ref == indicator_ref.id
    assert stix2_obj.where_sighted_refs == [identity_ref.id]


def test_sighting_to_stix2_object_with_multiple_where_sighted(
    fake_valid_organization_author: OrganizationAuthor,
) -> None:
    """Test that Sighting supports multiple where_sighted."""
    # Given: A Sighting with multiple where_sighted
    org_a = Organization(name="Org A")
    org_b = Organization(name="Org B")
    sighting = Sighting(
        sighting_of=fake_valid_organization_author,
        where_sighted=[org_a, org_b],
    )
    # When: calling to_stix2_object method
    stix2_obj = sighting.to_stix2_object()
    # Then: where_sighted_refs should contain both IDs
    assert isinstance(stix2_obj, Stix2Sighting)
    assert len(stix2_obj.where_sighted_refs) == 2
    assert stix2_obj.where_sighted_refs == [org_a.id, org_b.id]


def test_sighting_count_zero_is_valid(
    fake_valid_organization_author: OrganizationAuthor,
) -> None:
    """Test that count=0 is accepted (ge=0)."""
    # Given: A Sighting with count=0
    sighting = Sighting(
        sighting_of=fake_valid_organization_author,
        where_sighted=[fake_valid_organization_author],
        count=0,
    )
    # When: calling to_stix2_object method
    stix2_obj = sighting.to_stix2_object()
    # Then: count should be 0
    assert stix2_obj.count == 0


def test_sighting_with_observed_data(
    fake_valid_organization_author: OrganizationAuthor,
) -> None:
    """Test that Sighting supports observed_data field."""
    # Given: A Sighting with observed_data references
    observed_data_ref = Reference(
        id="observed-data--ae6ebd9d-1a4a-4c2b-8ae9-dac8918f52a9"
    )
    sighting = Sighting(
        sighting_of=fake_valid_organization_author,
        where_sighted=[fake_valid_organization_author],
        observed_data=[observed_data_ref],
    )
    # When: calling to_stix2_object method
    stix2_obj = sighting.to_stix2_object()
    # Then: observed_data_refs should be set
    assert isinstance(stix2_obj, Stix2Sighting)
    assert stix2_obj.observed_data_refs == [observed_data_ref.id]


def test_sighting_with_qualification(
    fake_valid_organization_author: OrganizationAuthor,
) -> None:
    """Test that Sighting supports qualification field (false positive)."""
    # Given: A Sighting marked as false positive
    sighting = Sighting(
        sighting_of=fake_valid_organization_author,
        where_sighted=[fake_valid_organization_author],
        qualification=True,
    )
    # When: calling to_stix2_object method
    stix2_obj = sighting.to_stix2_object()
    # Then: x_opencti_negative should be True
    assert isinstance(stix2_obj, Stix2Sighting)
    assert stix2_obj.x_opencti_negative is True
