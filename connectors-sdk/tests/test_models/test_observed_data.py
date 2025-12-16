"""Tests for ObservedData model."""

from datetime import datetime, timezone

import pytest
from connectors_sdk.models import URL, BaseIdentifiedEntity, IPV4Address, ObservedData
from pydantic import ValidationError
from stix2.v21 import ObservedData as Stix2ObservedData


def test_observed_data_is_a_base_identified_entity():
    """Test that ObservedData is a BaseIdentifiedEntity."""
    assert issubclass(ObservedData, BaseIdentifiedEntity)


def test_observed_data_requires_first_observed():
    """Test that ObservedData requires first_observed field."""
    input_data = {
        "last_observed": datetime(2025, 1, 1, 13, 0, 0, tzinfo=timezone.utc),
        "number_observed": 5,
        "entities": [IPV4Address(value="1.1.1.1")],
    }
    with pytest.raises(ValidationError) as error:
        ObservedData.model_validate(input_data)
        assert "first_observed" in str(error.value)


def test_observed_data_requires_last_observed():
    """Test that ObservedData requires last_observed field."""
    input_data = {
        "first_observed": datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        "number_observed": 5,
        "entities": [IPV4Address(value="1.1.1.1")],
    }
    with pytest.raises(ValidationError) as error:
        ObservedData.model_validate(input_data)
        assert "last_observed" in str(error.value)


def test_observed_data_requires_number_observed():
    """Test that ObservedData requires number_observed field."""
    input_data = {
        "first_observed": datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        "last_observed": datetime(2025, 1, 1, 13, 0, 0, tzinfo=timezone.utc),
        "entities": [IPV4Address(value="1.1.1.1")],
    }
    with pytest.raises(ValidationError) as error:
        ObservedData.model_validate(input_data)
        assert "number_observed" in str(error.value)


def test_observed_data_requires_entities():
    """Test that ObservedData requires entities field."""
    input_data = {
        "first_observed": datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        "last_observed": datetime(2025, 1, 1, 13, 0, 0, tzinfo=timezone.utc),
        "number_observed": 5,
    }
    with pytest.raises(ValidationError) as error:
        ObservedData.model_validate(input_data)
        assert "entities" in str(error.value)


def test_observed_data_should_not_accept_empty_entities():
    """Test that ObservedData cannot be created with empty entities list."""
    input_data = {
        "first_observed": datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        "last_observed": datetime(2025, 1, 1, 13, 0, 0, tzinfo=timezone.utc),
        "number_observed": 5,
        "entities": [],
    }
    with pytest.raises(ValidationError) as error:
        ObservedData.model_validate(input_data)
        assert "entities" in str(error.value)


def test_observed_data_should_not_accept_none_entities():
    """Test that ObservedData cannot be created with None entities."""
    # Given valid input data for ObservedData with entities = None
    input_data = {
        "first_observed": datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        "last_observed": datetime(2025, 1, 1, 13, 0, 0, tzinfo=timezone.utc),
        "number_observed": 5,
        "entities": None,
    }
    with pytest.raises(ValidationError) as error:
        ObservedData.model_validate(input_data)
        assert "entities" in str(error.value)


def test_observed_data_should_not_accept_invalid_input():
    """Test that ObservedData should not accept invalid input."""
    input_data = {
        "first_observed": datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        "last_observed": datetime(2025, 1, 1, 13, 0, 0, tzinfo=timezone.utc),
        "number_observed": 5,
        "entities": [IPV4Address(value="1.1.1.1")],
        "invalid_key": "invalid_value",
    }
    with pytest.raises(ValidationError) as error:
        ObservedData.model_validate(input_data)
        assert "invalid_key" in str(error.value)


def test_observed_data_should_not_accept_incoherent_dates():
    """Test that ObservedData should not accept incoherent dates."""
    input_data = {
        "first_observed": datetime(2025, 1, 2, 12, 0, 0, tzinfo=timezone.utc),
        "last_observed": datetime(2025, 1, 1, 13, 0, 0, tzinfo=timezone.utc),
        "number_observed": 5,
        "entities": [IPV4Address(value="1.1.1.1")],
    }
    with pytest.raises(ValidationError) as error:
        ObservedData.model_validate(input_data)
        assert (
            "'last_observed' must be greater than or equal to 'first_observed'"
            in str(error.value)
        )


def test_observed_data_accepts_equal_dates():
    """Test that ObservedData accepts first_observed equal to last_observed."""
    input_data = {
        "first_observed": datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        "last_observed": datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        "number_observed": 5,
        "entities": [IPV4Address(value="1.1.1.1")],
    }
    observed_data = ObservedData.model_validate(input_data)
    assert observed_data.first_observed == observed_data.last_observed


def test_observed_data_should_not_accept_zero_number_observed():
    """Test that ObservedData rejects zero number_observed."""
    input_data = {
        "first_observed": datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        "last_observed": datetime(2025, 1, 1, 13, 0, 0, tzinfo=timezone.utc),
        "number_observed": 0,
        "entities": [IPV4Address(value="1.1.1.1")],
    }
    with pytest.raises(ValidationError) as error:
        ObservedData.model_validate(input_data)
        assert "Input should be greater than 0" in str(error.value)


def test_observed_data_should_not_accept_negative_number_observed():
    """Test that ObservedData rejects negative number_observed."""
    input_data = {
        "first_observed": datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        "last_observed": datetime(2025, 1, 1, 13, 0, 0, tzinfo=timezone.utc),
        "number_observed": -5,
        "entities": [IPV4Address(value="1.1.1.1")],
    }
    with pytest.raises(ValidationError) as error:
        ObservedData.model_validate(input_data)
        assert "Input should be greater than 0" in str(error.value)


def test_observed_data_with_single_object():
    """Test that ObservedData can be created with a single object."""
    ipv4 = IPV4Address(value="192.168.1.1")
    input_data = {
        "first_observed": datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        "last_observed": datetime(2025, 1, 1, 13, 0, 0, tzinfo=timezone.utc),
        "number_observed": 5,
        "entities": [ipv4],
    }
    observed_data = ObservedData.model_validate(input_data)
    assert len(observed_data.entities) == 1
    assert observed_data.entities[0].value == "192.168.1.1"


def test_observed_data_with_multiple_entities():
    """Test that ObservedData can be created with multiple entities."""
    ipv4 = IPV4Address(value="192.168.1.1")
    url = URL(value="https://example.com")
    input_data = {
        "first_observed": datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        "last_observed": datetime(2025, 1, 1, 13, 0, 0, tzinfo=timezone.utc),
        "number_observed": 5,
        "entities": [ipv4, url],
    }
    observed_data = ObservedData.model_validate(input_data)
    assert len(observed_data.entities) == 2


def test_observed_data_to_stix2_object_returns_valid_stix_object(
    fake_valid_organization_author,
    fake_valid_external_references,
    fake_valid_tlp_markings,
    fake_valid_associated_files,
):
    """Test that ObservedData.to_stix2_object returns a valid STIX ObservedData."""
    input_data = {
        "first_observed": datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        "last_observed": datetime(2025, 1, 1, 13, 0, 0, tzinfo=timezone.utc),
        "number_observed": 5,
        "entities": [IPV4Address(value="1.1.1.1")],
        "author": fake_valid_organization_author,
        "external_references": fake_valid_external_references,
        "markings": fake_valid_tlp_markings,
        "associated_files": fake_valid_associated_files,
        "labels": ["test_label"],
    }
    observed_data = ObservedData.model_validate(input_data)

    stix2_obj = observed_data.to_stix2_object()

    assert isinstance(stix2_obj, Stix2ObservedData)
    assert stix2_obj.first_observed == observed_data.first_observed
    assert stix2_obj.last_observed == observed_data.last_observed
    assert stix2_obj.number_observed == observed_data.number_observed


def test_observed_data_to_stix2_object_with_entities(
    fake_valid_organization_author,
    fake_valid_tlp_markings,
):
    """Test that ObservedData.to_stix2_object correctly includes object_refs."""
    ipv4 = IPV4Address(value="192.168.1.1")
    url = URL(value="https://example.com")
    input_data = {
        "first_observed": datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        "last_observed": datetime(2025, 1, 1, 13, 0, 0, tzinfo=timezone.utc),
        "number_observed": 5,
        "entities": [ipv4, url],
        "author": fake_valid_organization_author,
        "markings": fake_valid_tlp_markings,
    }
    observed_data = ObservedData.model_validate(input_data)

    stix2_obj = observed_data.to_stix2_object()

    assert isinstance(stix2_obj, Stix2ObservedData)
    assert len(stix2_obj.object_refs) == 2
    assert ipv4.id in stix2_obj.object_refs
    assert url.id in stix2_obj.object_refs
