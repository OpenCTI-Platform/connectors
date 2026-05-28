from datetime import datetime

import pytest
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.indicator import Indicator
from pydantic import ValidationError
from stix2.v21 import Indicator as Stix2Indicator


def test_indicator_is_a_base_identified_entity():
    """Test that Indicator is a BaseIdentifiedEntity."""
    # Given the Indicator class
    # When checking its type
    # Then it should be a subclass of BaseIdentifiedEntity
    assert issubclass(Indicator, BaseIdentifiedEntity)


def test_indicator_has_required_fields():
    """Test that Indicator has the default fields."""
    # Given the Indicator implementation
    # When creating an instance of Indicator
    indicator = Indicator(
        name="Test Indicator",
        pattern="[ipv4-addr:value = '0.0.0.0']",
        pattern_type="stix",
    )
    # Then it should have the default fields
    assert hasattr(indicator, "name")
    assert hasattr(indicator, "pattern")
    assert hasattr(indicator, "pattern_type")
    assert hasattr(indicator, "main_observable_type")
    assert hasattr(indicator, "description")
    assert hasattr(indicator, "indicator_types")
    assert hasattr(indicator, "platforms")
    assert hasattr(indicator, "valid_from")
    assert hasattr(indicator, "valid_until")
    assert hasattr(indicator, "kill_chain_phases")
    assert hasattr(indicator, "score")
    assert hasattr(indicator, "associated_files")
    assert hasattr(indicator, "create_observables")


def test_indicator_should_not_accept_incoherent_dates():
    """Test that Indicator should not accept incoherent dates."""
    # Given an invalid input data for Indicator with valid_from after valid_until
    input_data = {
        "name": "Test Indicator",
        "pattern": "[ipv4-addr:value = '0.0.0.0']",
        "pattern_type": "stix",
        "valid_from": datetime.fromisoformat("2024-01-01T00:00:00+00:00"),
        "valid_until": datetime.fromisoformat("2023-01-01T00:00:00+00:00"),
    }
    # When validating the indicator
    # Then It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        _ = Indicator.model_validate(input_data)
        assert all(
            w in str(error.value.errors()[0]) for w in ("'valid_until'", "'valid_from'")
        )


def test_indicator_to_stix2_object_returns_valid_stix_object(
    fake_valid_organization_author,
    fake_valid_external_references,
    fake_valid_tlp_markings,
):
    """Test that Indicator.to_stix2_object returns a valid STIX Indicator."""
    # Given: A valid indicator input data
    input_data = {
        "name": "Test Indicator",
        "description": "Test Indicator description",
        "pattern": "[url:value='http://example.com']",
        "pattern_type": "stix",
        "indicator_types": ["malicious-activity", "anomalous-activity"],
        "kill_chain_phases": [
            {
                "chain_name": "test-chain",
                "phase_name": "test-phase",
            }
        ],
        "valid_from": datetime.fromisoformat("2023-01-01T00:00:00+00:00"),
        "valid_until": datetime.fromisoformat("2023-12-31T23:59:59+00:00"),
        "score": 50,
        "platforms": ["linux", "windows"],
        "main_observable_type": "Url",
        "author": fake_valid_organization_author,
        "external_references": fake_valid_external_references,
        "markings": fake_valid_tlp_markings,
    }
    indicator = Indicator.model_validate(input_data)

    # When: calling to_stix2_object method
    stix2_obj = indicator.to_stix2_object()

    # Then: A valid STIX Indicator is returned
    assert isinstance(stix2_obj, Stix2Indicator)
