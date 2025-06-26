# pragma: no cover  # do not compute coverage on test files
"""Offer tests for observations OpenCTI entities."""

from datetime import datetime

import pytest
import stix2
from connectors_sdk.models.octi._common import BaseIdentifiedEntity
from connectors_sdk.models.octi.activities.observations import (
    Indicator,
    IPV4Address,
    Observable,
)
from pydantic import ValidationError

### OBSERVABLE BASE TYPE


def test_observable_is_a_base_identified_entity():
    """Test that Observable is a BaseIdentifiedEntity."""
    # Given the Observable class
    # When checking iits type
    # Then it should be a subclass of BaseIdentifiedEntity
    assert issubclass(Observable, BaseIdentifiedEntity)


def test_observable_has_required_fields():
    """Test that Observable has the default fields."""

    # Given an Observable implementation
    class DummyObservable(Observable):
        """Dummy Observable for testing."""

        def to_stix2_object(self):
            """Dummy method to satisfy the interface."""
            return stix2.v21.IPv4Address(value="127.0.0.1")

    # When creating an instance of DummyObservable
    observable = DummyObservable()
    # Then it should have the default fields
    assert hasattr(observable, "score")
    assert hasattr(observable, "description")
    assert hasattr(observable, "labels")
    assert hasattr(observable, "associated_files")
    assert hasattr(observable, "create_indicator")


#### INDICATOR


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
    fake_valid_external_referencess,
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
        "external_references": fake_valid_external_referencess,
        "markings": fake_valid_tlp_markings,
    }
    indicator = Indicator.model_validate(input_data)

    # When: calling to_stix2_object method
    stix2_obj = indicator.to_stix2_object()

    # Then: A valid STIX Indicator is returned
    assert isinstance(stix2_obj, stix2.Indicator)


### OBSERVABLES


@pytest.mark.parametrize(
    "observable_type",
    [
        pytest.param(IPV4Address, id="ipv4_address"),
        # Add more observable types as needed
    ],
)
def test_is_observable_subtype(observable_type):
    """Test that the observable type is a subtype of Observable."""
    # Given an observable type
    # When checking its type
    # Then it should be a subclass of Observable
    assert issubclass(observable_type, Observable)


### IPV4Address


def test_ip_v4_class_should_not_accept_invalid_input():
    """Test that IPV4Address class should not accept invalid input."""
    # Given: An invalid input data for IPV4Address
    input_data = {
        "value": "invalid_ip",
        "invalid_key": "invalid_value",
    }
    # When validating the ipv4 address
    # Then: It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        IPV4Address.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_ip_v4_address_to_stix2_object_returns_valid_stix_object():
    """Test that IPV4Address to_stix2_object method returns a valid STIX2.1 IPV4Address."""
    # Given: A valid IPV4Address instance
    ipv4_address = IPV4Address(value="0.0.0.0/24")  # explict test with CIDR notation
    # When: calling to_stix2_object method
    stix2_obj = ipv4_address.to_stix2_object()
    # Then: A valid STIX2.1 IPV4Address is returned
    assert isinstance(stix2_obj, stix2.v21.IPv4Address)
