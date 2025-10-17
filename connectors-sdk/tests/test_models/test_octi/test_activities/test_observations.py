# pragma: no cover  # do not compute coverage on test files
"""Offer tests for observations OpenCTI entities."""

from datetime import datetime

import pytest
from connectors_sdk.models._observable import Observable
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.domain_name import DomainName
from connectors_sdk.models.file import File
from connectors_sdk.models.indicator import Indicator
from connectors_sdk.models.ipv4_address import IPV4Address
from connectors_sdk.models.octi.activities.observations import (
    URL,
    IPV6Address,
    Software,
)
from pydantic import ValidationError
from stix2.v21 import URL as Stix2URL
from stix2.v21 import DomainName as Stix2DomainName
from stix2.v21 import File as Stix2File
from stix2.v21 import Indicator as Stix2Indicator
from stix2.v21 import IPv4Address as Stix2IPv4Address
from stix2.v21 import IPv6Address as Stix2IPv6Address
from stix2.v21 import Software as Stix2Software

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
            return Stix2IPv4Address(value="127.0.0.1")

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


### DomainName


def test_domain_name_class_should_not_accept_invalid_input():
    """Test that DomainName class should not accept invalid input."""
    # Given: An invalid input data for DomainName
    input_data = {
        "value": "invalid_ip",
        "invalid_key": "invalid_value",
    }
    # When validating the domain name
    # Then: It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        DomainName.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_domain_name_to_stix2_object_returns_valid_stix_object():
    """Test that DomainName to_stix2_object method returns a valid STIX2.1 DomainName."""
    # Given: A valid DomainName instance
    domain_name = DomainName(value="test.com")
    # When: calling to_stix2_object method
    stix2_obj = domain_name.to_stix2_object()
    # Then: A valid STIX2.1 DomainName is returned
    assert isinstance(stix2_obj, Stix2DomainName)


### File


def test_file_class_should_not_accept_invalid_input():
    """Test that File class should not accept invalid input."""
    # Given: An invalid input data for File
    input_data = {
        "value": "invalid_ip",
        "invalid_key": "invalid_value",
    }
    # When validating the file
    # Then: It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        File.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_file_should_not_accept_missing_name_and_missing_hashes():
    """Test that File should not accept both missing name and missing hashes."""
    # Given an invalid input data for File with no name nor hashes
    input_data = {"mime_type": "text/plain"}
    # When validating the file
    # Then it should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        _ = File.model_validate(input_data)
        assert all(w in str(error.value.errors()[0]) for w in ("'name'", "'hashes'"))


def test_file_to_stix2_object_returns_valid_stix_object():
    """Test that File to_stix2_object method returns a valid STIX2.1 File."""
    # Given: A valid File instance
    file = File(name="test.txt")
    # When: calling to_stix2_object method
    stix2_obj = file.to_stix2_object()
    # Then: A valid STIX2.1 File is returned
    assert isinstance(stix2_obj, Stix2File)


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
    assert isinstance(stix2_obj, Stix2IPv4Address)


### IPV6Address


def test_ip_v6_class_should_not_accept_invalid_input():
    """Test that IPV6Address class should not accept invalid input."""
    # Given: An invalid input data for IPV6Address
    input_data = {
        "value": "invalid_ip",
        "invalid_key": "invalid_value",
    }
    # When validating the ipv6 address
    # Then: It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        IPV6Address.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_ip_v6_address_to_stix2_object_returns_valid_stix_object():
    """Test that IPV6Address to_stix2_object method returns a valid STIX2.1 IPV6Address."""
    # Given: A valid IPV6Address instance
    ipv6_address = IPV6Address(value="b357:5b10:0f48:d182:0140:494c:8fe9:6eda")
    # When: calling to_stix2_object method
    stix2_obj = ipv6_address.to_stix2_object()
    # Then: A valid STIX2.1 IPV6Address is returned
    assert isinstance(stix2_obj, Stix2IPv6Address)


### Software


def test_software_class_should_not_accept_invalid_input():
    """Test that Software class should not accept invalid input."""
    # Given: An invalid input data for Software
    input_data = {
        "name": "Test software",
        "invalid_key": "invalid_value",
    }
    # When validating the software
    # Then: It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        Software.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_software_address_to_stix2_object_returns_valid_stix_object(
    fake_valid_organization_author,
    fake_valid_tlp_markings,
    fake_valid_external_references,
):
    """Test that Software to_stix2_object method returns a valid STIX2.1 Software."""
    # Given: A valid Software instance
    ipv4_address = Software(
        name="Test Software",
        description="Test software description",
        labels=["label_1", "label_2"],
        version="1.0.0",
        vendor="Test vendor",
        swid="Test SWID",
        cpe="cpe:/a:test:software:1.0.0",
        languages=["python"],
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
    )
    # When: calling to_stix2_object method
    stix2_obj = ipv4_address.to_stix2_object()
    # Then: A valid STIX2.1 Software is returned
    assert isinstance(stix2_obj, Stix2Software)


### URL


def test_url_class_should_not_accept_invalid_input():
    """Test that URL class should not accept invalid input."""
    # Given: An invalid input data for URL
    input_data = {
        "value": "invalid_ip",
        "invalid_key": "invalid_value",
    }
    # When validating the url
    # Then: It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        URL.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_url_to_stix2_object_returns_valid_stix_object():
    """Test that URL to_stix2_object method returns a valid STIX2.1 URL."""
    # Given: A valid URL instance
    domain_name = URL(value="test.com")
    # When: calling to_stix2_object method
    stix2_obj = domain_name.to_stix2_object()
    # Then: A valid STIX2.1 URL is returned
    assert isinstance(stix2_obj, Stix2URL)
