import pytest
from connectors_sdk.models import IPV4Address
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.base_observable_entity import BaseObservableEntity
from stix2.v21 import IPv4Address as Stix2IPv4Address


def test_observable_is_a_base_identified_entity():
    """Test that Observable is a BaseIdentifiedEntity."""
    # Given the Observable class
    # When checking iits type
    # Then it should be a subclass of BaseIdentifiedEntity
    assert issubclass(BaseObservableEntity, BaseIdentifiedEntity)


def test_observable_has_required_fields():
    """Test that Observable has the default fields."""

    # Given an Observable implementation
    class DummyObservable(BaseObservableEntity):
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
    assert issubclass(observable_type, BaseObservableEntity)
