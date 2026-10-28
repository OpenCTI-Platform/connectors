import pytest
import stix2
from connectors_sdk.models import AssociatedFile, Hostname, IPV4Address
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.base_observable_entity import BaseObservableEntity
from pycti import STIX_EXT_OCTI_SCO
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


def test_observable_writes_opencti_attributes_in_sco_extension(
    fake_valid_organization_author,
    fake_valid_external_references,
):
    """Test that the OpenCTI attributes go in the SCO extension and stay top-level."""
    # Given an observable with OpenCTI attributes
    observable = IPV4Address(
        value="127.0.0.1",
        score=0,
        description="Test description",
        labels=["test"],
        author=fake_valid_organization_author,
        external_references=fake_valid_external_references,
        associated_files=[AssociatedFile(name="file.txt", content=b"content")],
        create_indicator=True,
    )
    # When converting it to a STIX object
    stix2_obj = observable.to_stix2_object()
    # Then the extension holds the attributes, like OpenCTI exports
    assert stix2_obj.extensions[STIX_EXT_OCTI_SCO] == {
        "extension_type": "property-extension",
        "labels": ["test"],
        "description": "Test description",
        "score": 0,
        "created_by_ref": fake_valid_organization_author.id,
        "external_references": [
            external_ref.to_stix2_object()
            for external_ref in fake_valid_external_references
        ],
    }
    # And the deprecated top-level properties are still there
    assert stix2_obj.x_opencti_score == 0
    assert stix2_obj.x_opencti_labels == ["test"]
    # And files and create_indicator are only at the top level
    assert len(stix2_obj.x_opencti_files) == 1
    assert stix2_obj.x_opencti_create_indicator is True


def test_observable_sco_extension_without_attributes():
    """Test that the SCO extension only has its type when no attribute is set."""
    # Given an observable without OpenCTI attributes
    observable = IPV4Address(value="127.0.0.1")
    # When converting it to a STIX object
    stix2_obj = observable.to_stix2_object()
    # Then the extension only has its type
    assert stix2_obj.extensions == {
        STIX_EXT_OCTI_SCO: {"extension_type": "property-extension"}
    }


@pytest.mark.parametrize(
    "observable",
    [
        pytest.param(IPV4Address(value="127.0.0.1"), id="stix_observable"),
        pytest.param(Hostname(value="example.com"), id="opencti_custom_observable"),
    ],
)
def test_observable_attributes_do_not_change_id(
    observable,
    fake_valid_organization_author,
    fake_valid_external_references,
):
    """Test that the OpenCTI attributes do not change the STIX id."""
    # Given the same observable with OpenCTI attributes
    observable_with_attributes = observable.model_copy(
        update={
            "score": 50,
            "description": "Test description",
            "labels": ["test"],
            "author": fake_valid_organization_author,
            "external_references": fake_valid_external_references,
        }
    )
    # When converting both to STIX objects
    stix2_obj = observable.to_stix2_object()
    stix2_obj_with_attributes = observable_with_attributes.to_stix2_object()
    # Then they have the same id
    assert stix2_obj.id == stix2_obj_with_attributes.id
    # And the serialized object is still valid STIX
    parsed = stix2.parse(stix2_obj_with_attributes.serialize(), allow_custom=True)
    assert parsed.id == stix2_obj.id
