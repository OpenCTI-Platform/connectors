import pytest
from connectors_sdk.models import Hostname, MediaContent, Text
from connectors_sdk.models.base_custom_observable_entity import (
    BaseCustomObservableEntity,
)
from connectors_sdk.models.base_observable_entity import BaseObservableEntity
from pycti import STIX_EXT_OCTI_SCO, CustomObservableText


def test_custom_observable_is_a_base_observable_entity():
    """Test that BaseCustomObservableEntity is a BaseObservableEntity."""
    # Given the BaseCustomObservableEntity class
    # When checking its type
    # Then it should be a subclass of BaseObservableEntity
    assert issubclass(BaseCustomObservableEntity, BaseObservableEntity)


@pytest.mark.parametrize(
    "custom_observable_type",
    [
        pytest.param(Hostname, id="hostname"),
        pytest.param(MediaContent, id="media_content"),
        pytest.param(Text, id="text"),
    ],
)
def test_is_custom_observable_subtype(custom_observable_type):
    """Test that the OpenCTI custom observable types use BaseCustomObservableEntity."""
    # Given a custom observable type
    # When checking its type
    # Then it should be a subclass of BaseCustomObservableEntity
    assert issubclass(custom_observable_type, BaseCustomObservableEntity)


def test_custom_observable_writes_opencti_properties_at_top_level(
    fake_valid_organization_author,
    fake_valid_external_references,
):
    """Test that the OpenCTI properties are at the top level, as in OpenCTI exports."""

    # Given a custom observable with OpenCTI properties
    class DummyCustomObservable(BaseCustomObservableEntity):
        """Dummy custom observable for testing."""

        def to_stix2_object(self):
            """Make stix object."""
            return CustomObservableText(
                value="dummy", **self._common_stix2_properties()
            )

    observable = DummyCustomObservable(
        score=0,
        description="Test description",
        labels=["test"],
        author=fake_valid_organization_author,
        external_references=fake_valid_external_references,
    )
    # When converting it to a STIX object
    stix2_obj = observable.to_stix2_object()
    # Then the properties are at the top level
    assert stix2_obj.labels == ["test"]
    assert stix2_obj.description == "Test description"
    assert stix2_obj.score == 0
    assert stix2_obj.created_by_ref == fake_valid_organization_author.id
    assert stix2_obj.external_references == [
        external_ref.to_stix2_object()
        for external_ref in fake_valid_external_references
    ]
    # And the SCO extension only declares the new-sco type
    assert stix2_obj.extensions == {STIX_EXT_OCTI_SCO: {"extension_type": "new-sco"}}
    # And the deprecated x_opencti_* properties are still there
    assert stix2_obj.x_opencti_labels == ["test"]
    assert stix2_obj.x_opencti_score == 0
