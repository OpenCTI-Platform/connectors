import pytest
from connectors_sdk.models.base_observable_entity import BaseObservableEntity
from connectors_sdk.models.media_content import MediaContent
from pycti import CustomObservableMediaContent
from pydantic import ValidationError


def test_media_content_is_a_base_observable_entity():
    """Test that MediaContent is a BaseObservableEntity."""
    assert issubclass(MediaContent, BaseObservableEntity)


def test_media_content_class_should_not_accept_invalid_input():
    """Test that MediaContent class should not accept invalid input."""
    input_data = {
        "url": "https://example.com/post",
        "invalid_key": "invalid_value",
    }
    with pytest.raises(ValidationError):
        MediaContent.model_validate(input_data)


def test_media_content_to_stix2_object_returns_valid_stix_object(
    fake_valid_organization_author,
    fake_valid_external_references,
    fake_valid_tlp_markings,
):
    """Test that MediaContent to_stix2_object method returns a valid custom STIX object."""
    media_content = MediaContent(
        title="Test title",
        description="Test description",
        content="Test body",
        media_category="article",
        url="https://example.com/post",
        publication_date="2024-01-01T00:00:00Z",
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
        score=80,
        labels=["news"],
        create_indicator=True,
    )
    stix2_obj = media_content.to_stix2_object()

    assert stix2_obj == CustomObservableMediaContent(
        url="https://example.com/post",
        title="Test title",
        content="Test body",
        media_category="article",
        publication_date="2024-01-01T00:00:00Z",
        allow_custom=True,
        object_marking_refs=[marking.id for marking in fake_valid_tlp_markings],
        x_opencti_score=80,
        x_opencti_description="Test description",
        x_opencti_labels=["news"],
        x_opencti_external_references=[
            external_ref.to_stix2_object()
            for external_ref in fake_valid_external_references
        ],
        x_opencti_created_by_ref=fake_valid_organization_author.id,
        x_opencti_files=[],
        x_opencti_create_indicator=True,
    )
