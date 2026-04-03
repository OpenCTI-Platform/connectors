import pytest
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.channel import Channel
from pycti import Channel as PyctiChannel
from pycti import CustomObjectChannel
from pydantic import ValidationError


def test_channel_is_a_base_identified_entity():
    """Test that Channel is a BaseIdentifiedEntity."""
    assert issubclass(Channel, BaseIdentifiedEntity)


def test_channel_class_should_not_accept_invalid_input():
    """Test that Channel class should not accept invalid input."""
    input_data = {
        "name": "Test channel",
        "invalid_key": "invalid_value",
    }
    with pytest.raises(ValidationError):
        Channel.model_validate(input_data)


def test_channel_to_stix2_object_returns_valid_stix_object(
    fake_valid_organization_author,
    fake_valid_external_references,
    fake_valid_tlp_markings,
):
    """Test that Channel to_stix2_object method returns a valid STIX-like object."""
    channel = Channel(
        name="Test channel",
        description="Test description",
        aliases=["Test alias"],
        channel_types=["test_channel_type"],
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
    )
    stix2_obj = channel.to_stix2_object()

    assert stix2_obj == CustomObjectChannel(
        id=PyctiChannel.generate_id(name="Test channel"),
        name="Test channel",
        description="Test description",
        aliases=["Test alias"],
        channel_types=["test_channel_type"],
        created_by_ref=fake_valid_organization_author.id,
        object_marking_refs=[marking.id for marking in fake_valid_tlp_markings],
        external_references=[
            external_ref.to_stix2_object()
            for external_ref in fake_valid_external_references
        ],
        created=stix2_obj.created,
        modified=stix2_obj.modified,
    )
