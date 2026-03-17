import pytest
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.channel import Channel
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
        channel_types=["blog"],
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
    )
    stix2_obj = channel.to_stix2_object()
    assert stix2_obj.get("type") == "channel"
