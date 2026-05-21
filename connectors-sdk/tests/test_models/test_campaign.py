import pytest
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.campaign import Campaign
from pycti import Campaign as PyctiCampaign
from pydantic import ValidationError
from stix2.v21 import Campaign as Stix2Campaign


def test_campaign_is_a_base_identified_entity():
    """Test that Campaign is a BaseIdentifiedEntity."""
    assert issubclass(Campaign, BaseIdentifiedEntity)


def test_campaign_class_should_not_accept_invalid_input():
    """Test that Campaign class should not accept invalid input."""
    input_data = {
        "name": "Test campaign",
        "invalid_key": "invalid_value",
    }
    with pytest.raises(ValidationError):
        Campaign.model_validate(input_data)


def test_campaign_to_stix2_object_returns_valid_stix_object(
    fake_valid_organization_author,
    fake_valid_external_references,
    fake_valid_tlp_markings,
):
    """Test that Campaign to_stix2_object method returns a valid STIX2.1 Campaign."""
    campaign = Campaign(
        name="Test campaign",
        description="Test description",
        aliases=["Test alias"],
        first_seen="2023-01-01T00:00:00Z",
        last_seen="2024-01-01T00:00:00Z",
        objective="Test objective",
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
    )
    stix2_obj = campaign.to_stix2_object()

    assert stix2_obj == Stix2Campaign(
        id=PyctiCampaign.generate_id(name="Test campaign"),
        name="Test campaign",
        description="Test description",
        aliases=["Test alias"],
        first_seen="2023-01-01T00:00:00Z",
        last_seen="2024-01-01T00:00:00Z",
        objective="Test objective",
        created_by_ref=fake_valid_organization_author.id,
        object_marking_refs=[marking.id for marking in fake_valid_tlp_markings],
        external_references=[
            external_ref.to_stix2_object()
            for external_ref in fake_valid_external_references
        ],
        created=stix2_obj.created,
        modified=stix2_obj.modified,
    )
