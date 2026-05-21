import pytest
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.infrastructure import Infrastructure
from pycti import Infrastructure as PyctiInfrastructure
from pydantic import ValidationError
from stix2.v21 import Infrastructure as Stix2Infrastructure
from stix2.v21 import KillChainPhase


def test_infrastructure_is_a_base_identified_entity():
    """Test that Infrastructure is a BaseIdentifiedEntity."""
    assert issubclass(Infrastructure, BaseIdentifiedEntity)


def test_infrastructure_class_should_not_accept_invalid_input():
    """Test that Infrastructure class should not accept invalid input."""
    input_data = {
        "name": "Test infrastructure",
        "invalid_key": "invalid_value",
    }
    with pytest.raises(ValidationError):
        Infrastructure.model_validate(input_data)


def test_infrastructure_to_stix2_object_returns_valid_stix_object(
    fake_valid_organization_author,
    fake_valid_external_references,
    fake_valid_tlp_markings,
):
    """Test that Infrastructure to_stix2_object method returns a valid STIX2.1 Infrastructure."""
    infrastructure = Infrastructure(
        name="Test infrastructure",
        description="Test description",
        aliases=["Test alias"],
        infrastructure_types=["command-and-control"],
        first_seen="2023-01-01T00:00:00Z",
        last_seen="2024-01-01T00:00:00Z",
        kill_chain_phases=[
            {
                "chain_name": "lockheed-martin-cyber-kill-chain",
                "phase_name": "actions-on-objectives",
            }
        ],
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
    )
    stix2_obj = infrastructure.to_stix2_object()

    assert stix2_obj == Stix2Infrastructure(
        id=PyctiInfrastructure.generate_id(name="Test infrastructure"),
        name="Test infrastructure",
        description="Test description",
        aliases=["Test alias"],
        infrastructure_types=["command-and-control"],
        first_seen="2023-01-01T00:00:00Z",
        last_seen="2024-01-01T00:00:00Z",
        kill_chain_phases=[
            KillChainPhase(
                kill_chain_name="lockheed-martin-cyber-kill-chain",
                phase_name="actions-on-objectives",
            )
        ],
        created_by_ref=fake_valid_organization_author.id,
        object_marking_refs=[marking.id for marking in fake_valid_tlp_markings],
        external_references=[
            external_ref.to_stix2_object()
            for external_ref in fake_valid_external_references
        ],
        created=stix2_obj.created,
        modified=stix2_obj.modified,
    )
