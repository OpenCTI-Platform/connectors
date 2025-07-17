"""Offers tests for the taxonomies entities."""

from connectors_sdk.models.octi._common import BaseEntity
from connectors_sdk.models.octi.settings.taxonomies import KillChainPhase


def test_kill_chain_phase_is_a_base_entity():
    """Test that KillChainPhase is a BaseEntity."""
    # Given the KillChainPhase class
    # When checking its type
    # Then it should be a subclass of BaseEntity
    assert issubclass(KillChainPhase, BaseEntity)


def test_kill_chain_phase_has_required_fields():
    """Test that KillChainPhase has the required fields."""
    # Given the KillChainPhase class
    # When creating an instance
    phase = KillChainPhase(chain_name="foo", phase_name="pre-attack")
    # Then it should have the required fields
    assert phase.chain_name == "foo"
    assert phase.phase_name == "pre-attack"


def test_kill_chain_phase_to_stix2_object():
    """Test that KillChainPhase can be converted to a STIX2 object."""
    # Given a KillChainPhase instance
    phase = KillChainPhase(chain_name="foo", phase_name="pre-attack")
    # When converting it to a STIX2 object
    stix_object = phase.to_stix2_object()
    # Then it should be a valid STIX2 KillChainPhase object
    assert stix_object.get("kill_chain_name") == "foo"
    assert stix_object.get("phase_name") == "pre-attack"
