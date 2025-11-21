"""Module to test the threat actor TTP import feature end-to-end."""

import json
from os import environ as os_environ
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from conftest import mock_env_vars
from crowdstrike_feeds_connector.actor.builder import ActorBundleBuilder
from crowdstrike_feeds_connector.actor.importer import ActorImporter
from crowdstrike_feeds_services.client.actors import ActorsAPI
from stix2 import TLP_AMBER, Bundle, Identity, MarkingDefinition

# =====================
# Fixtures
# =====================


@pytest.fixture
def fake_actor_data() -> dict:
    """Load fake actor data from JSON file."""
    faker_dir = Path(__file__).parent.parent / "faker"
    with open(faker_dir / "api_actor.json", "r") as f:
        data = json.load(f)
        return data["body"]["resources"][0]


@pytest.fixture
def fake_mitre_attacks_data() -> dict:
    """Load fake MITRE attacks data from JSON file."""
    faker_dir = Path(__file__).parent.parent / "faker"
    with open(faker_dir / "api_mitre_attacks.json", "r") as f:
        return json.load(f)


@pytest.fixture
def author_identity() -> Identity:
    """Fixture for author identity."""
    return Identity(  # pylint: disable=W9101 # it's a test no real ingest
        name="CrowdStrike",
        identity_class="organization",
    )


@pytest.fixture
def tlp_marking() -> MarkingDefinition:
    """Fixture for TLP marking."""
    return TLP_AMBER


@pytest.fixture
def mock_helper() -> MagicMock:
    """Fixture for mock OpenCTI helper."""
    helper = MagicMock()
    helper.connector_logger.info = MagicMock()
    helper.connector_logger.error = MagicMock()
    return helper


@pytest.fixture
def crowdstrike_config_standard() -> dict[str, str]:
    """Fixture for standard CrowdStrike configuration."""
    return {
        "OPENCTI_URL": "http://localhost:8080",
        "OPENCTI_TOKEN": f"{uuid4()}",
        "CONNECTOR_ID": f"{uuid4()}",
        "CONNECTOR_NAME": "CrowdStrike Test",
        "CONNECTOR_SCOPE": "crowdstrike",
        "CROWDSTRIKE_BASE_URL": "https://api.crowdstrike.com",
        "CROWDSTRIKE_CLIENT_ID": f"{uuid4()}",
        "CROWDSTRIKE_CLIENT_SECRET": f"{uuid4()}",
    }


# =====================
# Test Cases
# =====================


# Scenario: Import TTPs for a threat actor
@pytest.mark.order(0)
def test_import_ttps_for_threat_actor(
    crowdstrike_config_standard: dict[str, str],
    fake_actor_data: dict,
    fake_mitre_attacks_data: dict,
    author_identity: Identity,
    tlp_marking: MarkingDefinition,
    mock_helper: MagicMock,
) -> None:
    """
    Feature: Threat Actor TTP Import
      As a Threat Intel Analyst
      I want to see TTPs (Tactics, Techniques, and Procedures) associated with threat actors
      Because understanding adversary behavior patterns is critical for threat detection

    Scenario: Import TTPs for a threat actor
    """
    # Given the Crowdstrike API provides TTP data for threat actors
    mock_env, actor_with_ttps, ttps_response = _given_crowdstrike_api_provides_ttp_data(
        crowdstrike_config_standard, fake_actor_data, fake_mitre_attacks_data
    )

    try:
        # When the System imports or updates a threat actor
        bundle = _when_system_imports_threat_actor(
            actor_data=actor_with_ttps,
            ttps_response=ttps_response,
            author=author_identity,
            tlp_marking=tlp_marking,
            helper=mock_helper,
        )

        # Then the System should retrieve associated TTPs via query_mitre_attacks
        _then_system_retrieves_associated_ttps(bundle, ttps_response)

        # And the Threat Intel Analyst should see IntrusionSet-uses-AttackPattern relationships
        _then_analyst_sees_intrusion_set_uses_attack_pattern_relationships(
            bundle, ttps_response
        )
    finally:
        mock_env.stop()


# Scenario: Handle actors without TTPs
@pytest.mark.order(1)
def test_handle_actors_without_ttps(
    crowdstrike_config_standard: dict[str, str],
    fake_actor_data: dict,
    author_identity: Identity,
    tlp_marking: MarkingDefinition,
    mock_helper: MagicMock,
) -> None:
    """
    Feature: Threat Actor TTP Import
      As a Threat Intel Analyst
      I want to see TTPs (Tactics, Techniques, and Procedures) associated with threat actors
      Because understanding adversary behavior patterns is critical for threat detection

    Scenario: Handle actors without TTPs
    """
    # Given the Crowdstrike API returns an actor with no TTP data
    mock_env, actor_without_ttps, empty_response = (
        _given_crowdstrike_api_returns_actor_without_ttps(
            crowdstrike_config_standard, fake_actor_data
        )
    )

    try:
        # When the System imports the actor
        bundle = _when_system_imports_actor_without_ttps(
            actor_data=actor_without_ttps,
            empty_response=empty_response,
            author=author_identity,
            tlp_marking=tlp_marking,
            helper=mock_helper,
        )

        # Then the System should create the actor without TTP relationships
        _then_system_creates_actor_without_ttp_relationships(bundle)

        # And the Threat Intel Analyst should see the actor without techniques
        _then_analyst_sees_actor_without_techniques(bundle, actor_without_ttps)
    finally:
        mock_env.stop()


# Scenario: Query MITRE attacks for actor
@pytest.mark.order(2)
def test_query_mitre_attacks_for_actor(
    crowdstrike_config_standard: dict[str, str],
    fake_mitre_attacks_data: dict,
    mock_helper: MagicMock,
) -> None:
    """
    Feature: MITRE ATT&CK API Integration
      As the System
      I want to query TTPs from the Crowdstrike API
      Because the Threat Intel Analyst needs technique information for threat actors

    Scenario: Query MITRE attacks for actor
    """
    # Given the System has a threat actor identifier
    mock_env, actor_id = _given_system_has_threat_actor_identifier(
        crowdstrike_config_standard
    )

    try:
        # When the System calls query_mitre_attacks from the Crowdstrike API
        ttps_response = _when_system_calls_query_mitre_attacks(
            actor_id=actor_id,
            expected_response=fake_mitre_attacks_data,
            helper=mock_helper,
        )

        # Then the System receives TTP data in format {actor-slug}_{tactic}_{technique}
        _then_system_receives_ttp_data_in_correct_format(ttps_response)

        # And the System can parse the technique identifiers
        _then_system_can_parse_technique_identifiers(ttps_response)
    finally:
        mock_env.stop()


# Scenario: Create AttackPattern from technique ID
@pytest.mark.order(3)
def test_create_attack_pattern_from_technique_id(
    crowdstrike_config_standard: dict[str, str],
    fake_actor_data: dict,
    fake_mitre_attacks_data: dict,
    author_identity: Identity,
    tlp_marking: MarkingDefinition,
    mock_helper: MagicMock,
) -> None:
    """
    Feature: AttackPattern Entity Creation
      As the System
      I want to create AttackPattern entities from TTP data
      Because the Threat Intel Analyst needs standardized MITRE ATT&CK techniques

    Scenario: Create AttackPattern from technique ID
    """
    # Given the Crowdstrike API returns technique IDs for an actor
    mock_env, technique_ids = _given_crowdstrike_api_returns_technique_ids(
        crowdstrike_config_standard, fake_mitre_attacks_data
    )

    try:
        # When the System processes TTP data from the API
        attack_patterns = _when_system_processes_ttp_data(
            technique_ids=technique_ids,
            actor_data=fake_actor_data,
            author=author_identity,
            tlp_marking=tlp_marking,
            helper=mock_helper,
        )

        # Then the System should create AttackPattern entities with MITRE IDs
        _then_system_creates_attack_patterns_with_mitre_ids(attack_patterns)

        # And the Threat Intel Analyst can reference standard attack techniques
        _then_analyst_can_reference_standard_attack_techniques(attack_patterns)
    finally:
        mock_env.stop()


# Scenario: Link actor to techniques
@pytest.mark.order(4)
def test_link_actor_to_techniques(
    crowdstrike_config_standard: dict[str, str],
    fake_actor_data: dict,
    fake_mitre_attacks_data: dict,
    author_identity: Identity,
    tlp_marking: MarkingDefinition,
    mock_helper: MagicMock,
) -> None:
    """
    Feature: TTP Relationship Creation
      As the System
      I want to create uses relationships between actors and techniques
      Because the Threat Intel Analyst needs to understand actor capabilities

    Scenario: Link actor to techniques
    """
    # Given the System has created IntrusionSet and AttackPattern entities
    mock_env, attack_patterns = _given_system_has_intrusion_set_and_attack_patterns(
        config_data=crowdstrike_config_standard,
        actor_data=fake_actor_data,
        ttps_response=fake_mitre_attacks_data,
        author=author_identity,
        tlp_marking=tlp_marking,
        helper=mock_helper,
    )

    try:
        # When the System builds the actor bundle
        bundle = _when_system_builds_actor_bundle(
            actor_data=fake_actor_data,
            attack_patterns=attack_patterns,
            author=author_identity,
            tlp_marking=tlp_marking,
        )

        # Then the System should create uses relationships
        _then_system_creates_uses_relationships(bundle)

        # And the Threat Intel Analyst should see which techniques the actor employs
        _then_analyst_sees_which_techniques_actor_employs(bundle, attack_patterns)
    finally:
        mock_env.stop()


# =====================
# GWT Gherkin-style functions
# =====================


def _given_crowdstrike_api_provides_ttp_data(
    config_data: dict[str, str], actor_data: dict, ttps_response: dict
) -> tuple[Any, dict, dict]:
    """Given the Crowdstrike API provides TTP data for threat actors."""
    mock_env = mock_env_vars(os_environ, config_data)

    assert "id" in actor_data  # noqa: S101
    assert "name" in actor_data  # noqa: S101
    assert "resources" in ttps_response  # noqa: S101
    assert len(ttps_response["resources"]) > 0  # noqa: S101

    return mock_env, actor_data, ttps_response


def _when_system_imports_threat_actor(
    actor_data: dict,
    ttps_response: dict,
    author: Identity,
    tlp_marking: MarkingDefinition,
    helper: MagicMock,
) -> Bundle:
    """When the System imports or updates a threat actor."""
    with patch.object(ActorsAPI, "query_mitre_attacks", return_value=ttps_response):
        importer = ActorImporter(
            helper=helper,
            author=author,
            default_latest_timestamp=0,
            tlp_marking=tlp_marking,
            indicator_config={},
        )

        attack_patterns = importer._get_and_create_attack_patterns(actor_data)

        builder = ActorBundleBuilder(
            actor=actor_data,
            author=author,
            source_name="CrowdStrike",
            object_markings=[tlp_marking],
            confidence_level=80,
            related_indicators=[],
            attack_patterns=attack_patterns,
        )

        return builder.build()


def _then_system_retrieves_associated_ttps(bundle: Bundle, ttps_response: dict) -> None:
    """Then the System should retrieve associated TTPs via query_mitre_attacks."""
    attack_patterns = [
        obj
        for obj in bundle.objects
        if hasattr(obj, "type") and obj.type == "attack-pattern"
    ]

    expected_techniques = {
        ttp.split("_")[2]
        for ttp in ttps_response["resources"]
        if len(ttp.split("_")) >= 3 and ttp.split("_")[2].startswith("T")
    }

    assert len(attack_patterns) == len(expected_techniques)  # noqa: S101


def _then_analyst_sees_intrusion_set_uses_attack_pattern_relationships(
    bundle: Bundle, ttps_response: dict
) -> None:
    """And the Threat Intel Analyst should see IntrusionSet-uses-AttackPattern relationships."""
    uses_relationships = [
        obj
        for obj in bundle.objects
        if hasattr(obj, "type")
        and obj.type == "relationship"
        and obj.relationship_type == "uses"
    ]

    expected_techniques = {
        ttp.split("_")[2]
        for ttp in ttps_response["resources"]
        if len(ttp.split("_")) >= 3 and ttp.split("_")[2].startswith("T")
    }

    assert len(uses_relationships) == len(expected_techniques)  # noqa: S101


def _given_crowdstrike_api_returns_actor_without_ttps(
    config_data: dict[str, str], actor_data: dict
) -> tuple[Any, dict, dict]:
    """Given the Crowdstrike API returns an actor with no TTP data."""
    mock_env = mock_env_vars(os_environ, config_data)
    empty_response = {"errors": [], "meta": {"powered_by": "msa-api"}, "resources": []}

    return mock_env, actor_data, empty_response


def _when_system_imports_actor_without_ttps(
    actor_data: dict,
    empty_response: dict,
    author: Identity,
    tlp_marking: MarkingDefinition,
    helper: MagicMock,
) -> Bundle:
    """When the System imports the actor."""
    with patch.object(ActorsAPI, "query_mitre_attacks", return_value=empty_response):
        importer = ActorImporter(
            helper=helper,
            author=author,
            default_latest_timestamp=0,
            tlp_marking=tlp_marking,
            indicator_config={},
        )

        attack_patterns = importer._get_and_create_attack_patterns(actor_data)

        builder = ActorBundleBuilder(
            actor=actor_data,
            author=author,
            source_name="CrowdStrike",
            object_markings=[tlp_marking],
            confidence_level=80,
            related_indicators=[],
            attack_patterns=attack_patterns,
        )

        return builder.build()


def _then_system_creates_actor_without_ttp_relationships(bundle: Bundle) -> None:
    """Then the System should create the actor without TTP relationships."""
    uses_relationships = [
        obj
        for obj in bundle.objects
        if hasattr(obj, "type")
        and obj.type == "relationship"
        and obj.relationship_type == "uses"
    ]

    assert len(uses_relationships) == 0  # noqa: S101


def _then_analyst_sees_actor_without_techniques(
    bundle: Bundle, actor_data: dict
) -> None:
    """And the Threat Intel Analyst should see the actor without techniques."""
    intrusion_sets = [
        obj
        for obj in bundle.objects
        if hasattr(obj, "type") and obj.type == "intrusion-set"
    ]

    attack_patterns = [
        obj
        for obj in bundle.objects
        if hasattr(obj, "type") and obj.type == "attack-pattern"
    ]

    assert len(intrusion_sets) == 1  # noqa: S101
    assert intrusion_sets[0].name == actor_data["name"]  # noqa: S101
    assert len(attack_patterns) == 0  # noqa: S101


def _given_system_has_threat_actor_identifier(
    config_data: dict[str, str],
) -> tuple[Any, int]:
    """Given the System has a threat actor identifier."""
    mock_env = mock_env_vars(os_environ, config_data)
    return mock_env, 123456


def _when_system_calls_query_mitre_attacks(
    actor_id: int,
    expected_response: dict,
    helper: MagicMock,
) -> dict:
    """When the System calls query_mitre_attacks from the Crowdstrike API."""
    with patch.object(ActorsAPI, "query_mitre_attacks", return_value=expected_response):
        api = ActorsAPI(helper)
        response = api.query_mitre_attacks(actor_id)

    return response


def _then_system_receives_ttp_data_in_correct_format(ttps_response: dict) -> None:
    """Then the System receives TTP data in format {actor-slug}_{tactic}_{technique}."""
    assert "resources" in ttps_response  # noqa: S101

    for ttp_id in ttps_response["resources"]:
        parts = ttp_id.split("_")
        assert len(parts) == 3  # noqa: S101
        assert parts[1].startswith("TA")  # noqa: S101
        assert parts[2].startswith("T")  # noqa: S101


def _then_system_can_parse_technique_identifiers(ttps_response: dict) -> None:
    """And the System can parse the technique identifiers."""
    technique_ids = {
        ttp.split("_")[2]
        for ttp in ttps_response["resources"]
        if len(ttp.split("_")) >= 3 and ttp.split("_")[2].startswith("T")
    }

    assert len(technique_ids) > 0  # noqa: S101
    for technique_id in technique_ids:
        assert technique_id.startswith("T")  # noqa: S101
        assert len(technique_id) >= 4  # noqa: S101


def _given_crowdstrike_api_returns_technique_ids(
    config_data: dict[str, str], mitre_attacks_data: dict
) -> tuple[Any, list]:
    """Given the Crowdstrike API returns technique IDs for an actor."""
    mock_env = mock_env_vars(os_environ, config_data)
    technique_ids = mitre_attacks_data["resources"]
    return mock_env, technique_ids


def _when_system_processes_ttp_data(
    technique_ids: list,
    actor_data: dict,
    author: Identity,
    tlp_marking: MarkingDefinition,
    helper: MagicMock,
) -> list:
    """When the System processes the TTP data."""
    with patch.object(
        ActorsAPI, "query_mitre_attacks", return_value={"resources": technique_ids}
    ):
        importer = ActorImporter(
            helper=helper,
            author=author,
            default_latest_timestamp=0,
            tlp_marking=tlp_marking,
            indicator_config={},
        )

        attack_patterns = importer._get_and_create_attack_patterns(actor_data)

    return attack_patterns


def _then_system_creates_attack_patterns_with_mitre_ids(attack_patterns: list) -> None:
    """Then the System creates AttackPattern entities with proper MITRE IDs."""
    assert len(attack_patterns) > 0  # noqa: S101

    for attack_pattern in attack_patterns:
        assert hasattr(attack_pattern, "x_mitre_id")  # noqa: S101
        assert attack_pattern.x_mitre_id.startswith("T")  # noqa: S101
        assert len(attack_pattern.x_mitre_id) >= 4  # noqa: S101

    for pattern in attack_patterns:
        assert hasattr(pattern, "name")  # noqa: S101
        assert len(pattern.name) > 0  # noqa: S101


def _then_analyst_can_reference_standard_attack_techniques(
    attack_patterns: list,
) -> None:
    """And the Threat Intel Analyst can reference standard ATT&CK techniques."""
    for pattern in attack_patterns:
        assert hasattr(pattern, "type")  # noqa: S101
        assert pattern.type == "attack-pattern"  # noqa: S101
        assert hasattr(pattern, "id")  # noqa: S101
        assert pattern.id.startswith("attack-pattern--")  # noqa: S101


def _given_system_has_intrusion_set_and_attack_patterns(
    config_data: dict[str, str],
    actor_data: dict,
    ttps_response: dict,
    author: Identity,
    tlp_marking: MarkingDefinition,
    helper: MagicMock,
) -> tuple[Any, list]:
    """Given the System has created IntrusionSet and AttackPattern entities."""
    mock_env = mock_env_vars(os_environ, config_data)

    with patch.object(ActorsAPI, "query_mitre_attacks", return_value=ttps_response):
        importer = ActorImporter(
            helper=helper,
            author=author,
            default_latest_timestamp=0,
            tlp_marking=tlp_marking,
            indicator_config={},
        )

        attack_patterns = importer._get_and_create_attack_patterns(actor_data)
        return mock_env, attack_patterns


def _when_system_builds_actor_bundle(
    actor_data: dict,
    attack_patterns: list,
    author: Identity,
    tlp_marking: MarkingDefinition,
) -> Bundle:
    """When the System builds the actor bundle."""
    builder = ActorBundleBuilder(
        actor=actor_data,
        author=author,
        source_name="CrowdStrike",
        object_markings=[tlp_marking],
        confidence_level=80,
        related_indicators=[],
        attack_patterns=attack_patterns,
    )

    return builder.build()


def _then_system_creates_uses_relationships(bundle: Bundle) -> None:
    """Then the System creates 'uses' relationships."""
    uses_relationships = [
        obj
        for obj in bundle.objects
        if hasattr(obj, "type")
        and obj.type == "relationship"
        and obj.relationship_type == "uses"
    ]

    assert len(uses_relationships) > 0  # noqa: S101


def _then_analyst_sees_which_techniques_actor_employs(
    bundle: Bundle, attack_patterns: list
) -> None:
    """And the Threat Intel Analyst sees which techniques the actor employs."""
    intrusion_sets = [
        obj
        for obj in bundle.objects
        if hasattr(obj, "type") and obj.type == "intrusion-set"
    ]

    uses_relationships = [
        obj
        for obj in bundle.objects
        if hasattr(obj, "type")
        and obj.type == "relationship"
        and obj.relationship_type == "uses"
    ]

    assert len(intrusion_sets) == 1  # noqa: S101
    intrusion_set = intrusion_sets[0]

    for relationship in uses_relationships:
        assert relationship.source_ref == intrusion_set.id  # noqa: S101
        assert "attack-pattern--" in relationship.target_ref  # noqa: S101
