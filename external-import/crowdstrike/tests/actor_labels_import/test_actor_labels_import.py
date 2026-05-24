"""Tests for actor motivation values and actor_type surfaced as IntrusionSet labels."""

import json
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from crowdstrike_feeds_connector.actor.builder import ActorBundleBuilder
from crowdstrike_feeds_connector.related_actors.builder import RelatedActorBundleBuilder
from stix2 import TLP_AMBER, Identity, IntrusionSet, MarkingDefinition

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
        "CONNECTOR_LOG_LEVEL": "info",
    }


# =====================
# Helper
# =====================


def _build_intrusion_set(
    actor_data: dict[str, Any],
    author: Identity,
    tlp_marking: MarkingDefinition,
) -> IntrusionSet:
    """Build a single IntrusionSet via ActorBundleBuilder and return it."""
    builder = ActorBundleBuilder(
        actor=actor_data,
        author=author,
        source_name="CrowdStrike",
        object_markings=[tlp_marking],
        confidence_level=75,
    )
    bundle = builder.build()
    intrusion_sets = [obj for obj in bundle.objects if isinstance(obj, IntrusionSet)]
    assert len(intrusion_sets) == 1, "Expected exactly one IntrusionSet in bundle"
    return intrusion_sets[0]


def _build_related_intrusion_set(
    actor_data: dict[str, Any],
    author: Identity,
    tlp_marking: MarkingDefinition,
) -> IntrusionSet:
    """Build a single IntrusionSet via RelatedActorBundleBuilder and return it."""
    builder = RelatedActorBundleBuilder(
        actor=actor_data,
        author=author,
        source_name="CrowdStrike",
        object_markings=[tlp_marking],
        confidence_level=75,
    )
    results = builder.build()
    assert (
        len(results) == 1
    ), "Expected exactly one IntrusionSet from RelatedActorBundleBuilder"
    return results[0]


# =====================
# ActorBundleBuilder tests
# =====================


def test_actor_builder_motivations_appear_as_labels(
    fake_actor_data: dict,
    author_identity: Identity,
    tlp_marking: MarkingDefinition,
) -> None:
    """
    Feature: Actor Motivation Labels
      As a Threat Intel Analyst
      I want motivation values surfaced as labels on IntrusionSet
      So that I can filter and identify actors by motivation without opening detail view

    Scenario: Motivation values appear as labels on IntrusionSet
    """
    actor = dict(fake_actor_data)
    actor["motivations"] = [
        {"id": 1, "slug": "criminal", "value": "Criminal"},
        {"id": 2, "slug": "espionage", "value": "Espionage"},
    ]
    actor["actor_type"] = None  # isolate motivations test

    intrusion_set = _build_intrusion_set(actor, author_identity, tlp_marking)

    labels = intrusion_set.get("labels") or []
    assert "Criminal" in labels
    assert "Espionage" in labels


def test_actor_builder_actor_type_appears_as_label(
    fake_actor_data: dict,
    author_identity: Identity,
    tlp_marking: MarkingDefinition,
) -> None:
    """
    Scenario: Actor type appears as a label on IntrusionSet
    """
    actor = dict(fake_actor_data)
    actor["motivations"] = []
    actor["actor_type"] = "Nation State"

    intrusion_set = _build_intrusion_set(actor, author_identity, tlp_marking)

    labels = intrusion_set.get("labels") or []
    assert "Nation State" in labels


def test_actor_builder_motivations_and_actor_type_combined(
    fake_actor_data: dict,
    author_identity: Identity,
    tlp_marking: MarkingDefinition,
) -> None:
    """
    Scenario: Both motivations and actor_type appear together as labels
    """
    actor = dict(fake_actor_data)
    actor["motivations"] = [
        {"id": 1, "slug": "criminal", "value": "Criminal"},
        {"id": 2, "slug": "espionage", "value": "Espionage"},
    ]
    actor["actor_type"] = "Nation State"

    intrusion_set = _build_intrusion_set(actor, author_identity, tlp_marking)

    labels = intrusion_set.get("labels") or []
    assert "Criminal" in labels
    assert "Espionage" in labels
    assert "Nation State" in labels


def test_actor_builder_raw_motivation_values_not_stix_mapped(
    fake_actor_data: dict,
    author_identity: Identity,
    tlp_marking: MarkingDefinition,
) -> None:
    """
    Scenario: Labels use raw CrowdStrike values, not STIX-mapped values
    The STIX motivation mapping (e.g. 'personal-gain') should NOT appear in labels.
    """
    actor = dict(fake_actor_data)
    actor["motivations"] = [
        {"id": 1, "slug": "criminal", "value": "Criminal"},
    ]
    actor["actor_type"] = None

    intrusion_set = _build_intrusion_set(actor, author_identity, tlp_marking)

    labels = intrusion_set.get("labels") or []
    assert "Criminal" in labels
    # STIX mapped value should NOT be used as label
    assert "personal-gain" not in labels


def test_actor_builder_stix_motivation_mapping_unaffected(
    fake_actor_data: dict,
    author_identity: Identity,
    tlp_marking: MarkingDefinition,
) -> None:
    """
    Scenario: Existing STIX motivation mapping is preserved
    Labels are additive — primary_motivation/secondary_motivations must still be set.
    """
    actor = dict(fake_actor_data)
    actor["motivations"] = [
        {"id": 1, "slug": "criminal", "value": "Criminal"},
        {"id": 2, "slug": "espionage", "value": "Espionage"},
    ]
    actor["actor_type"] = None

    intrusion_set = _build_intrusion_set(actor, author_identity, tlp_marking)

    assert intrusion_set.primary_motivation == "personal-gain"
    assert "organizational-gain" in (intrusion_set.secondary_motivations or [])


def test_actor_builder_null_motivations_handled_gracefully(
    fake_actor_data: dict,
    author_identity: Identity,
    tlp_marking: MarkingDefinition,
) -> None:
    """
    Scenario: Null/missing motivations and actor_type do not cause errors
    """
    actor = dict(fake_actor_data)
    actor["motivations"] = None
    actor["actor_type"] = None

    # Should not raise
    intrusion_set = _build_intrusion_set(actor, author_identity, tlp_marking)

    labels = intrusion_set.get("labels")
    assert labels is None or labels == []


def test_actor_builder_empty_motivation_values_skipped(
    fake_actor_data: dict,
    author_identity: Identity,
    tlp_marking: MarkingDefinition,
) -> None:
    """
    Scenario: Empty string motivation values are filtered out
    """
    actor = dict(fake_actor_data)
    actor["motivations"] = [
        {"id": 1, "slug": "criminal", "value": ""},
        {"id": 2, "slug": "espionage", "value": "Espionage"},
    ]
    actor["actor_type"] = ""

    intrusion_set = _build_intrusion_set(actor, author_identity, tlp_marking)

    labels = intrusion_set.get("labels") or []
    assert "Espionage" in labels
    assert "" not in labels


# =====================
# RelatedActorBundleBuilder tests
# =====================


def test_related_actor_builder_motivations_appear_as_labels(
    author_identity: Identity,
    tlp_marking: MarkingDefinition,
) -> None:
    """
    Scenario: RelatedActorBundleBuilder surfaces motivation values as labels
    """
    actor = {
        "id": "1234",
        "name": "TEST ACTOR",
        "motivations": [
            {"id": 1, "slug": "criminal", "value": "Criminal"},
            {"id": 2, "slug": "espionage", "value": "Espionage"},
        ],
        "actor_type": None,
        "url": "https://falcon.crowdstrike.com/actor/test-actor",
    }

    intrusion_set = _build_related_intrusion_set(actor, author_identity, tlp_marking)

    labels = intrusion_set.get("labels") or []
    assert "Criminal" in labels
    assert "Espionage" in labels


def test_related_actor_builder_actor_type_appears_as_label(
    author_identity: Identity,
    tlp_marking: MarkingDefinition,
) -> None:
    """
    Scenario: RelatedActorBundleBuilder surfaces actor_type as a label
    """
    actor = {
        "id": "1234",
        "name": "TEST ACTOR",
        "motivations": [],
        "actor_type": "eCrime",
        "url": "https://falcon.crowdstrike.com/actor/test-actor",
    }

    intrusion_set = _build_related_intrusion_set(actor, author_identity, tlp_marking)

    labels = intrusion_set.get("labels") or []
    assert "eCrime" in labels


def test_related_actor_builder_null_motivations_handled_gracefully(
    author_identity: Identity,
    tlp_marking: MarkingDefinition,
) -> None:
    """
    Scenario: Null/missing motivations and actor_type in RelatedActorBundleBuilder don't error
    """
    actor = {
        "id": "1234",
        "name": "TEST ACTOR",
        "motivations": None,
        "actor_type": None,
        "url": "https://falcon.crowdstrike.com/actor/test-actor",
    }

    intrusion_set = _build_related_intrusion_set(actor, author_identity, tlp_marking)

    labels = intrusion_set.get("labels")
    assert labels is None or labels == []


def test_related_actor_builder_raw_values_not_stix_mapped(
    author_identity: Identity,
    tlp_marking: MarkingDefinition,
) -> None:
    """
    Scenario: RelatedActorBundleBuilder uses raw CrowdStrike motivation values as labels
    """
    actor = {
        "id": "1234",
        "name": "TEST ACTOR",
        "motivations": [
            {"id": 1, "slug": "state-sponsored", "value": "State-Sponsored"},
        ],
        "actor_type": "Nation State",
        "url": "https://falcon.crowdstrike.com/actor/test-actor",
    }

    intrusion_set = _build_related_intrusion_set(actor, author_identity, tlp_marking)

    labels = intrusion_set.get("labels") or []
    assert "State-Sponsored" in labels
    assert "Nation State" in labels
    # STIX mapped values should NOT appear as labels
    assert "geopolitical" not in labels
