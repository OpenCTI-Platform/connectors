"""Module to test the configurable report relationship guessing feature end-to-end."""

import json
from os import environ as os_environ
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from conftest import mock_env_vars
from crowdstrike_feeds_connector.report.builder import ReportBundleBuilder
from models.configs.config_loader import ConfigLoader
from stix2 import TLP_AMBER, Bundle, Identity, MarkingDefinition

# =====================
# Fixtures
# =====================


@pytest.fixture
def fake_report_data() -> dict:
    """Load fake report data from JSON file."""
    faker_dir = Path(__file__).parent.parent / "faker"
    with open(faker_dir / "api_report.json", "r") as f:
        return json.load(f)


@pytest.fixture
def author_identity() -> Identity:
    """Fixture for author identity."""
    return Identity(  # pylint: disable=W9101  # it's a test no real ingest
        name="CrowdStrike",
        identity_class="organization",
    )


@pytest.fixture
def tlp_marking() -> MarkingDefinition:
    """Fixture for TLP marking."""
    return TLP_AMBER


@pytest.fixture
def crowdstrike_config_with_guessing_disabled() -> dict[str, str]:
    """Fixture for CrowdStrike configuration with relationship guessing disabled."""
    return {
        "OPENCTI_URL": "http://localhost:8080",
        "OPENCTI_TOKEN": f"{uuid4()}",
        "CONNECTOR_ID": f"{uuid4()}",
        "CONNECTOR_NAME": "CrowdStrike Test",
        "CONNECTOR_SCOPE": "crowdstrike",
        "CROWDSTRIKE_BASE_URL": "https://api.crowdstrike.com",
        "CROWDSTRIKE_CLIENT_ID": f"{uuid4()}",
        "CROWDSTRIKE_CLIENT_SECRET": f"{uuid4()}",
        "CROWDSTRIKE_REPORT_GUESS_RELATIONS": "False",
    }


@pytest.fixture
def crowdstrike_config_with_guessing_enabled() -> dict[str, str]:
    """Fixture for CrowdStrike configuration with relationship guessing enabled."""
    return {
        "OPENCTI_URL": "http://localhost:8080",
        "OPENCTI_TOKEN": f"{uuid4()}",
        "CONNECTOR_ID": f"{uuid4()}",
        "CONNECTOR_NAME": "CrowdStrike Test",
        "CONNECTOR_SCOPE": "crowdstrike",
        "CROWDSTRIKE_BASE_URL": "https://api.crowdstrike.com",
        "CROWDSTRIKE_CLIENT_ID": f"{uuid4()}",
        "CROWDSTRIKE_CLIENT_SECRET": f"{uuid4()}",
        "CROWDSTRIKE_REPORT_GUESS_RELATIONS": "True",
    }


@pytest.fixture
def mock_related_indicators() -> list:
    """Fixture for mock related indicators."""
    return []


# =====================
# Test Cases
# =====================


# Scenario: Disable relationship guessing by default
@pytest.mark.order(0)
def test_disable_relationship_guessing_by_default(
    crowdstrike_config_with_guessing_disabled: dict[str, str],
    fake_report_data: dict,
    author_identity: Identity,
    tlp_marking: MarkingDefinition,
    mock_related_indicators: list,
) -> None:
    """
    Feature: Configurable Report Relationship Guessing
      As a Threat Intel Analyst
      I want to control whether relationships are automatically guessed in reports
      Because automatic relationship creation introduces noise and inaccurate data connections

    Scenario: Disable relationship guessing by default
    """
    # Given the Admin has set report_guess_relations to False in the configuration
    mock_env, config = _given_admin_has_set_report_guess_relations_to_false(
        crowdstrike_config_with_guessing_disabled
    )

    try:
        # When the System imports a report from the Crowdstrike API
        bundle = _when_system_imports_report_from_crowdstrike_api(
            config=config,
            report_data=fake_report_data,
            author=author_identity,
            tlp_marking=tlp_marking,
            related_indicators=mock_related_indicators,
        )

        # Then the System should not create automatic relationships between entities
        _then_system_should_not_create_automatic_relationships(bundle)

        # And the Threat Intel Analyst should only see explicit relationships from the source data
        _then_analyst_should_only_see_explicit_relationships(bundle, fake_report_data)
    finally:
        mock_env.stop()


# Scenario: Enable relationship guessing when needed
@pytest.mark.order(0)
def test_enable_relationship_guessing_when_needed(
    crowdstrike_config_with_guessing_enabled: dict[str, str],
    fake_report_data: dict,
    author_identity: Identity,
    tlp_marking: MarkingDefinition,
    mock_related_indicators: list,
) -> None:
    """
    Feature: Configurable Report Relationship Guessing
      As a Threat Intel Analyst
      I want to control whether relationships are automatically guessed in reports
      Because automatic relationship creation introduces noise and inaccurate data connections

    Scenario: Enable relationship guessing when needed
    """
    # Given the Admin has set report_guess_relations to True in the configuration
    mock_env, config = _given_admin_has_set_report_guess_relations_to_true(
        crowdstrike_config_with_guessing_enabled
    )

    try:
        # When the System imports a report from the Crowdstrike API
        bundle = _when_system_imports_report_from_crowdstrike_api(
            config=config,
            report_data=fake_report_data,
            author=author_identity,
            tlp_marking=tlp_marking,
            related_indicators=mock_related_indicators,
        )

        # Then the System should create relationships between all entities in the report
        _then_system_should_create_relationships_between_all_entities(bundle)

        # And the Threat Intel Analyst should see all guessed relationships
        _then_analyst_should_see_all_guessed_relationships(bundle, fake_report_data)
    finally:
        mock_env.stop()


# =====================
# GWT Gherkin-style functions
# =====================


def _given_admin_has_set_report_guess_relations_to_false(
    config_data: dict[str, str],
) -> tuple[Any, ConfigLoader]:
    """Given the Admin has set report_guess_relations to False in the configuration."""
    mock_env = mock_env_vars(os_environ, config_data)
    config = ConfigLoader()

    assert not config.crowdstrike.report_guess_relations  # noqa: S101

    return mock_env, config


def _given_admin_has_set_report_guess_relations_to_true(
    config_data: dict[str, str],
) -> tuple[Any, ConfigLoader]:
    """Given the Admin has set report_guess_relations to True in the configuration."""
    mock_env = mock_env_vars(os_environ, config_data)
    config = ConfigLoader()

    assert config.crowdstrike.report_guess_relations  # noqa: S101

    return mock_env, config


def _when_system_imports_report_from_crowdstrike_api(
    config: ConfigLoader,
    report_data: dict,
    author: Identity,
    tlp_marking: MarkingDefinition,
    related_indicators: list,
) -> Bundle:
    """When the System imports a report from the Crowdstrike API."""
    builder = ReportBundleBuilder(
        report=report_data,
        author=author,
        source_name="CrowdStrike",
        object_markings=[tlp_marking],
        report_status=0,
        report_type="threat-report",
        confidence_level=80,
        related_indicators=related_indicators,
        report_guess_relations=config.crowdstrike.report_guess_relations,
    )

    bundle = builder.build()

    return bundle


def _then_system_should_create_relationships_between_all_entities(
    bundle: Bundle,
) -> None:
    """Then the System should create relationships between all entities in the report."""
    relationships = [
        obj
        for obj in bundle.objects
        if hasattr(obj, "type") and obj.type == "relationship"
    ]

    assert len(relationships) > 5  # noqa: S101

    relationship_types = set()
    for rel in relationships:
        if hasattr(rel, "relationship_type"):
            relationship_types.add(rel.relationship_type)

    assert len(relationship_types) >= 1  # noqa: S101


def _then_system_should_not_create_automatic_relationships(bundle: Bundle) -> None:
    """Then the System should not create automatic relationships between entities."""
    relationships = [
        obj
        for obj in bundle.objects
        if hasattr(obj, "type") and obj.type == "relationship"
    ]

    assert len(relationships) < 10  # noqa: S101


def _then_analyst_should_only_see_explicit_relationships(
    bundle: Bundle, report_data: dict
) -> None:
    """Then the Threat Intel Analyst should only see explicit relationships from the source data."""
    entities = [
        obj
        for obj in bundle.objects
        if hasattr(obj, "type")
        and obj.type not in ["relationship", "report", "marking-definition"]
    ]

    intrusion_sets = [
        obj for obj in entities if hasattr(obj, "type") and obj.type == "intrusion-set"
    ]

    malwares = [
        obj for obj in entities if hasattr(obj, "type") and obj.type == "malware"
    ]

    assert len(intrusion_sets) > 0  # noqa: S101
    assert len(malwares) == 0  # noqa: S101

    intrusion_set_names = [getattr(obj, "name", "") for obj in intrusion_sets]

    assert "TEST BEAR" in intrusion_set_names  # noqa: S101


def _then_analyst_should_see_all_guessed_relationships(
    bundle: Bundle, report_data: dict
) -> None:
    """Then the Threat Intel Analyst should see all guessed relationships."""
    relationships = [
        obj
        for obj in bundle.objects
        if hasattr(obj, "type") and obj.type == "relationship"
    ]

    entities = [
        obj
        for obj in bundle.objects
        if hasattr(obj, "type")
        and obj.type not in ["relationship", "report", "marking-definition", "identity"]
    ]

    entity_types = {}
    for entity in entities:
        entity_type = getattr(entity, "type", "unknown")
        entity_types[entity_type] = entity_types.get(entity_type, 0) + 1

    if len(entities) > 1 and "intrusion-set" in entity_types:
        assert len(relationships) > 0  # noqa: S101

    report_objects = [
        obj for obj in bundle.objects if hasattr(obj, "type") and obj.type == "report"
    ]

    if report_objects:
        report = report_objects[0]
        if hasattr(report, "object_refs"):
            assert len(report.object_refs) > 0  # noqa: S101
