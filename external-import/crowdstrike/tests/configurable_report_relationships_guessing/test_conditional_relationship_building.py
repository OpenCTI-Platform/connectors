"""Module to test conditional relationship building based on configuration."""

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


@pytest.fixture
def minimal_crowdstrike_config_without_guessing_param() -> dict[str, str]:
    """Fixture for minimal CrowdStrike configuration without report_guess_relations parameter."""
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


# Scenario: Build report without guessed relationships
@pytest.mark.order(2)
def test_build_report_without_guessed_relationships(
    crowdstrike_config_with_guessing_disabled: dict[str, str],
    fake_report_data: dict,
    author_identity: Identity,
    tlp_marking: MarkingDefinition,
    mock_related_indicators: list,
) -> None:
    """
    Feature: Conditional Relationship Building
      As the System
      I want to respect the relationship guessing configuration
      Because the Admin needs control over data quality for Threat Intel Analysts

    Scenario: Build report without guessed relationships
    """
    # Given the Admin has configured report_guess_relations as False
    mock_env, config = _given_admin_has_configured_report_guess_relations_as_false(
        crowdstrike_config_with_guessing_disabled
    )

    try:
        # When the System processes report data from the Crowdstrike API
        bundle = _when_system_processes_report_data(
            config=config,
            report_data=fake_report_data,
            author=author_identity,
            tlp_marking=tlp_marking,
            related_indicators=mock_related_indicators,
        )

        # Then the System only creates entity objects without inter-entity relationships
        _then_system_only_creates_entity_objects_without_relationships(bundle)

        # And the Threat Intel Analyst receives clean data without noise
        _then_analyst_receives_clean_data_without_noise(bundle)
    finally:
        mock_env.stop()


# Scenario: Build report with guessed relationships
@pytest.mark.order(2)
def test_build_report_with_guessed_relationships(
    crowdstrike_config_with_guessing_enabled: dict[str, str],
    fake_report_data: dict,
    author_identity: Identity,
    tlp_marking: MarkingDefinition,
    mock_related_indicators: list,
) -> None:
    """
    Feature: Conditional Relationship Building
      As the System
      I want to respect the relationship guessing configuration
      Because the Admin needs control over data quality for Threat Intel Analysts

    Scenario: Build report with guessed relationships
    """
    # Given the Admin has configured report_guess_relations as True
    mock_env, config = _given_admin_has_configured_report_guess_relations_as_true(
        crowdstrike_config_with_guessing_enabled
    )

    try:
        # When the System processes report data from the Crowdstrike API
        bundle = _when_system_processes_report_data(
            config=config,
            report_data=fake_report_data,
            author=author_identity,
            tlp_marking=tlp_marking,
            related_indicators=mock_related_indicators,
        )

        # Then the System creates both entities and their inter-relationships
        _then_system_creates_both_entities_and_relationships(bundle)

        # And the Threat Intel Analyst receives comprehensive relationship data
        _then_analyst_receives_comprehensive_relationship_data(bundle)
    finally:
        mock_env.stop()


# Scenario: Verify backward compatibility
@pytest.mark.order(2)
def test_backward_compatibility_for_existing_deployments(
    minimal_crowdstrike_config_without_guessing_param: dict[str, str],
    fake_report_data: dict,
    author_identity: Identity,
    tlp_marking: MarkingDefinition,
    mock_related_indicators: list,
) -> None:
    """
    Feature: Conditional Relationship Building
      As the System
      I want to respect the relationship guessing configuration
      Because the Admin needs control over data quality for Threat Intel Analysts

    Scenario: Verify backward compatibility
    """
    # Given an existing deployment without the new configuration parameter
    mock_env, config = _given_existing_deployment_without_new_configuration_parameter(
        minimal_crowdstrike_config_without_guessing_param
    )

    try:
        # When the System builds a report using the configuration
        bundle = _when_system_builds_report_with_config(
            config=config,
            report_data=fake_report_data,
            author=author_identity,
            tlp_marking=tlp_marking,
            related_indicators=mock_related_indicators,
        )

        # Then the System should default to not guessing relationships
        _then_system_should_default_to_not_creating_guessed_relationships(bundle)
    finally:
        mock_env.stop()


# =====================
# GWT Gherkin-style functions
# =====================


def _given_admin_has_configured_report_guess_relations_as_false(
    config_data: dict[str, str],
) -> tuple[Any, ConfigLoader]:
    """Given the Admin has configured report_guess_relations as False."""
    mock_env = mock_env_vars(os_environ, config_data)
    config = ConfigLoader()

    assert not config.crowdstrike.report_guess_relations  # noqa: S101

    return mock_env, config


def _given_admin_has_configured_report_guess_relations_as_true(
    config_data: dict[str, str],
) -> tuple[Any, ConfigLoader]:
    """Given the Admin has configured report_guess_relations as True."""
    mock_env = mock_env_vars(os_environ, config_data)
    config = ConfigLoader()

    assert config.crowdstrike.report_guess_relations  # noqa: S101

    return mock_env, config


def _given_existing_deployment_without_new_configuration_parameter(
    config_data: dict[str, str],
) -> tuple[Any, ConfigLoader]:
    """Given an existing deployment without the new configuration parameter."""
    mock_env = mock_env_vars(os_environ, config_data)
    config = ConfigLoader()

    # Verify the config defaults to False when not specified
    assert hasattr(config.crowdstrike, "report_guess_relations")  # noqa: S101
    assert not config.crowdstrike.report_guess_relations  # noqa: S101

    return mock_env, config


def _when_system_processes_report_data(
    config: ConfigLoader,
    report_data: dict,
    author: Identity,
    tlp_marking: MarkingDefinition,
    related_indicators: list,
) -> Bundle:
    """When the System processes report data from the Crowdstrike API."""
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


def _when_system_builds_report_with_config(
    config: ConfigLoader,
    report_data: dict,
    author: Identity,
    tlp_marking: MarkingDefinition,
    related_indicators: list,
) -> Bundle:
    """When the System builds a report with the configuration."""
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


def _then_system_only_creates_entity_objects_without_relationships(
    bundle: Bundle,
) -> None:
    """Then the System only creates entity objects without inter-entity relationships."""
    relationships = []
    entities = []
    reports = []

    for obj in bundle.objects:
        if hasattr(obj, "type"):
            if obj.type == "relationship":
                relationships.append(obj)
            elif obj.type == "report":
                reports.append(obj)
            elif obj.type not in ["marking-definition", "identity"]:
                entities.append(obj)

    assert len(entities) > 0  # noqa: S101

    guessed_rel_types = ["uses", "targets"]
    guessed_relationships = [
        r
        for r in relationships
        if hasattr(r, "relationship_type") and r.relationship_type in guessed_rel_types
    ]

    assert len(guessed_relationships) == 0  # noqa: S101

    if reports:
        report = reports[0]
        if hasattr(report, "object_refs"):
            relationship_ids = {r.id for r in relationships if hasattr(r, "id")}
            refs_that_are_relationships = [
                ref for ref in report.object_refs if ref in relationship_ids
            ]
            assert len(refs_that_are_relationships) == 0  # noqa: S101


def _then_analyst_receives_clean_data_without_noise(bundle: Bundle) -> None:
    """And the Threat Intel Analyst receives clean data without noise."""
    entities = [
        obj
        for obj in bundle.objects
        if hasattr(obj, "type")
        and obj.type not in ["relationship", "report", "marking-definition", "identity"]
    ]

    entity_types = set()
    for entity in entities:
        if hasattr(entity, "type"):
            entity_types.add(entity.type)

    expected_types = {"intrusion-set", "malware", "location"}

    assert len(entity_types.intersection(expected_types)) > 0  # noqa: S101


def _then_system_creates_both_entities_and_relationships(bundle: Bundle) -> None:
    """Then the System creates both entities and their inter-relationships."""
    relationships = []
    entities = []

    for obj in bundle.objects:
        if hasattr(obj, "type"):
            if obj.type == "relationship":
                relationships.append(obj)
            elif obj.type not in ["report", "marking-definition", "identity"]:
                entities.append(obj)

    assert len(entities) > 0  # noqa: S101
    assert len(relationships) > 0  # noqa: S101

    relationship_types = set()
    for rel in relationships:
        if hasattr(rel, "relationship_type"):
            relationship_types.add(rel.relationship_type)

    assert "uses" in relationship_types or "targets" in relationship_types  # noqa: S101


def _then_analyst_receives_comprehensive_relationship_data(bundle: Bundle) -> None:
    """And the Threat Intel Analyst receives comprehensive relationship data."""
    relationships = [
        obj
        for obj in bundle.objects
        if hasattr(obj, "type") and obj.type == "relationship"
    ]

    rel_by_type = {}
    for rel in relationships:
        if hasattr(rel, "relationship_type"):
            rel_type = rel.relationship_type
            rel_by_type[rel_type] = rel_by_type.get(rel_type, 0) + 1

    assert len(rel_by_type) >= 1  # noqa: S101

    reports = [
        obj for obj in bundle.objects if hasattr(obj, "type") and obj.type == "report"
    ]

    if reports:
        report = reports[0]
        if hasattr(report, "object_refs"):
            assert len(report.object_refs) > len(relationships)  # noqa: S101


def _then_system_should_default_to_not_creating_guessed_relationships(
    bundle: Bundle,
) -> None:
    """Then the System should default to not creating guessed relationships."""
    # Count relationship types
    relationships = [
        obj
        for obj in bundle.objects
        if hasattr(obj, "type") and obj.type == "relationship"
    ]

    # Should have no guessed relationships (uses, targets)
    guessed_rel_types = ["uses", "targets"]
    guessed_relationships = [
        r
        for r in relationships
        if hasattr(r, "relationship_type") and r.relationship_type in guessed_rel_types
    ]

    # Default behavior should not create guessed relationships
    assert len(guessed_relationships) == 0  # noqa: S101
