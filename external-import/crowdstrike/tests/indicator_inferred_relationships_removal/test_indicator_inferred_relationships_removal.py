"""Module to test the indicator inferred relationships removal feature end-to-end."""

import json
from os import environ as os_environ
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from conftest import mock_env_vars
from crowdstrike_feeds_connector.indicator.builder import (
    IndicatorBundleBuilder,
    IndicatorBundleBuilderConfig,
)
from models.configs.config_loader import ConfigLoader
from stix2 import TLP_AMBER, Bundle, Identity, MarkingDefinition

# =====================
# Fixtures
# =====================


@pytest.fixture
def fake_indicator_data() -> dict:
    """Load fake indicator data from JSON file."""
    faker_dir = Path(__file__).parent.parent / "faker"
    with open(faker_dir / "api_indicator.json", "r") as f:
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
def mock_helper() -> MagicMock:
    """Fixture for mock OpenCTI helper."""
    helper = MagicMock()
    helper.connector_logger.info = MagicMock()
    helper.connector_logger.error = MagicMock()
    helper.connector_logger.warning = MagicMock()
    helper.connector_logger.debug = MagicMock()
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


# Scenario: Ingest indicators with associated actors should not create inferred uses relationships with associated malware
@pytest.mark.order(1)
def test_no_inferred_uses_relationships_between_actors_and_malware(
    crowdstrike_config_standard: dict[str, str],
    fake_indicator_data: dict,
    author_identity: Identity,
    tlp_marking: MarkingDefinition,
    mock_helper: MagicMock,
) -> None:
    """
    Feature: Remove Inferred Relationships from Indicator Associations
      As a Threat Intel Analyst
      I want to have only verified relationships from CrowdStrike's database
      Because inferred relationships can lead to misinformation and inaccuracies in threat intelligence

    Scenario: Ingest indicators with associated actors should not create inferred uses relationships with associated malware
    """
    # Given an indicator with associated threat actors and malware
    mock_env, config, indicator_data = _given_indicator_with_actors_and_malware_sectors(
        crowdstrike_config_standard, fake_indicator_data
    )

    try:
        # When the indicator is ingested into the system
        bundle = _when_indicator_is_ingested(
            config=config,
            indicator_data=indicator_data,
            author=author_identity,
            tlp_marking=tlp_marking,
            helper=mock_helper,
        )

        # Then no inferred uses relationships should be created between the actor and the associated malware
        _then_no_uses_relationships_between_actors_and_malware(bundle)
    finally:
        mock_env.stop()


# Scenario: Ingest indicators with associated actors should not create inferred targets relationships with associated Sector
@pytest.mark.order(1)
def test_no_inferred_targets_relationships_between_actors_and_sectors(
    crowdstrike_config_standard: dict[str, str],
    fake_indicator_data: dict,
    author_identity: Identity,
    tlp_marking: MarkingDefinition,
    mock_helper: MagicMock,
) -> None:
    """
    Feature: Remove Inferred Relationships from Indicator Associations
      As a Threat Intel Analyst
      I want to have only verified relationships from CrowdStrike's database
      Because inferred relationships can lead to misinformation and inaccuracies in threat intelligence

    Scenario: Ingest indicators with associated actors should not create inferred targets relationships with associated Sector
    """
    # Given an indicator with associated threat actors and sectors
    mock_env, config, indicator_data = _given_indicator_with_actors_and_malware_sectors(
        crowdstrike_config_standard, fake_indicator_data
    )

    try:
        # When the indicator is ingested into the system
        bundle = _when_indicator_is_ingested(
            config=config,
            indicator_data=indicator_data,
            author=author_identity,
            tlp_marking=tlp_marking,
            helper=mock_helper,
        )

        # Then no inferred targets relationships should be created between the indicator and the associated sectors
        _then_no_targets_relationships_between_actors_and_sectors(bundle)
    finally:
        mock_env.stop()


# Scenario: Ingest indicators with associated malware should not create inferred targets relationships with associated Sector
@pytest.mark.order(1)
def test_no_inferred_targets_relationships_between_malware_and_sectors(
    crowdstrike_config_standard: dict[str, str],
    fake_indicator_data: dict,
    author_identity: Identity,
    tlp_marking: MarkingDefinition,
    mock_helper: MagicMock,
) -> None:
    """
    Feature: Remove Inferred Relationships from Indicator Associations
      As a Threat Intel Analyst
      I want to have only verified relationships from CrowdStrike's database
      Because inferred relationships can lead to misinformation and inaccuracies in threat intelligence

    Scenario: Ingest indicators with associated malware should not create inferred targets relationships with associated Sector
    """
    # Given an indicator with associated malware and sectors
    mock_env, config, indicator_data = _given_indicator_with_actors_and_malware_sectors(
        crowdstrike_config_standard, fake_indicator_data
    )

    try:
        # When the indicator is ingested into the system
        bundle = _when_indicator_is_ingested(
            config=config,
            indicator_data=indicator_data,
            author=author_identity,
            tlp_marking=tlp_marking,
            helper=mock_helper,
        )

        # Then no inferred targets relationships should be created between the malware and the associated sectors
        _then_no_targets_relationships_between_malware_and_sectors(bundle)
    finally:
        mock_env.stop()


# Scenario: Ingest indicators with associated actors should not create inferred targets relationships with associated vulnerabilities
@pytest.mark.order(1)
def test_no_inferred_targets_relationships_between_actors_and_vulnerabilities(
    crowdstrike_config_standard: dict[str, str],
    fake_indicator_data: dict,
    author_identity: Identity,
    tlp_marking: MarkingDefinition,
    mock_helper: MagicMock,
) -> None:
    """
    Feature: Remove Inferred Relationships from Indicator Associations
      As a Threat Intel Analyst
      I want to have only verified relationships from CrowdStrike's database
      Because inferred relationships can lead to misinformation and inaccuracies in threat intelligence

    Scenario: Ingest indicators with associated actors should not create inferred targets relationships with associated vulnerabilities
    """
    # Given an indicator with associated threat actors and vulnerabilities
    mock_env, config, indicator_data = _given_indicator_with_actors_and_vulnerabilities(
        crowdstrike_config_standard, fake_indicator_data
    )

    try:
        # When the indicator is ingested into the system
        bundle = _when_indicator_is_ingested(
            config=config,
            indicator_data=indicator_data,
            author=author_identity,
            tlp_marking=tlp_marking,
            helper=mock_helper,
        )

        # Then no inferred targets relationships should be created between the actor and the associated vulnerabilities
        _then_no_targets_relationships_between_actors_and_vulnerabilities(bundle)
    finally:
        mock_env.stop()


# Scenario: Ingest indicators with associated malware should not create inferred targets relationships with associated vulnerabilities
@pytest.mark.order(1)
def test_no_inferred_targets_relationships_between_malware_and_vulnerabilities(
    crowdstrike_config_standard: dict[str, str],
    fake_indicator_data: dict,
    author_identity: Identity,
    tlp_marking: MarkingDefinition,
    mock_helper: MagicMock,
) -> None:
    """
    Feature: Remove Inferred Relationships from Indicator Associations
      As a Threat Intel Analyst
      I want to have only verified relationships from CrowdStrike's database
      Because inferred relationships can lead to misinformation and inaccuracies in threat intelligence

    Scenario: Ingest indicators with associated malware should not create inferred targets relationships with associated vulnerabilities
    """
    # Given an indicator with associated malware and vulnerabilities
    mock_env, config, indicator_data = (
        _given_indicator_with_malware_and_vulnerabilities(
            crowdstrike_config_standard, fake_indicator_data
        )
    )

    try:
        # When the indicator is ingested into the system
        bundle = _when_indicator_is_ingested(
            config=config,
            indicator_data=indicator_data,
            author=author_identity,
            tlp_marking=tlp_marking,
            helper=mock_helper,
        )

        # Then no inferred targets relationships should be created between the malware and the associated vulnerabilities
        _then_no_targets_relationships_between_malware_and_vulnerabilities(bundle)
    finally:
        mock_env.stop()


# =====================
# GWT Gherkin-style functions
# =====================


def _given_indicator_with_actors_and_malware_sectors(
    config_data: dict[str, str], indicator_data: dict
) -> tuple[Any, ConfigLoader, dict]:
    """Given an indicator with associated threat actors and malware."""
    mock_env = mock_env_vars(os_environ, config_data)
    config = ConfigLoader()

    assert "actors" in indicator_data  # noqa: S101
    assert len(indicator_data["actors"]) > 0  # noqa: S101
    assert "malware_families" in indicator_data  # noqa: S101
    assert len(indicator_data["malware_families"]) > 0  # noqa: S101
    assert "targets" in indicator_data  # noqa: S101
    assert len(indicator_data["targets"]) > 0  # noqa: S101

    return mock_env, config, indicator_data


def _when_indicator_is_ingested(
    config: ConfigLoader,
    indicator_data: dict,
    author: Identity,
    tlp_marking: MarkingDefinition,
    helper: MagicMock,
) -> Bundle:
    """When the indicator is ingested into the system."""
    builder_config = IndicatorBundleBuilderConfig(
        indicator=indicator_data,
        author=author,
        source_name="CrowdStrike",
        object_markings=[tlp_marking],
        confidence_level=80,
        create_observables=True,
        create_indicators=True,
        default_x_opencti_score=50,
        indicator_low_score=40,
        indicator_low_score_labels=["low"],
        indicator_medium_score=60,
        indicator_medium_score_labels=["medium"],
        indicator_high_score=80,
        indicator_high_score_labels=["high", "Malicious"],
        indicator_unwanted_labels=[],
        scopes=["actor", "malware", "vulnerability"],
    )

    builder = IndicatorBundleBuilder(helper=helper, config=builder_config)
    result = builder.build()

    if result is None:
        raise ValueError("Builder returned None instead of a result")

    bundle = result["indicator_bundle"]
    return bundle


def _then_no_uses_relationships_between_actors_and_malware(bundle: Bundle) -> None:
    """Then no inferred uses relationships should be created between the actor and the associated malware."""
    intrusion_sets = [
        obj
        for obj in bundle.objects
        if hasattr(obj, "type") and obj.type == "intrusion-set"
    ]
    malware_objects = [
        obj for obj in bundle.objects if hasattr(obj, "type") and obj.type == "malware"
    ]
    relationship_objects = [
        obj
        for obj in bundle.objects
        if hasattr(obj, "type") and obj.type == "relationship"
    ]

    assert len(intrusion_sets) > 0  # noqa: S101
    assert len(malware_objects) > 0  # noqa: S101

    intrusion_set_ids = [actor.id for actor in intrusion_sets]
    malware_ids = [malware.id for malware in malware_objects]

    uses_relationships = [
        rel
        for rel in relationship_objects
        if hasattr(rel, "relationship_type")
        and rel.relationship_type == "uses"
        and hasattr(rel, "source_ref")
        and rel.source_ref in intrusion_set_ids
        and hasattr(rel, "target_ref")
        and rel.target_ref in malware_ids
    ]

    assert len(uses_relationships) == 0  # noqa: S101


def _then_no_targets_relationships_between_actors_and_sectors(bundle: Bundle) -> None:
    """Then no inferred targets relationships should be created between the actor and the associated sectors."""
    intrusion_sets = [
        obj
        for obj in bundle.objects
        if hasattr(obj, "type") and obj.type == "intrusion-set"
    ]
    sectors = [
        obj
        for obj in bundle.objects
        if hasattr(obj, "type")
        and obj.type == "identity"
        and hasattr(obj, "identity_class")
        and obj.identity_class == "class"
    ]
    relationship_objects = [
        obj
        for obj in bundle.objects
        if hasattr(obj, "type") and obj.type == "relationship"
    ]

    assert len(intrusion_sets) > 0  # noqa: S101
    assert len(sectors) > 0  # noqa: S101

    intrusion_set_ids = [actor.id for actor in intrusion_sets]
    sector_ids = [sector.id for sector in sectors]

    targets_relationships = [
        rel
        for rel in relationship_objects
        if hasattr(rel, "relationship_type")
        and rel.relationship_type == "targets"
        and hasattr(rel, "source_ref")
        and rel.source_ref in intrusion_set_ids
        and hasattr(rel, "target_ref")
        and rel.target_ref in sector_ids
    ]

    assert len(targets_relationships) == 0  # noqa: S101


def _given_indicator_with_actors_and_vulnerabilities(
    config_data: dict[str, str], indicator_data: dict
) -> tuple[Any, ConfigLoader, dict]:
    """Given an indicator with associated threat actors and vulnerabilities."""
    mock_env = mock_env_vars(os_environ, config_data)
    config = ConfigLoader()

    assert "actors" in indicator_data  # noqa: S101
    assert len(indicator_data["actors"]) > 0  # noqa: S101
    assert "vulnerabilities" in indicator_data  # noqa: S101
    assert len(indicator_data["vulnerabilities"]) > 0  # noqa: S101

    return mock_env, config, indicator_data


def _given_indicator_with_malware_and_vulnerabilities(
    config_data: dict[str, str], indicator_data: dict
) -> tuple[Any, ConfigLoader, dict]:
    """Given an indicator with associated malware and vulnerabilities."""
    mock_env = mock_env_vars(os_environ, config_data)
    config = ConfigLoader()

    assert "malware_families" in indicator_data  # noqa: S101
    assert len(indicator_data["malware_families"]) > 0  # noqa: S101
    assert "vulnerabilities" in indicator_data  # noqa: S101
    assert len(indicator_data["vulnerabilities"]) > 0  # noqa: S101

    return mock_env, config, indicator_data


def _then_no_targets_relationships_between_actors_and_vulnerabilities(
    bundle: Bundle,
) -> None:
    """Then no inferred targets relationships should be created between the actor and the associated vulnerabilities."""
    intrusion_sets = [
        obj
        for obj in bundle.objects
        if hasattr(obj, "type") and obj.type == "intrusion-set"
    ]
    vulnerabilities = [
        obj
        for obj in bundle.objects
        if hasattr(obj, "type") and obj.type == "vulnerability"
    ]
    relationship_objects = [
        obj
        for obj in bundle.objects
        if hasattr(obj, "type") and obj.type == "relationship"
    ]

    assert len(intrusion_sets) > 0  # noqa: S101
    assert len(vulnerabilities) > 0  # noqa: S101

    intrusion_set_ids = [actor.id for actor in intrusion_sets]
    vulnerability_ids = [vuln.id for vuln in vulnerabilities]

    targets_relationships = [
        rel
        for rel in relationship_objects
        if hasattr(rel, "relationship_type")
        and rel.relationship_type == "targets"
        and hasattr(rel, "source_ref")
        and rel.source_ref in intrusion_set_ids
        and hasattr(rel, "target_ref")
        and rel.target_ref in vulnerability_ids
    ]

    assert len(targets_relationships) == 0  # noqa: S101


def _then_no_targets_relationships_between_malware_and_vulnerabilities(
    bundle: Bundle,
) -> None:
    """Then no inferred targets relationships should be created between the malware and the associated vulnerabilities."""
    malware_objects = [
        obj for obj in bundle.objects if hasattr(obj, "type") and obj.type == "malware"
    ]
    vulnerabilities = [
        obj
        for obj in bundle.objects
        if hasattr(obj, "type") and obj.type == "vulnerability"
    ]
    relationship_objects = [
        obj
        for obj in bundle.objects
        if hasattr(obj, "type") and obj.type == "relationship"
    ]

    assert len(malware_objects) > 0  # noqa: S101
    assert len(vulnerabilities) > 0  # noqa: S101

    malware_ids = [malware.id for malware in malware_objects]
    vulnerability_ids = [vuln.id for vuln in vulnerabilities]

    targets_relationships = [
        rel
        for rel in relationship_objects
        if hasattr(rel, "relationship_type")
        and rel.relationship_type == "targets"
        and hasattr(rel, "source_ref")
        and rel.source_ref in malware_ids
        and hasattr(rel, "target_ref")
        and rel.target_ref in vulnerability_ids
    ]

    assert len(targets_relationships) == 0  # noqa: S101


def _then_no_targets_relationships_between_malware_and_sectors(bundle: Bundle) -> None:
    """Then no inferred targets relationships should be created between the malware and the associated sectors."""
    malware_objects = [
        obj for obj in bundle.objects if hasattr(obj, "type") and obj.type == "malware"
    ]
    sectors = [
        obj
        for obj in bundle.objects
        if hasattr(obj, "type")
        and obj.type == "identity"
        and hasattr(obj, "identity_class")
        and obj.identity_class == "class"
    ]
    relationship_objects = [
        obj
        for obj in bundle.objects
        if hasattr(obj, "type") and obj.type == "relationship"
    ]

    assert len(malware_objects) > 0  # noqa: S101
    assert len(sectors) > 0  # noqa: S101

    malware_ids = [malware.id for malware in malware_objects]
    sector_ids = [sector.id for sector in sectors]

    targets_relationships = [
        rel
        for rel in relationship_objects
        if hasattr(rel, "relationship_type")
        and rel.relationship_type == "targets"
        and hasattr(rel, "source_ref")
        and rel.source_ref in malware_ids
        and hasattr(rel, "target_ref")
        and rel.target_ref in sector_ids
    ]

    assert len(targets_relationships) == 0  # noqa: S101
