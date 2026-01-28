"""Module to test the indicator kill chain isolation feature end-to-end."""

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


# Scenario: Ingest indicators without propagating kill chains to related malware
@pytest.mark.order(0)
def test_ingest_indicators_without_propagating_kill_chains_to_malware(
    crowdstrike_config_standard: dict[str, str],
    fake_indicator_data: dict,
    author_identity: Identity,
    tlp_marking: MarkingDefinition,
    mock_helper: MagicMock,
) -> None:
    """
    Feature: Disable Kill Chain Propagation from Indicators to related Malware
      As a Threat Intel Analyst
      I want to ensure that kill chains from indicators are not propagated to related malware objects
      Because kill chains should only be associated with indicators and not with associated malware

    Scenario: Ingest indicators without propagating kill chains to related malware
    """
    # Given an indicator with associated kill chains
    mock_env, config, indicator_with_kill_chains = (
        _given_indicator_with_associated_kill_chains(
            crowdstrike_config_standard, fake_indicator_data
        )
    )

    try:
        # When the indicator is ingested into the system
        bundle = _when_indicator_is_ingested(
            config=config,
            indicator_data=indicator_with_kill_chains,
            author=author_identity,
            tlp_marking=tlp_marking,
            helper=mock_helper,
        )

        # Then the kill chains should be associated only with the indicator
        _then_kill_chains_associated_only_with_indicator(
            bundle, indicator_with_kill_chains
        )

        # And the related malware objects should not have any kill chains associated with them
        _then_malware_objects_have_no_kill_chains(bundle, indicator_with_kill_chains)
    finally:
        mock_env.stop()


# =====================
# GWT Gherkin-style functions
# =====================


def _given_indicator_with_associated_kill_chains(
    config_data: dict[str, str], indicator_data: dict
) -> tuple[Any, ConfigLoader, dict]:
    """Given an indicator with associated kill chains."""
    mock_env = mock_env_vars(os_environ, config_data)
    config = ConfigLoader()

    assert "kill_chains" in indicator_data  # noqa: S101
    assert len(indicator_data["kill_chains"]) > 0  # noqa: S101
    assert "malware_families" in indicator_data  # noqa: S101
    assert len(indicator_data["malware_families"]) > 0  # noqa: S101

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
    )

    builder = IndicatorBundleBuilder(helper=helper, config=builder_config)
    result = builder.build()

    if result is None:
        raise ValueError("Builder returned None instead of a result")

    return result["indicator_bundle"]


def _then_kill_chains_associated_only_with_indicator(
    bundle: Bundle, indicator_data: dict
) -> None:
    """Then the kill chains should be associated only with the indicator."""
    indicator_objects = [
        obj
        for obj in bundle.objects
        if hasattr(obj, "type") and obj.type == "indicator"
    ]

    assert len(indicator_objects) > 0  # noqa: S101

    for indicator in indicator_objects:
        if hasattr(indicator, "kill_chain_phases"):
            assert len(indicator.kill_chain_phases) > 0  # noqa: S101

            kill_chain_names = [kc.phase_name for kc in indicator.kill_chain_phases]

            for cs_kill_chain in indicator_data["kill_chains"]:
                expected_phase = _map_crowdstrike_kill_chain_to_lockheed_martin(
                    cs_kill_chain
                )
                assert expected_phase in kill_chain_names  # noqa: S101


def _then_malware_objects_have_no_kill_chains(
    bundle: Bundle, indicator_data: dict
) -> None:
    """And the related malware objects should not have any kill chains associated with them."""
    malware_objects = [
        obj for obj in bundle.objects if hasattr(obj, "type") and obj.type == "malware"
    ]

    malware_families = indicator_data.get("malware_families", [])
    assert len(malware_objects) == len(malware_families)  # noqa: S101

    for malware in malware_objects:
        if hasattr(malware, "kill_chain_phases"):
            assert (
                malware.kill_chain_phases is None or len(malware.kill_chain_phases) == 0
            )  # noqa: S101
        else:
            assert not hasattr(malware, "kill_chain_phases")  # noqa: S101


def _map_crowdstrike_kill_chain_to_lockheed_martin(cs_kill_chain: str) -> str:
    """Map CrowdStrike kill chain to Lockheed Martin Cyber Kill Chain."""
    mapping = {
        "Reconnaissance": "reconnaissance",
        "Weaponization": "weaponization",
        "Delivery": "delivery",
        "Exploitation": "exploitation",
        "Installation": "installation",
        "C2": "command-and-control",
        "ActionOnObjectives": "action-on-objectives",
    }
    return mapping.get(cs_kill_chain, cs_kill_chain.lower())
