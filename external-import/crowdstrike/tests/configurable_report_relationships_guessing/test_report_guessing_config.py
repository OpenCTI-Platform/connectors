"""Module to test the CrowdStrike connector report relationship guessing configuration."""

from os import environ as os_environ
from typing import Any
from uuid import uuid4

import pytest
from conftest import mock_env_vars
from models.configs.config_loader import ConfigLoader
from models.configs.crowdstrike_configs import _ConfigLoaderCrowdstrike

# =====================
# Fixtures
# =====================


@pytest.fixture(
    params=[
        {
            "base_url": "https://api.crowdstrike.com",
            "client_id": f"{uuid4()}",
            "client_secret": f"{uuid4()}",
        },
    ]
)
def min_required_crowdstrike_config(request) -> dict[str, str]:
    """Fixture for minimum required CrowdStrike configuration."""
    return {
        "OPENCTI_URL": "http://localhost:8080",
        "OPENCTI_TOKEN": f"{uuid4()}",
        "CONNECTOR_ID": f"{uuid4()}",
        "CONNECTOR_NAME": "CrowdStrike Test",
        "CONNECTOR_SCOPE": "crowdstrike",
        "CROWDSTRIKE_BASE_URL": request.param["base_url"],
        "CROWDSTRIKE_CLIENT_ID": request.param["client_id"],
        "CROWDSTRIKE_CLIENT_SECRET": request.param["client_secret"],
    }


# =====================
# Test Cases
# =====================


# Scenario: Default configuration prevents guessing
@pytest.mark.order(1)
def test_default_configuration_prevents_guessing(
    min_required_crowdstrike_config: dict[str, str],
) -> None:
    """
    Feature: Report Guessing Configuration Option
      As an Admin
      I want to configure relationship guessing behavior
      Because different environments have different data quality requirements

    Scenario: Default configuration prevents guessing
    """
    # Given the Admin is installing the connector
    mock_env = _given_admin_is_installing_connector(min_required_crowdstrike_config)

    try:
        # When the Admin does not specify report_guess_relations configuration
        config = _when_admin_does_not_specify_report_guess_relations()

        # Then the System should default report_guess_relations to False
        _then_system_should_default_report_guess_relations_to_false(config)
    finally:
        # Cleanup - always stop mock_env even if test fails
        mock_env.stop()


# =====================
# GWT Gherkin-style functions
# =====================


def _given_admin_is_installing_connector(min_required_config: dict[str, str]) -> Any:
    """Given the Admin is installing the connector."""
    mock_env = mock_env_vars(os_environ, min_required_config)
    return mock_env


def _when_admin_does_not_specify_report_guess_relations() -> ConfigLoader:
    """When the Admin does not specify report_guess_relations configuration."""
    config = ConfigLoader()
    return config


def _then_system_should_default_report_guess_relations_to_false(
    config: ConfigLoader,
) -> None:
    """Then the System should default report_guess_relations to False."""
    assert hasattr(config.crowdstrike, "report_guess_relations")  # noqa: S101
    assert not config.crowdstrike.report_guess_relations  # noqa: S101

    field_info = _ConfigLoaderCrowdstrike.model_fields.get("report_guess_relations")
    assert field_info is not None  # noqa: S101
    assert not field_info.default  # noqa: S101
