"""Tests for the infrastructure settings of the IOC delta feed."""

from os import environ as os_environ
from unittest.mock import patch

import pytest
from connector.src.custom.configs.indicator.gti_config_indicator import (
    GTIIndicatorConfig,
)
from connector.src.custom.exceptions.gti_configuration_error import (
    GTIConfigurationError,
)
from pydantic import ValidationError


def _load_config(env: dict[str, str]) -> GTIIndicatorConfig:
    with patch.dict(os_environ, {"GTI_API_KEY": "fake-key", **env}):
        return GTIIndicatorConfig()


def test_infrastructure_disabled_by_default() -> None:
    """No infrastructure list is imported by default, up to 10 per list when enabled."""
    # Given a configuration without infrastructure settings
    # When it is loaded
    config = _load_config({})
    # Then the feature is disabled
    assert config.indicator_infrastructure == []  # noqa: S101
    assert config.indicator_infrastructure_limit == 10  # noqa: S101


def test_infrastructure_categories() -> None:
    """Known categories are accepted."""
    # Given a list of categories
    # When the configuration is loaded
    config = _load_config({"GTI_INDICATOR_INFRASTRUCTURE": "resolutions,contacted"})
    # Then they are set
    assert config.indicator_infrastructure == ["resolutions", "contacted"]  # noqa: S101


@pytest.mark.parametrize(
    "env",
    [
        {"GTI_INDICATOR_INFRASTRUCTURE": "urls"},
        {"GTI_INDICATOR_INFRASTRUCTURE_LIMIT": "0"},
    ],
)
def test_infrastructure_rejects_invalid_values(env: dict[str, str]) -> None:
    """Unknown categories and a limit below 1 fail validation."""
    # Given an invalid setting
    # When the configuration is loaded
    # Then validation fails
    with pytest.raises((GTIConfigurationError, ValidationError)):
        _load_config(env)
