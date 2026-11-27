"""Tests for the GTI configuration shared by several collections."""

from os import environ as os_environ
from unittest.mock import patch

import pytest
from connector.src.custom.configs.gti_config import GTIConfig
from connector.src.custom.configs.shared.gti_config_shared import GTISharedConfig
from pydantic import ValidationError


def _load_config(env: dict[str, str]) -> GTISharedConfig:
    with patch.dict(os_environ, {"GTI_API_KEY": "fake-key", **env}):
        return GTISharedConfig()


def test_indicator_scoring_defaults_to_threat_score() -> None:
    """The default keeps the scoring used before the setting existed."""
    # Given a configuration without indicator_scoring
    # When it is loaded
    config = _load_config({})
    # Then the threat_score strategy is used
    assert config.indicator_scoring == "threat_score"  # noqa: S101


@pytest.mark.parametrize(
    "strategy", ["threat_score", "gti_derived", "average_detection"]
)
def test_indicator_scoring_accepts_known_strategies(strategy: str) -> None:
    """Each documented strategy is accepted."""
    # Given a supported strategy
    # When the configuration is loaded
    config = _load_config({"GTI_INDICATOR_SCORING": strategy})
    # Then it is kept as is
    assert config.indicator_scoring == strategy  # noqa: S101


def test_indicator_scoring_rejects_unknown_strategy() -> None:
    """An unknown strategy fails validation."""
    # Given an unsupported strategy
    # When the configuration is loaded
    # Then validation fails
    with pytest.raises(ValidationError):
        _load_config({"GTI_INDICATOR_SCORING": "random"})


@pytest.mark.parametrize(
    "env, expected",
    [({}, "any"), ({"GTI_INDICATOR_MIN_VERDICT": "malicious"}, "malicious")],
)
def test_indicator_min_verdict(env: dict[str, str], expected: str) -> None:
    """The minimum verdict defaults to 'any' and accepts known verdicts."""
    # Given a configuration with or without a minimum verdict
    # When it is loaded
    # Then the minimum verdict is set
    assert _load_config(env).indicator_min_verdict == expected  # noqa: S101


def test_indicator_min_verdict_rejects_unknown_value() -> None:
    """An unknown verdict fails validation."""
    # Given an unsupported verdict
    # When the configuration is loaded
    # Then validation fails
    with pytest.raises(ValidationError):
        _load_config({"GTI_INDICATOR_MIN_VERDICT": "benign"})


@pytest.mark.parametrize(
    "env, expected", [({}, False), ({"GTI_IOC_TAGS_AS_LABELS": "true"}, True)]
)
def test_ioc_tags_as_labels(env: dict[str, str], expected: bool) -> None:
    """Tags as labels are disabled by default."""
    # Given a configuration with or without the option
    # When it is loaded
    # Then the option is set
    assert _load_config(env).ioc_tags_as_labels is expected  # noqa: S101


@pytest.mark.parametrize(
    "env, expected", [({}, False), ({"GTI_IP_LINK_TO_ASN": "true"}, True)]
)
def test_ip_link_to_asn(env: dict[str, str], expected: bool) -> None:
    """Autonomous systems are disabled by default."""
    # Given a configuration with or without the option
    # When it is loaded
    # Then the option is set
    assert _load_config(env).ip_link_to_asn is expected  # noqa: S101


@pytest.mark.parametrize(
    "env, expected", [({}, False), ({"GTI_IP_LINK_TO_COUNTRY": "true"}, True)]
)
def test_ip_link_to_country(env: dict[str, str], expected: bool) -> None:
    """Country links are disabled by default."""
    # Given a configuration with or without the option
    # When it is loaded
    # Then the option is set
    assert _load_config(env).ip_link_to_country is expected  # noqa: S101


@pytest.mark.parametrize(
    "env, expected",
    [({}, False), ({"GTI_RELATIONSHIP_DESCRIPTIONS": "true"}, True)],
)
def test_relationship_descriptions(env: dict[str, str], expected: bool) -> None:
    """Relationship descriptions are disabled by default."""
    # Given a configuration with or without the option
    # When it is loaded
    # Then the option is set
    assert _load_config(env).relationship_descriptions is expected  # noqa: S101


def test_gti_config_exposes_shared_settings() -> None:
    """The unified GTI configuration includes the shared settings."""
    # Given the unified configuration
    # When its fields are listed
    # Then the shared settings are present
    assert "indicator_scoring" in GTIConfig.model_fields  # noqa: S101
