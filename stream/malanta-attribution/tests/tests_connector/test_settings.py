from typing import Any

import pytest
from connector import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError


def make_settings(settings_dict: dict[str, Any]) -> ConnectorSettings:
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    return FakeConnectorSettings()


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "Malanta Attribution",
                    "scope": "indicator",
                    "log_level": "error",
                    "live_stream_id": "live",
                    "live_stream_listen_delete": False,
                    "live_stream_no_dependencies": True,
                },
                "malanta_attribution": {
                    "label_prefix": "apt:",
                    "actor_separators": ",",
                    "author_name": "Malanta.ai",
                    "create_intrusion_sets": True,
                    "min_confidence": 0,
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "scope": "indicator",
                    "log_level": "error",
                    "live_stream_id": "live",
                },
            },
            id="minimal_valid_settings_dict",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    settings = make_settings(settings_dict)

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.malanta_attribution, BaseConfigModel) is True


def test_settings_defaults_are_applied():
    """Defaults must match the documented behaviour in the README."""
    settings = make_settings(
        {
            "opencti": {"url": "http://localhost:8080", "token": "test-token"},
            "connector": {
                "id": "connector-id",
                "scope": "indicator",
                "live_stream_id": "live",
            },
        }
    )

    assert settings.connector.name == "Malanta Attribution"
    assert settings.malanta_attribution.label_prefix == "apt:"
    assert settings.malanta_attribution.actor_separators == ","
    assert settings.malanta_attribution.author_name == "Malanta.ai"
    assert settings.malanta_attribution.create_intrusion_sets is True
    assert settings.malanta_attribution.min_confidence == 0
    # This connector only adds attribution, so delete events are off by default.
    assert settings.connector.live_stream_listen_delete is False


@pytest.mark.parametrize(
    "settings_dict, case_id",
    [
        pytest.param({}, "empty_settings_dict", id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:PORT", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "scope": "indicator",
                    "live_stream_id": "live",
                },
            },
            "invalid_opencti_url",
            id="invalid_opencti_url",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {"scope": "indicator", "live_stream_id": "live"},
            },
            "missing_connector_id",
            id="missing_connector_id",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "scope": "indicator",
                    "live_stream_id": "live",
                },
                "malanta_attribution": {"min_confidence": 101},
            },
            "confidence_above_range",
            id="confidence_above_range",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "scope": "indicator",
                    "live_stream_id": "live",
                },
                "malanta_attribution": {"min_confidence": -1},
            },
            "confidence_below_range",
            id="confidence_below_range",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, case_id):
    with pytest.raises(ConfigValidationError) as err:
        make_settings(settings_dict)
    assert "Error validating configuration" in str(err)


def test_missing_live_stream_id_is_rejected():
    """`live_stream_id` has no default: a stream connector cannot run without it."""
    with pytest.raises(ConfigValidationError):
        make_settings(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {"id": "connector-id", "scope": "indicator"},
            }
        )


# --- regression: separators configured as a string ---------------------------


@pytest.mark.parametrize(
    "configured, expected",
    [
        pytest.param(",", ",", id="single_comma"),
        pytest.param(",;", ",;", id="comma_and_semicolon"),
        pytest.param("|", "|", id="pipe_only"),
    ],
)
def test_actor_separators_survives_string_configuration(configured, expected):
    """A comma must survive being configured as a string.

    Regression: this field was previously typed `ListFromString`, which splits
    its own input on commas. Configuring `actor_separators: ","` -- exactly what
    config.yml.sample and any env var produce -- validated to an empty list, so
    comma-joined tokens like `apt:APT17,APT5` were silently left unsplit. The
    unit tests missed it because they only ever exercised the Python default,
    which is a list and bypasses the validator.
    """
    settings = make_settings(
        {
            "opencti": {"url": "http://localhost:8080", "token": "test-token"},
            "connector": {
                "id": "connector-id",
                "scope": "indicator",
                "live_stream_id": "live",
            },
            "malanta_attribution": {"actor_separators": configured},
        }
    )
    assert settings.malanta_attribution.actor_separators == expected


def test_comma_joined_token_splits_with_string_configured_separators():
    """End-to-end of the above: the D8 token must actually split."""
    from connector.labels import parse_actor_labels

    settings = make_settings(
        {
            "opencti": {"url": "http://localhost:8080", "token": "test-token"},
            "connector": {
                "id": "connector-id",
                "scope": "indicator",
                "live_stream_id": "live",
            },
            "malanta_attribution": {"actor_separators": ","},
        }
    )
    actors = parse_actor_labels(
        ["apt:APT17,APT5"],
        separators=settings.malanta_attribution.actor_separators,
    )
    assert actors == ["APT17", "APT5"]
