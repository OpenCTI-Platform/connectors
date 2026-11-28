from typing import Any

import pytest
from connector import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError


def _settings_from(settings_dict: dict) -> ConnectorSettings:
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    return FakeConnectorSettings()


def _minimal_settings_dict(**misp: Any) -> dict:
    return {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "connector": {"id": "connector-id"},
        "misp": {"url": "https://misp.example.com", "api_key": "test-api-key", **misp},
    }


def test_settings_should_accept_minimal_input_with_defaults():
    settings = _settings_from(_minimal_settings_dict())

    assert isinstance(settings.misp, BaseConfigModel)
    assert settings.connector.name == "MISP Enrichment"
    assert settings.connector.scope == [
        "IPv4-Addr",
        "IPv6-Addr",
        "Domain-Name",
        "Url",
        "StixFile",
        "Email-Addr",
        "Indicator",
    ]
    assert settings.connector.max_tlp == "amber+strict"
    assert settings.misp.api_key.get_secret_value() == "test-api-key"
    assert settings.misp.ssl_verify is True
    assert settings.misp.import_attribute_tags_as_labels is True
    assert settings.misp.import_associated_events_tags_as_labels is False
    assert settings.misp.event_filter_creator_orgs == []
    assert settings.misp.event_filter_name_regex is None
    assert settings.misp.attribute_comment_filter_regex is None
    assert settings.misp.import_events is False


def test_settings_should_parse_comma_separated_organisations():
    settings = _settings_from(
        _minimal_settings_dict(
            event_filter_creator_orgs="CIRCL, ORGNAME",
            event_filter_owner_orgs_not="Org A",
        )
    )

    assert settings.misp.event_filter_creator_orgs == ["CIRCL", "ORGNAME"]
    assert settings.misp.event_filter_owner_orgs_not == ["Org A"]


def test_settings_should_turn_empty_regex_into_none():
    settings = _settings_from(_minimal_settings_dict(event_filter_name_regex=""))

    assert settings.misp.event_filter_name_regex is None


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {"id": "connector-id"},
                "misp": {"url": "https://misp.example.com"},
            },
            id="missing_misp_api_key",
        ),
        pytest.param(
            _minimal_settings_dict(event_filter_name_regex="(unclosed"),
            id="invalid_event_name_regex",
        ),
        pytest.param(
            _minimal_settings_dict(attribute_comment_filter_regex="[a-"),
            id="invalid_attribute_comment_regex",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict):
    with pytest.raises(ConfigValidationError) as err:
        _settings_from(settings_dict)
    assert "Error validating configuration" in str(err)
