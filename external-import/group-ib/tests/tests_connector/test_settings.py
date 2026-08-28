from typing import Any

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from settings import ConnectorSettings


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "Group-IB Test Connector",
                    "scope": "stix2,ipv4-addr,ipv6-addr",
                    "log_level": "error",
                    "duration_period": "PT4H",
                    "update_existing_data": True,
                },
                "ti_api": {
                    "username": "user@example.com",
                    "token": "test-ti-token",
                    "url": "https://tap.group-ib.com/api/v2/",
                    "proxy_ip": "10.0.0.5",
                    "proxy_port": "8080",
                    "extra_settings_schedule_time": "00:00",
                    "extra_settings_enable_statement_marking": False,
                    "collections_apt_threat_enable": True,
                    "collections_apt_threat_ttl": 90,
                    "collections_apt_threat_use_hunting_rules": True,
                    "collections_hi_threat_enable": False,
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {},
                "ti_api": {
                    "username": "user@example.com",
                    "token": "test-ti-token",
                },
            },
            id="minimal_valid_settings_dict",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`)
    accepts valid input. For the test purpose, `BaseConnectorSettings._load_config_dict` is
    overridden to return a fake but valid dict (instead of the env/config vars parsed from
    `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConnectorSettings` input
    """

    class FakeConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()
    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.ti_api, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param({}, "settings", id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "connector": {
                    "id": "connector-id",
                    "name": "Group-IB Test Connector",
                    "scope": "stix2,ipv4-addr",
                    "log_level": "error",
                    "duration_period": "PT4H",
                },
                "ti_api": {
                    "username": "user@example.com",
                    "token": "test-ti-token",
                },
            },
            "opencti.token",
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": 123456,
                    "name": "Group-IB Test Connector",
                    "scope": "stix2,ipv4-addr",
                    "log_level": "error",
                    "duration_period": "PT4H",
                },
                "ti_api": {
                    "username": "user@example.com",
                    "token": "test-ti-token",
                },
            },
            "connector.id",
            id="invalid_connector_id",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`)
    raises on invalid input. For the test purpose, `BaseConnectorSettings._load_config_dict` is
    overridden to return a fake and invalid dict (instead of the env/config vars parsed from
    `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConnectorSettings` input
    """

    class FakeConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake but invalid config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert "Error validating configuration" in str(err.value)


def _fake_settings_from_dict(settings_dict: dict[str, Any]) -> type[ConnectorSettings]:
    """Build a `ConnectorSettings` subclass returning ``settings_dict`` as raw config."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    return FakeConnectorSettings


def test_settings_should_migrate_legacy_double_underscore_ti_api_keys():
    """
    Legacy ``TI_API__*`` env vars are parsed by the connectors-sdk loader into the
    ``ti_api`` section with a leading-underscore/double-underscore suffix (e.g.
    ``TI_API__PROXY__IP`` -> ``_proxy__ip``). They must be migrated to the flattened
    single-underscore fields while emitting a ``DeprecationWarning``.
    """
    settings_dict = {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "connector": {},
        "ti_api": {
            "username": "user@example.com",
            "token": "test-ti-token",
            "_url": "https://legacy.group-ib.com/api/v2/",
            "_proxy__ip": "10.0.0.5",
            "_extra_settings__schedule_time": "02:30",
            "_collections__apt_threat__enable": "true",
            "_collections__apt_threat__ttl": "777",
        },
    }

    with pytest.warns(DeprecationWarning) as warning_records:
        settings = _fake_settings_from_dict(settings_dict)()

    assert settings.ti_api.url == "https://legacy.group-ib.com/api/v2/"
    assert settings.ti_api.proxy_ip == "10.0.0.5"
    assert settings.ti_api.extra_settings_schedule_time == "02:30"
    assert settings.ti_api.collections_apt_threat_enable is True
    assert settings.ti_api.collections_apt_threat_ttl == 777

    messages = [str(record.message) for record in warning_records]
    assert any("TI_API__PROXY__IP" in message for message in messages)
    assert any("TI_API_PROXY_IP" in message for message in messages)


def test_settings_new_keys_take_precedence_over_legacy_keys():
    """When both the legacy and the canonical variable are set, the canonical one wins."""
    settings_dict = {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "connector": {},
        "ti_api": {
            "username": "user@example.com",
            "token": "test-ti-token",
            "proxy_ip": "5.5.5.5",
            "_proxy__ip": "9.9.9.9",
        },
    }

    with pytest.warns(DeprecationWarning):
        settings = _fake_settings_from_dict(settings_dict)()

    assert settings.ti_api.proxy_ip == "5.5.5.5"


def test_settings_should_migrate_legacy_nested_config():
    """
    A legacy nested ``config.yml`` exposes ``ti_api`` with nested ``proxy``,
    ``extra_settings`` and ``collections`` sub-sections (the latter keyed by slash,
    e.g. ``apt/threat``). They must be flattened onto the canonical fields while
    emitting a ``DeprecationWarning``.
    """
    settings_dict = {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "connector": {},
        "ti_api": {
            "username": "user@example.com",
            "token": "test-ti-token",
            "url": "https://legacy.group-ib.com/api/v2/",
            "proxy": {"ip": "10.0.0.5", "port": "8080"},
            "extra_settings": {
                "schedule_time": "02:30",
                "enable_statement_marking": True,
            },
            "collections": {
                "apt/threat": {"enable": True, "ttl": 777},
                "suspicious_ip/scanner": {"enable": True},
            },
        },
    }

    with pytest.warns(DeprecationWarning) as warning_records:
        settings = _fake_settings_from_dict(settings_dict)()

    assert settings.ti_api.url == "https://legacy.group-ib.com/api/v2/"
    assert settings.ti_api.proxy_ip == "10.0.0.5"
    assert settings.ti_api.proxy_port == "8080"
    assert settings.ti_api.extra_settings_schedule_time == "02:30"
    assert settings.ti_api.extra_settings_enable_statement_marking is True
    assert settings.ti_api.collections_apt_threat_enable is True
    assert settings.ti_api.collections_apt_threat_ttl == 777
    assert settings.ti_api.collections_suspicious_ip_scanner_enable is True

    messages = [str(record.message) for record in warning_records]
    assert any("ti_api.proxy" in message for message in messages)
    assert any("ti_api.collections" in message for message in messages)


def test_settings_new_flat_keys_take_precedence_over_nested_config():
    """When both a nested sub-section and its flattened field are set, the flat one wins."""
    settings_dict = {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "connector": {},
        "ti_api": {
            "username": "user@example.com",
            "token": "test-ti-token",
            "proxy_ip": "5.5.5.5",
            "proxy": {"ip": "9.9.9.9"},
        },
    }

    with pytest.warns(DeprecationWarning):
        settings = _fake_settings_from_dict(settings_dict)()

    assert settings.ti_api.proxy_ip == "5.5.5.5"
