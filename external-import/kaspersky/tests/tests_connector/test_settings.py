"""Tests for the Kaspersky connector settings."""

from datetime import timedelta
from typing import Any
from uuid import UUID

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from kaspersky.settings import ConnectorSettings

CONNECTOR_ID_DEFAULT = "ec1217f4-241e-45a9-9ee9-b59e826c967f"

MINIMAL_VALID_SETTINGS_DICT = {
    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
    "connector": {},
    "kaspersky": {"user": "test-user", "password": "test-password"},
}

FULL_VALID_SETTINGS_DICT = {
    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
    "connector": {
        "id": "connector-id",
        "name": "Test Connector",
        "scope": "kaspersky",
        "log_level": "info",
        "duration_period": "PT6H",
    },
    "kaspersky": {
        "base_url": "https://tip.example.com",
        "user": "test-user",
        "password": "test-password",
        "certificate_path": "/run/secrets/kaspersky_certificate",
        "tlp": "Green",
        "create_observables": False,
        "create_indicators": True,
        "scopes": "publication,master_ioc",
        "publication_start_timestamp": 1704067200,
        "publication_report_type": "malware",
        "publication_report_status": "Analyzed",
        "publication_report_ignore_prefixes": "Monthly APT activity report",
        "publication_excluded_ioc_indicator_types": "Md5sum, FileItem/Sha1sum",
        "master_ioc_fetch_weekday": 1,
        "master_ioc_excluded_ioc_indicator_types": "md5Hash, sha1Hash",
        "master_ioc_report_type": "threat-report",
        "master_ioc_report_status": "In progress",
        "master_yara_fetch_weekday": 2,
        "master_yara_include_report": False,
        "master_yara_report_type": "threat-report",
        "master_yara_report_status": "Closed",
    },
}


def _build_settings(settings_dict: dict[str, Any]) -> ConnectorSettings:
    """Build `ConnectorSettings` from a dict, without reading env vars or files."""

    class FakeConnectorSettings(ConnectorSettings):
        """`ConnectorSettings` loading its config from the given dict."""

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    return FakeConnectorSettings()


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(FULL_VALID_SETTINGS_DICT, id="full_valid_settings_dict"),
        pytest.param(MINIMAL_VALID_SETTINGS_DICT, id="minimal_valid_settings_dict"),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """`ConnectorSettings` accepts valid input."""
    settings = _build_settings(settings_dict)

    assert isinstance(settings.opencti, BaseConfigModel)
    assert isinstance(settings.connector, BaseConfigModel)
    assert isinstance(settings.kaspersky, BaseConfigModel)


def test_settings_should_parse_full_input():
    """Every custom value of the full dict reaches the settings, parsed."""
    settings = _build_settings(FULL_VALID_SETTINGS_DICT)

    assert settings.connector.duration_period == timedelta(hours=6)
    kaspersky = settings.kaspersky
    assert kaspersky.base_url == "https://tip.example.com"
    assert kaspersky.password.get_secret_value() == "test-password"
    assert kaspersky.certificate_path == "/run/secrets/kaspersky_certificate"
    assert kaspersky.tlp == "Green"
    assert kaspersky.create_observables is False
    assert kaspersky.scopes == ["publication", "master_ioc"]
    assert kaspersky.publication_start_timestamp == 1704067200
    assert kaspersky.publication_report_ignore_prefixes == [
        "Monthly APT activity report"
    ]
    assert kaspersky.publication_excluded_ioc_indicator_types == [
        "Md5sum",
        "FileItem/Sha1sum",
    ]
    assert kaspersky.master_ioc_fetch_weekday == 1
    assert kaspersky.master_ioc_excluded_ioc_indicator_types == [
        "md5Hash",
        "sha1Hash",
    ]
    assert kaspersky.master_yara_fetch_weekday == 2
    assert kaspersky.master_yara_include_report is False


def test_settings_should_apply_defaults():
    """The minimal dict yields the documented defaults."""
    settings = _build_settings(MINIMAL_VALID_SETTINGS_DICT)

    assert settings.connector.name == "Kaspersky"
    assert settings.connector.scope == ["kaspersky"]
    assert settings.connector.log_level == "error"
    assert settings.connector.duration_period == timedelta(hours=12)

    kaspersky = settings.kaspersky
    assert kaspersky.base_url == "https://tip.kaspersky.com"
    assert kaspersky.certificate_path is None
    assert kaspersky.tlp == "Amber"
    assert kaspersky.create_observables is True
    assert kaspersky.create_indicators is True
    assert kaspersky.scopes == ["publication", "master_ioc", "master_yara"]
    assert kaspersky.publication_start_timestamp == 0
    assert kaspersky.publication_report_type == "threat-report"
    assert kaspersky.publication_report_status == "New"
    assert kaspersky.publication_report_ignore_prefixes == []
    assert kaspersky.publication_excluded_ioc_indicator_types == []
    assert kaspersky.master_ioc_fetch_weekday is None
    assert kaspersky.master_ioc_excluded_ioc_indicator_types == []
    assert kaspersky.master_ioc_report_type == "threat-report"
    assert kaspersky.master_ioc_report_status == "New"
    assert kaspersky.master_yara_fetch_weekday is None
    assert kaspersky.master_yara_include_report is True
    assert kaspersky.master_yara_report_type == "threat-report"
    assert kaspersky.master_yara_report_status == "New"


def test_settings_should_default_connector_id():
    """With an empty `connector` section, the connector id is the UUIDv4 default."""
    settings = _build_settings(MINIMAL_VALID_SETTINGS_DICT)

    assert settings.connector.id == CONNECTOR_ID_DEFAULT
    assert UUID(settings.connector.id).version == 4


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "opencti": {"url": "http://localhost:8080"},
            },
            id="missing_opencti_token",
        ),
        pytest.param(
            {**MINIMAL_VALID_SETTINGS_DICT, "connector": {"id": 123456}},
            id="invalid_connector_id",
        ),
        pytest.param(
            {**MINIMAL_VALID_SETTINGS_DICT, "kaspersky": {"password": "p"}},
            id="missing_kaspersky_user",
        ),
        pytest.param(
            {**MINIMAL_VALID_SETTINGS_DICT, "kaspersky": {"user": "u"}},
            id="missing_kaspersky_password",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict):
    """`ConnectorSettings` raises on invalid input."""
    with pytest.raises(ConfigValidationError) as err:
        _build_settings(settings_dict)
    assert "Error validating configuration" in str(err)


def test_settings_should_migrate_deprecated_interval_sec():
    """The legacy `interval_sec` alone migrates to `connector.duration_period`."""
    settings_dict = {
        **MINIMAL_VALID_SETTINGS_DICT,
        "kaspersky": {
            **MINIMAL_VALID_SETTINGS_DICT["kaspersky"],
            "interval_sec": 3600,
        },
    }

    with pytest.warns(UserWarning, match="kaspersky.interval_sec"):
        settings = _build_settings(settings_dict)

    assert settings.connector.duration_period == timedelta(seconds=3600)


def test_settings_should_prefer_duration_period_over_interval_sec():
    """When both are set, `connector.duration_period` wins over `interval_sec`."""
    settings_dict = {
        **MINIMAL_VALID_SETTINGS_DICT,
        "connector": {"duration_period": "PT6H"},
        "kaspersky": {
            **MINIMAL_VALID_SETTINGS_DICT["kaspersky"],
            "interval_sec": 3600,
        },
    }

    with pytest.warns(UserWarning, match="Using only 'connector.duration_period'"):
        settings = _build_settings(settings_dict)

    assert settings.connector.duration_period == timedelta(hours=6)
