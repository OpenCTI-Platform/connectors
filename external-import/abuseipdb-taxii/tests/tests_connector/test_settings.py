import copy
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from conftest import VALID_SETTINGS_DICT, make_settings
from connector import ConnectorSettings
from connectors_sdk import (
    BaseConfigModel,
    BaseExternalImportConnectorSettings,
    ConfigValidationError,
)


def test_settings_should_be_external_import_connector_settings():
    assert issubclass(ConnectorSettings, BaseExternalImportConnectorSettings) is True


def _without(path: list[str]) -> dict:
    data = copy.deepcopy(VALID_SETTINGS_DICT)
    cursor = data
    for key in path[:-1]:
        cursor = cursor[key]
    del cursor[path[-1]]
    return data


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(VALID_SETTINGS_DICT, id="full_valid_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "abuseipdb_taxii": {
                    "username": "test-user",
                    "password": "test-password",
                },
            },
            id="minimal_valid_settings_dict",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    class FakeConnectorSettings(ConnectorSettings):
        """Override `_load_config_dict` to validate a dict instead of env/config files."""

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()

    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.opencti, BaseConfigModel)
    assert isinstance(settings.connector, BaseConfigModel)
    assert isinstance(settings.abuseipdb_taxii, BaseConfigModel)
    assert settings.connector.type == "EXTERNAL_IMPORT"


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param({}, "token", id="empty_settings_dict"),
        pytest.param(
            _without(["opencti", "token"]), "opencti.token", id="missing_opencti_token"
        ),
        pytest.param(
            _without(["abuseipdb_taxii", "password"]),
            "abuseipdb_taxii.password",
            id="missing_password",
        ),
        pytest.param(
            _without(["abuseipdb_taxii", "username"]),
            "abuseipdb_taxii.username",
            id="missing_username",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    with pytest.raises(ConfigValidationError) as err:
        make_settings(settings_dict)
    assert field_name in str(err.value.__cause__)


def test_rejects_non_https_taxii_url():
    data = copy.deepcopy(VALID_SETTINGS_DICT)
    data["abuseipdb_taxii"]["url"] = "http://taxii.abuseipdb.com/taxii2/"

    with pytest.raises(ConfigValidationError) as err:
        make_settings(data)
    assert "abuseipdb_taxii.url" in str(err.value.__cause__)


@pytest.mark.parametrize("page_size", [9, 1001])
def test_rejects_page_size_outside_server_bounds(page_size: int):
    data = copy.deepcopy(VALID_SETTINGS_DICT)
    data["abuseipdb_taxii"]["page_size"] = page_size

    with pytest.raises(ConfigValidationError):
        make_settings(data)


def test_defaults_are_applied():
    settings = make_settings(
        {
            "opencti": {"url": "http://localhost:8080", "token": "test-token"},
            "abuseipdb_taxii": {"username": "test-user", "password": "test-password"},
        }
    )
    config = settings.abuseipdb_taxii

    assert settings.connector.id == "d251fc99-1dfa-4f38-886c-8d72f3fff019"
    assert settings.connector.name == "AbuseIPDB TAXII"
    assert settings.connector.scope == ["abuseipdb-taxii"]
    assert settings.connector.duration_period == timedelta(hours=1)
    assert settings.connector.log_level == "error"
    assert config.api_root == "https://taxii.abuseipdb.com/taxii2/abuseipdb-taxii2/"
    assert config.page_size == 1000
    assert config.verify_ssl is True
    assert config.request_timeout_seconds == 60.0
    assert config.collection_id is None
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
    assert abs(config.import_since - thirty_days_ago) < timedelta(minutes=1)


@pytest.mark.parametrize(
    "value, expected",
    [("", None), ("   ", None), ("  feed-id  ", "feed-id")],
)
def test_collection_id_is_stripped_and_blank_is_unset(value: str, expected: str | None):
    data = copy.deepcopy(VALID_SETTINGS_DICT)
    data["abuseipdb_taxii"]["collection_id"] = value

    assert make_settings(data).abuseipdb_taxii.collection_id == expected


def test_import_since_accepts_a_relative_duration():
    data = copy.deepcopy(VALID_SETTINGS_DICT)
    data["abuseipdb_taxii"]["import_since"] = "P7D"

    config = make_settings(data).abuseipdb_taxii

    seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
    assert abs(config.import_since - seven_days_ago) < timedelta(minutes=1)
    assert config.import_since_iso.endswith("Z")


def test_import_since_iso_is_a_taxii_timestamp(settings: ConnectorSettings):
    assert settings.abuseipdb_taxii.import_since_iso == "2026-08-19T04:00:00Z"


def test_password_is_not_exposed_in_helper_config(settings: ConnectorSettings):
    helper_config = settings.to_helper_config()

    assert "test-password" not in str(helper_config)
    assert "test-password" not in repr(settings)
    assert settings.abuseipdb_taxii.password.get_secret_value() == "test-password"
    assert helper_config["connector"]["type"] == "EXTERNAL_IMPORT"


def test_password_is_not_exposed_when_username_is_missing():
    with pytest.raises(ConfigValidationError) as err:
        make_settings(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "abuseipdb_taxii": {"password": "test-password"},
            }
        )

    assert "test-password" not in str(err.value.__cause__)
