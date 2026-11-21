from typing import Any
from uuid import UUID

import pytest
from connectors_sdk import ConfigValidationError
from settings import ConnectorSettings

MINIMAL_VALID_SETTINGS_DICT = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {},
    "eset": {
        "username": "test-user",
        "password": "test-password",
    },
}


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "ESET Cyber Threat Intelligence",
                    "scope": "eset",
                    "log_level": "error",
                    "duration_period": "PT1H",
                    "update_existing_data": True,
                },
                "eset": {
                    "api_url": "eti.eset.com",
                    "username": "test-user",
                    "password": "test-password",
                    "collections": "ei.misp,ei.cc,ei.urls",
                    "import_apt_reports": True,
                    "import_start_date": "2022-04-01",
                    "create_observables": True,
                    "interval": 60,
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(MINIMAL_VALID_SETTINGS_DICT, id="minimal_valid_settings_dict"),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """Valid configurations (full and minimal) must be accepted."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()

    assert str(settings.opencti.url) == "http://localhost:8080/"
    assert settings.eset.username == "test-user"
    assert settings.eset.password.get_secret_value() == "test-password"


def test_settings_should_accept_null_collections():
    """An explicit null keeps the APT-reports-only mode supported."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    **MINIMAL_VALID_SETTINGS_DICT,
                    "eset": {
                        **MINIMAL_VALID_SETTINGS_DICT["eset"],
                        "collections": None,
                    },
                }
            )

    assert FakeConnectorSettings().eset.collections is None


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param({}, "settings_dict", id="empty_settings_dict"),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "opencti": {"url": "http://localhost:8080"},
            },
            "opencti.token",
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "eset": {"username": "test-user"},
            },
            "eset.password",
            id="missing_eset_password",
        ),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "connector": {"id": 123},
            },
            "connector.id",
            id="invalid_connector_id",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    """Invalid configurations must raise a ConfigValidationError."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()

    assert str(err.value) == "Error validating configuration."


def test_settings_should_default_connector_id():
    """The connector id MUST fall back on its unique default UUID v4."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler({**MINIMAL_VALID_SETTINGS_DICT, "connector": {}})

    settings = FakeConnectorSettings()

    assert settings.connector.id == "d7e41182-96c6-4b56-8d7e-38d06399d010"
    assert UUID(settings.connector.id).version == 4


def test_settings_should_strip_spaces_in_collections():
    """A comma-separated string with spaces must give a clean list of collections."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    **MINIMAL_VALID_SETTINGS_DICT,
                    "eset": {
                        **MINIMAL_VALID_SETTINGS_DICT["eset"],
                        "collections": "ei.misp, ei.cc",
                    },
                }
            )

    settings = FakeConnectorSettings()

    assert settings.eset.collections == ["ei.misp", "ei.cc"]
