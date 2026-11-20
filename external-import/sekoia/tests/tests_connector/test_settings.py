import os
import sys
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from src.connector.settings import ConnectorSettings

CONNECTOR_ID = "sekoia--8c694370-34bb-4f5d-a934-856779a473a0"
DEFAULT_SCOPE = [
    "identity",
    "attack-pattern",
    "course-of-action",
    "intrusion-set",
    "malware",
    "tool",
    "report",
    "location",
    "vulnerability",
    "indicator",
    "campaign",
    "infrastructure",
    "relationship",
]

MINIMAL_VALID_SETTINGS_DICT = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {},
    "sekoia": {
        "api_key": "test-api-key",
    },
}

FULL_VALID_SETTINGS_DICT = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {
        "id": "test-connector-id",
        "name": "Test Sekoia",
        "scope": "indicator,report",
        "log_level": "info",
        "duration_period": "PT5M",
    },
    "sekoia": {
        "api_key": "test-api-key",
        "base_url": "https://sekoia.test",
        "collection": "test-collection",
        "start_date": "2022-01-01",
        "limit": 100,
        "create_observables": False,
        "import_source_list": True,
        "import_ioc_relationships": False,
        "confidence_score": 50,
        "send_confidence": False,
    },
}


def build_settings(settings_dict: dict[str, Any]) -> ConnectorSettings:
    """Build the settings from a dict, without reading env vars or files."""

    class FakeConnectorSettings(ConnectorSettings):
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
    settings = build_settings(settings_dict)

    assert isinstance(settings.opencti, BaseConfigModel)
    assert isinstance(settings.connector, BaseConfigModel)
    assert isinstance(settings.sekoia, BaseConfigModel)
    assert settings.sekoia.api_key.get_secret_value() == "test-api-key"


def test_settings_should_read_every_field():
    settings = build_settings(FULL_VALID_SETTINGS_DICT)

    assert settings.connector.id == "test-connector-id"
    assert settings.connector.name == "Test Sekoia"
    assert settings.connector.scope == ["indicator", "report"]
    assert settings.connector.log_level == "info"
    assert settings.connector.duration_period == timedelta(minutes=5)
    assert settings.sekoia.base_url == "https://sekoia.test"
    assert settings.sekoia.collection == "test-collection"
    assert settings.sekoia.start_date == "2022-01-01"
    assert settings.sekoia.limit == 100
    assert settings.sekoia.create_observables is False
    assert settings.sekoia.import_source_list is True
    assert settings.sekoia.import_ioc_relationships is False
    assert settings.sekoia.confidence_score == 50
    assert settings.sekoia.send_confidence is False


def assert_default_values(settings: ConnectorSettings) -> None:
    assert settings.connector.type == "EXTERNAL_IMPORT"
    assert settings.connector.name == "SEKOIA.IO"
    assert settings.connector.scope == DEFAULT_SCOPE
    assert settings.connector.log_level == "error"
    assert settings.connector.duration_period == timedelta(seconds=60)
    assert settings.sekoia.base_url == "https://api.sekoia.io"
    assert settings.sekoia.collection == "d6092c37-d8d7-45c3-8aff-c4dc26030608"
    assert settings.sekoia.start_date is None
    assert settings.sekoia.limit == 200
    assert settings.sekoia.create_observables is True
    assert settings.sekoia.import_source_list is False
    assert settings.sekoia.import_ioc_relationships is True
    assert settings.sekoia.confidence_score is None
    assert settings.sekoia.send_confidence is True


def test_settings_should_apply_defaults():
    settings = build_settings(MINIMAL_VALID_SETTINGS_DICT)

    assert_default_values(settings)


def test_settings_should_ignore_empty_values():
    # An empty value gives the default value, as before the migration.
    settings = build_settings(
        {
            "opencti": {"url": "http://localhost:8080", "token": "test-token"},
            "connector": {
                "id": "",
                "name": "",
                "scope": "",
                "log_level": "",
                "duration_period": "",
            },
            "sekoia": {
                "api_key": "test-api-key",
                "base_url": "",
                "collection": "",
                "start_date": "",
                "limit": "",
                "create_observables": "",
                "import_source_list": "",
                "import_ioc_relationships": "",
                "confidence_score": "",
                "send_confidence": "",
            },
        }
    )

    assert settings.connector.id == CONNECTOR_ID
    assert_default_values(settings)


def test_settings_should_strip_spaces():
    # Spaces around a value are removed, as before the migration.
    # A value with only spaces is empty, so the default value is used.
    settings = build_settings(
        {
            "opencti": {"url": " http://localhost:8080 ", "token": " test-token\n"},
            "connector": {"name": " Test Sekoia "},
            "sekoia": {
                "api_key": " test-api-key\n",
                "base_url": " https://sekoia.test ",
                "collection": "   ",
                "limit": " 100 ",
            },
        }
    )

    assert str(settings.opencti.url) == "http://localhost:8080/"
    assert settings.opencti.token.get_secret_value() == "test-token"
    assert settings.connector.name == "Test Sekoia"
    assert settings.sekoia.api_key.get_secret_value() == "test-api-key"
    assert settings.sekoia.base_url == "https://sekoia.test"
    assert settings.sekoia.collection == "d6092c37-d8d7-45c3-8aff-c4dc26030608"
    assert settings.sekoia.limit == 100


def test_settings_should_default_connector_id():
    # The connector keeps the id it had before the migration.
    # It is not a plain UUID, so existing deployments keep their identity.
    settings = build_settings(MINIMAL_VALID_SETTINGS_DICT)

    assert settings.connector.id == CONNECTOR_ID


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "sekoia": {"api_key": "test-api-key"},
            },
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {"id": 123456},
                "sekoia": {"api_key": "test-api-key"},
            },
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "sekoia": {},
            },
            id="missing_sekoia_api_key",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "sekoia": {"api_key": ""},
            },
            id="empty_sekoia_api_key",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "sekoia": {"api_key": "test-api-key", "limit": 0},
            },
            id="invalid_sekoia_limit",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict):
    with pytest.raises(ConfigValidationError) as err:
        build_settings(settings_dict)

    assert "Error validating configuration" in str(err.value)


# The tests below load the settings from real sources (env vars, files).
# The SDK finds the config files next to the running `__main__` module.
# So each test fakes a connector folder in `tmp_path` and points
# `__main__` to its `src/__main__.py`, as `python -m src` does.

ENV_VARS = {
    "OPENCTI_URL": "http://localhost:8080",
    "OPENCTI_TOKEN": "env-token",
    "CONNECTOR_ID": "env-connector-id",
    "CONNECTOR_NAME": "Env Sekoia",
    "CONNECTOR_SCOPE": "indicator,report",
    "CONNECTOR_LOG_LEVEL": "debug",
    "CONNECTOR_DURATION_PERIOD": "PT2H",
    "SEKOIA_API_KEY": "env-api-key",
    "SEKOIA_BASE_URL": "https://env.sekoia.test",
    "SEKOIA_COLLECTION": "env-collection",
    "SEKOIA_START_DATE": "2023-05-01",
    "SEKOIA_LIMIT": "300",
    "SEKOIA_CREATE_OBSERVABLES": "false",
    "SEKOIA_IMPORT_SOURCE_LIST": "true",
    "SEKOIA_IMPORT_IOC_RELATIONSHIPS": "false",
    "SEKOIA_CONFIDENCE_SCORE": "80",
    "SEKOIA_SEND_CONFIDENCE": "false",
}


@pytest.fixture
def connector_dir(monkeypatch, tmp_path):
    """Fake connector folder with no config file and no config env var."""
    for name in list(os.environ):
        if name.startswith(("OPENCTI_", "CONNECTOR_", "SEKOIA_")):
            monkeypatch.delenv(name)

    (tmp_path / "src").mkdir()
    main_file = tmp_path / "src" / "__main__.py"
    main_file.touch()
    monkeypatch.setitem(
        sys.modules, "__main__", SimpleNamespace(__file__=str(main_file))
    )
    return tmp_path


def test_settings_should_read_environment_variables(monkeypatch, connector_dir):
    for name, value in ENV_VARS.items():
        monkeypatch.setenv(name, value)

    settings = ConnectorSettings()

    assert str(settings.opencti.url) == "http://localhost:8080/"
    assert settings.opencti.token.get_secret_value() == "env-token"
    assert settings.connector.id == "env-connector-id"
    assert settings.connector.name == "Env Sekoia"
    assert settings.connector.scope == ["indicator", "report"]
    assert settings.connector.log_level == "debug"
    assert settings.connector.duration_period == timedelta(hours=2)
    assert settings.sekoia.api_key.get_secret_value() == "env-api-key"
    assert settings.sekoia.base_url == "https://env.sekoia.test"
    assert settings.sekoia.collection == "env-collection"
    assert settings.sekoia.start_date == "2023-05-01"
    assert settings.sekoia.limit == 300
    assert settings.sekoia.create_observables is False
    assert settings.sekoia.import_source_list is True
    assert settings.sekoia.import_ioc_relationships is False
    assert settings.sekoia.confidence_score == 80
    assert settings.sekoia.send_confidence is False


def test_settings_should_ignore_empty_environment_variables(monkeypatch, connector_dir):
    for name in ENV_VARS:
        monkeypatch.setenv(name, "")
    monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "env-token")
    monkeypatch.setenv("SEKOIA_API_KEY", "env-api-key")

    settings = ConnectorSettings()

    assert settings.connector.id == CONNECTOR_ID
    assert_default_values(settings)


def test_settings_should_strip_spaces_in_environment_variables(
    monkeypatch, connector_dir
):
    monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", " env-token\n")
    monkeypatch.setenv("SEKOIA_API_KEY", " env-api-key\n")

    settings = ConnectorSettings()

    assert settings.opencti.token.get_secret_value() == "env-token"
    assert settings.sekoia.api_key.get_secret_value() == "env-api-key"


def write_config_file(
    connector_dir: Path, file_format: str, variables: dict[str, str]
) -> None:
    """Write the variables in `src/config.yml` or in `.env`."""
    if file_format == "dotenv":
        lines = [f"{name}={value}" for name, value in variables.items()]
        (connector_dir / ".env").write_text("\n".join(lines) + "\n")
        return

    sections: dict[str, list[str]] = {}
    for name, value in variables.items():
        section, key = name.lower().split("_", 1)
        sections.setdefault(section, []).append(f"  {key}: '{value}'")
    lines = []
    for section, keys in sections.items():
        lines += [f"{section}:", *keys]
    (connector_dir / "src" / "config.yml").write_text("\n".join(lines) + "\n")


@pytest.mark.parametrize("file_format", ["yml", "dotenv"])
def test_settings_should_ignore_empty_values_in_config_files(
    connector_dir, file_format
):
    variables = dict.fromkeys(ENV_VARS, "")
    variables["OPENCTI_URL"] = "http://localhost:8080"
    variables["OPENCTI_TOKEN"] = "file-token"
    variables["SEKOIA_API_KEY"] = "file-api-key"
    write_config_file(connector_dir, file_format, variables)

    settings = ConnectorSettings()

    assert settings.opencti.token.get_secret_value() == "file-token"
    assert settings.sekoia.api_key.get_secret_value() == "file-api-key"
    assert settings.connector.id == CONNECTOR_ID
    assert_default_values(settings)


def test_settings_should_read_config_yml_in_src(connector_dir):
    (connector_dir / "src" / "config.yml").write_text(
        "opencti:\n"
        "  url: 'http://localhost:8080'\n"
        "  token: 'yml-token'\n"
        "sekoia:\n"
        "  api_key: 'yml-api-key'\n"
        "  limit: 50\n"
    )

    settings = ConnectorSettings()

    assert settings.opencti.token.get_secret_value() == "yml-token"
    assert settings.sekoia.api_key.get_secret_value() == "yml-api-key"
    assert settings.sekoia.limit == 50
    assert settings.connector.id == CONNECTOR_ID


def test_settings_should_read_dot_env_at_connector_root(connector_dir):
    (connector_dir / ".env").write_text(
        "OPENCTI_URL=http://localhost:8080\n"
        "OPENCTI_TOKEN=dotenv-token\n"
        "SEKOIA_API_KEY=dotenv-api-key\n"
        "SEKOIA_LIMIT=75\n"
    )

    settings = ConnectorSettings()

    assert settings.opencti.token.get_secret_value() == "dotenv-token"
    assert settings.sekoia.api_key.get_secret_value() == "dotenv-api-key"
    assert settings.sekoia.limit == 75


def test_settings_should_prefer_environment_variables_over_config_yml(
    monkeypatch, connector_dir
):
    (connector_dir / "src" / "config.yml").write_text(
        "opencti:\n"
        "  url: 'http://localhost:8080'\n"
        "  token: 'yml-token'\n"
        "sekoia:\n"
        "  api_key: 'yml-api-key'\n"
        "  limit: 50\n"
    )
    monkeypatch.setenv("SEKOIA_LIMIT", "500")

    settings = ConnectorSettings()

    assert settings.sekoia.limit == 500
    assert settings.sekoia.api_key.get_secret_value() == "yml-api-key"
