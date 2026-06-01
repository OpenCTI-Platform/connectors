import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

import pytest
from flashpoint_connector.config_loader import (
    ConfigLoader,
    ConfigRetrievalError,
    comma_separated_list_validator,
    iso_string_validator,
    pycti_list_serializer,
)
from pydantic_settings import SettingsConfigDict


def fake_config_dict() -> dict[str, dict[str, Any]]:
    """
    Create a fake and valid config dict to test the config loader.
    """
    return {
        "opencti": {
            "token": "test-opencti-token",
            "url": "http://test-opencti-url/",
        },
        "connector": {
            "id": "test-connector-id",
            "type": "EXTERNAL_IMPORT",
            "name": "External Import Connector",
            "scope": "test",
            "log_level": "info",
            "duration_period": "PT1H",
        },
        "flashpoint": {
            "api_key": "test-flashpoint-api-key",
            "import_start_date": (
                datetime.now(timezone.utc) - timedelta(days=30)
            ).isoformat(
                timespec="minutes"
            ),  # Reduce precision for later comparison in tests
            "import_reports": True,
            "guess_relationships_from_reports": False,
            "import_alerts": True,
            "alert_create_related_entities": True,
            "import_indicators": True,
            "import_communities": True,
            "communities_queries": "cybersecurity,cyberattack",
            "import_ccm_alerts": True,
            "fresh_ccm_alerts_only": True,
            "indicator_tlp": "TLP:CLEAR",
        },
    }


def fake_environ(config_dict: dict[str, dict[str, Any]]):
    """
    Create a environ-like dict to patch os.environ with the given config_dict.
    """
    environ = {}
    for key, value in config_dict.items():
        for sub_key, sub_value in value.items():
            if sub_value is not None:
                environ[f"{key.upper()}_{sub_key.upper()}"] = str(sub_value)
    return environ


def test_config_loader_with_valid_yaml_file():
    """
    Test the config loader with a valid YAML file.
    """
    config_dict = fake_config_dict()

    with patch(
        "flashpoint_connector.config_loader.ConfigLoader.model_config",
        SettingsConfigDict(
            frozen=True,
            extra="allow",
            yaml_file=f"{Path(__file__).parent}/config.test.yml",
            env_file=None,
        ),
    ):
        config_loader = ConfigLoader()
        config_loader_dump = config_loader.model_dump_pycti()
        # Re-serialize to reduce precision as in config_dict
        config_loader_dump["flashpoint"]["import_start_date"] = (
            config_loader.flashpoint.import_start_date.isoformat(timespec="minutes")
        )
        config_loader_dump["flashpoint"][
            "api_key"
        ] = config_loader.flashpoint.api_key.get_secret_value()

        assert config_loader_dump == config_dict


def test_config_loader_with_valid_environment_variables():
    """
    Test the config loader with valid environment variables
    """
    config_dict = fake_config_dict()

    with patch.dict(os.environ, fake_environ(config_dict)):
        config_loader = ConfigLoader()
        config_loader_dump = config_loader.model_dump_pycti()
        # Re-serialize to reduce precision as in config_dict
        config_loader_dump["flashpoint"]["import_start_date"] = (
            config_loader.flashpoint.import_start_date.isoformat(timespec="minutes")
        )
        config_loader_dump["flashpoint"][
            "api_key"
        ] = config_loader.flashpoint.api_key.get_secret_value()

        assert config_loader_dump == config_dict


def test_config_loader_with_invalid_environment_variables():
    """
    Test the config loader with invalid environment variables.
    """
    config_dict = fake_config_dict()
    config_dict["flashpoint"]["api_key"] = None  # API key is required

    with patch.dict(os.environ, fake_environ(config_dict)):
        with pytest.raises(ConfigRetrievalError):
            _ = ConfigLoader()


def test_comma_separated_list_validator_with_list_input():
    result = comma_separated_list_validator(["a", "b", "c"])
    assert result == ["a", "b", "c"]


def test_iso_string_validator_with_duration():
    result = iso_string_validator("P30D")
    assert isinstance(result, datetime)
    expected_approx = datetime.now(timezone.utc) - timedelta(days=30)
    assert abs((result - expected_approx).total_seconds()) < 5


def test_iso_string_validator_with_non_string():
    """Cover line 91: input already a datetime, returned as-is."""
    dt = datetime(2026, 1, 1, tzinfo=timezone.utc)
    result = iso_string_validator(dt)
    assert result is dt


def test_pycti_list_serializer_pycti_mode():
    mock_info = Mock()
    mock_info.context = {"mode": "pycti"}
    result = pycti_list_serializer(["a", "b", "c"], mock_info)
    assert result == "a,b,c"


def test_pycti_list_serializer_non_pycti_mode():
    mock_info = Mock()
    mock_info.context = {}
    result = pycti_list_serializer(["a", "b"], mock_info)
    assert result == ["a", "b"]


def test_pycti_list_serializer_no_context():
    mock_info = Mock()
    mock_info.context = None
    result = pycti_list_serializer(["a"], mock_info)
    assert result == ["a"]


def test_config_loader_with_dotenv_file(tmp_path):
    """Test config loader when .env file exists."""
    env_file = tmp_path / ".env"
    config_dict = fake_config_dict()

    lines = []
    for section, values in config_dict.items():
        for key, value in values.items():
            if value is not None:
                lines.append(f"{section.upper()}_{key.upper()}={value}")
    env_file.write_text("\n".join(lines))

    with patch(
        "flashpoint_connector.config_loader.ConfigLoader.model_config",
        SettingsConfigDict(
            frozen=True,
            extra="allow",
            env_nested_delimiter="_",
            env_nested_max_split=1,
            enable_decoding=False,
            yaml_file=str(tmp_path / "nonexistent.yml"),
            env_file=str(env_file),
        ),
    ):
        config_loader = ConfigLoader()
        assert (
            config_loader.flashpoint.api_key.get_secret_value()
            == "test-flashpoint-api-key"
        )


def test_config_loader_migrate_deprecated_interval():
    """Test deprecated FLASHPOINT_INTERVAL migration."""
    config_dict = fake_config_dict()
    config_dict["flashpoint"]["interval"] = "120"  # 120 minutes

    with patch.dict(os.environ, fake_environ(config_dict)):
        with patch.dict(os.environ, {"FLASHPOINT_INTERVAL": "120"}):
            with pytest.warns(
                UserWarning,
                match="FLASHPOINT_INTERVAL.*deprecated.*CONNECTOR_DURATION_PERIOD",
            ):
                config_loader = ConfigLoader()
            assert config_loader.connector.duration_period == timedelta(minutes=120)
