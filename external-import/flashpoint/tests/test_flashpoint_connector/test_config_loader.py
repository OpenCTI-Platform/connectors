import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from flashpoint_connector.config_loader import ConfigLoader, ConfigRetrievalError
from pydantic_settings import SettingsConfigDict


def fake_config_dict() -> dict[str, dict[str, Any]]:
    """
    Create a fake and valid config dict to test the config loader.
    """
    return {
        "opencti": {
            "token": "test-opencti-token",
            "url": "http://test-opencti-url/",
            "ssl_verify": False,
            "json_logging": True,
        },
        "connector": {
            "id": "test-connector-id",
            "type": "EXTERNAL_IMPORT",
            "name": "External Import Connector",
            "scope": "test",
            "log_level": "info",
            "duration_period": "PT1H",
            "expose_metrics": False,
            "metrics_port": 9095,
            "only_contextual": False,
            "queue_protocol": "amqp",
            "queue_threshold": 500,
            "run_and_terminate": False,
            "send_to_directory": False,
            "send_to_directory_path": None,
            "send_to_directory_retention": 7,
            "send_to_queue": True,
            "validate_before_import": False,
        },
        "flashpoint": {
            "api_key": "test-flashpoint-api-key",
            "import_start_date": (
                datetime.now(timezone.utc) - timedelta(days=30)
            ).isoformat(
                timespec="minutes"
            ),  # Reduce precision for later comparison in tests
            "import_reports": True,
            "indicators_in_reports": True,
            "guess_relationships_from_reports": False,
            "import_alerts": True,
            "alert_create_related_entities": True,
            "import_indicators": True,
            "import_communities": True,
            "communities_queries": "cybersecurity,cyberattack",
            "import_ccm_alerts": True,
            "fresh_ccm_alerts_only": True,
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
