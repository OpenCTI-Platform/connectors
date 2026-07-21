import pytest
from trukno_connector.config import ConnectorConfig, load_config


def test_load_config_from_mapping():
    config = load_config(
        {
            "opencti": {"url": "http://opencti:8080", "token": "token"},
            "connector": {"id": "uuid", "name": "TruKno", "scope": "report"},
            "trukno": {
                "api_base_url": "https://api.trukno.com/v2",
                "api_key": "secret",
                "interval_minutes": 60,
                "initial_lookback_days": 30,
            },
        }
    )

    assert isinstance(config, ConnectorConfig)
    assert config.trukno_api_key == "secret"
    assert config.interval_minutes == 60


def test_load_config_applies_defaults_for_optional_fields():
    config = load_config(
        {
            "opencti": {"url": "http://opencti:8080", "token": "token"},
            "connector": {"id": "uuid"},
            "trukno": {"api_key": "secret"},
        }
    )

    assert config.connector_name == "TruKno"
    assert config.connector_scope == "report,attack-pattern,malware"
    assert config.trukno_api_base_url == "https://api.trukno.com/v2"
    assert config.interval_minutes == 60
    assert config.initial_lookback_days == 30


def test_load_config_still_requires_connector_id():
    with pytest.raises(ValueError, match="connector\\.id is required"):
        load_config(
            {
                "opencti": {"url": "http://opencti:8080", "token": "token"},
                "connector": {"name": "TruKno"},
                "trukno": {"api_key": "secret"},
            }
        )


def test_load_config_requires_api_key():
    with pytest.raises(ValueError, match="trukno\\.api_key is required"):
        load_config(
            {
                "opencti": {"url": "http://opencti:8080", "token": "token"},
                "connector": {"id": "uuid", "name": "TruKno", "scope": "report"},
                "trukno": {
                    "api_base_url": "https://api.trukno.com/v2",
                    "interval_minutes": 60,
                    "initial_lookback_days": 30,
                },
            }
        )


def test_load_config_requires_positive_numeric_values():
    with pytest.raises(
        ValueError, match="trukno\\.interval_minutes must be a positive integer"
    ):
        load_config(
            {
                "opencti": {"url": "http://opencti:8080", "token": "token"},
                "connector": {"id": "uuid", "name": "TruKno", "scope": "report"},
                "trukno": {
                    "api_base_url": "https://api.trukno.com/v2",
                    "api_key": "secret",
                    "interval_minutes": 0,
                    "initial_lookback_days": 30,
                },
            }
        )
