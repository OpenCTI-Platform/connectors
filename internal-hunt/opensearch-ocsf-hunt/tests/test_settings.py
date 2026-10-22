import copy
from typing import Any

import pytest
from conftest import VALID_SETTINGS
from connectors_sdk import ConfigValidationError
from opensearch_ocsf_hunt import ConnectorSettings


def _settings_dict(overrides: dict[str, Any]) -> dict[str, Any]:
    values = copy.deepcopy(VALID_SETTINGS)
    for namespace, items in overrides.items():
        values.setdefault(namespace, {}).update(items)
    return values


def _fake_settings_class(settings_dict: dict[str, Any]) -> type[ConnectorSettings]:
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _: Any, handler: Any) -> Any:
            return handler(settings_dict)

    return FakeConnectorSettings


def test_settings_should_accept_valid_input():
    # Given valid basic authentication settings
    FakeConnectorSettings = _fake_settings_class(_settings_dict({}))

    # When they are loaded
    settings = FakeConnectorSettings()

    # Then the OpenSearch OCSF hunt defaults apply
    assert settings.connector.type == "INTERNAL_HUNT"
    assert settings.connector.platform == "opensearch"
    assert settings.connector.security_platform_name == "OpenSearch"
    config = settings.opensearch_ocsf_hunt
    assert config.query_language == "ppl"
    assert config.sigma_pipeline == "ocsf"
    assert config.indices == ["ocsf-*"]
    assert (config.timestamp_field, config.timestamp_format) == ("time", "epoch_millis")
    assert config.verify_ssl is True


def test_settings_should_accept_a_cluster_without_security():
    # Given settings without credentials and with custom indices
    FakeConnectorSettings = _fake_settings_class(
        _settings_dict(
            {
                "opensearch_ocsf_hunt": {
                    "username": None,
                    "password": None,
                    "indices": "amazon-security-lake-*,ocsf-*",
                    "query_language": "opensearch-lucene",
                    "timestamp_format": "date",
                }
            }
        )
    )

    # When/Then the settings are valid
    config = FakeConnectorSettings().opensearch_ocsf_hunt
    assert config.indices == ["amazon-security-lake-*", "ocsf-*"]
    assert config.query_language == "opensearch-lucene"
    assert config.timestamp_format == "date"


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"opensearch_ocsf_hunt": {"url": None}}, id="no_url"),
        pytest.param({"opensearch_ocsf_hunt": {"password": "  "}}, id="no_password"),
        pytest.param({"opensearch_ocsf_hunt": {"username": None}}, id="password_only"),
        pytest.param({"opensearch_ocsf_hunt": {"query_language": "sql"}}, id="lang"),
        pytest.param(
            {"opensearch_ocsf_hunt": {"timestamp_format": "epoch_second"}},
            id="time_format",
        ),
        pytest.param({"opensearch_ocsf_hunt": {"indices": ""}}, id="no_indices"),
        pytest.param({"connector": {"scope": "opensearch,splunk"}}, id="two_scopes"),
    ],
)
def test_settings_should_raise_when_invalid_input(overrides):
    # Given invalid settings
    FakeConnectorSettings = _fake_settings_class(_settings_dict(overrides))

    # When/Then they are rejected
    with pytest.raises(ConfigValidationError):
        FakeConnectorSettings()
