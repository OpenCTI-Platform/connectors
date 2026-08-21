from datetime import timedelta
from typing import Any
from uuid import UUID

import pytest
from connector import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError

FULL_VALID_SETTINGS_DICT = {
    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
    "connector": {
        "id": "connector-id",
        "name": "TAXII2",
        "scope": "ipv4-addr,ipv6-addr,vulnerability,domain,url,file-sha256,file-md5,file-sha1",
        "log_level": "error",
        "duration_period": "PT60M",
    },
    "taxii2": {
        "discovery_url": "https://taxii.example.com/taxii2/",
        "username": "test-username",
        "password": "test-password",
        "use_token": False,
        "token": "test-bearer-token",
        "use_apikey": False,
        "apikey_key": "X-Api-Key",
        "apikey_value": "test-apikey-value",
        "use_cert": False,
        "cert_path": "/tmp/client.pem",
        "verify_ssl": True,
        "v21": True,
        "collections": "root_a.collection_a,root_b.collection_b",
        "initial_history": 48,
        "interval": 2,
        "create_indicators": True,
        "create_observables": True,
        "add_custom_label": True,
        "custom_label": "taxii2",
        "force_pattern_as_name": True,
        "force_multiple_pattern_name": "Multiple Indicators",
        "stix_custom_property_to_label": True,
        "stix_custom_property": "x_custom_property",
        "enable_url_query_limit": True,
        "url_query_limit": 200,
        "determine_x_opencti_score_by_label": True,
        "default_x_opencti_score": 50,
        "indicator_high_score_labels": "high,critical",
        "indicator_high_score": 80,
        "indicator_medium_score_labels": "medium",
        "indicator_medium_score": 60,
        "indicator_low_score_labels": "low",
        "indicator_low_score": 40,
        "set_indicator_as_detection": True,
        "create_author": True,
        "author_name": "TAXII2 Author",
        "author_description": "TAXII2 Author description",
        "author_reliability": "A - Completely reliable",
        "exclude_specific_labels": True,
        "labels_to_exclude": "tlp:.*,internal",
        "replace_characters_in_label": True,
        "characters_to_replace_in_label": "-:_, :_",
        "ignore_pattern_types": True,
        "pattern_types_to_ignore": "yara,sigma",
        "ignore_object_types": True,
        "object_types_to_ignore": "report,note",
        "ignore_specific_patterns": True,
        "patterns_to_ignore": "[ipv4-addr:value = '127.0.0.1']",
        "ignore_specific_notes": True,
        "notes_to_ignore": "internal note",
        "save_original_indicator_id_to_note": True,
        "save_original_indicator_id_abstract": "Original indicator ID",
        "change_report_status": True,
        "change_report_status_x_opencti_workflow_id": "workflow-id",
    },
}

MINIMAL_VALID_SETTINGS_DICT = {
    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
    "connector": {"id": "connector-id"},
    "taxii2": {"discovery_url": "https://taxii.example.com/taxii2/"},
}


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(FULL_VALID_SETTINGS_DICT, id="full_valid_settings_dict"),
        pytest.param(MINIMAL_VALID_SETTINGS_DICT, id="minimal_valid_settings_dict"),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) accepts
    valid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake but valid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

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
    assert isinstance(settings.taxii2, BaseConfigModel) is True
    assert settings.connector.type == "EXTERNAL_IMPORT"
    assert settings.taxii2.discovery_url == "https://taxii.example.com/taxii2/"


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param({}, "settings", id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "connector": {"id": "connector-id"},
                "taxii2": {"discovery_url": "https://taxii.example.com/taxii2/"},
            },
            "opencti.token",
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {"id": 123456},
                "taxii2": {"discovery_url": "https://taxii.example.com/taxii2/"},
            },
            "connector.id",
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {"id": "connector-id"},
                "taxii2": {},
            },
            "taxii2.discovery_url",
            id="missing_taxii2_discovery_url",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) raises
    on invalid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake and invalid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConnectorSettings` input
    :param field_name: The name of the invalid field, only used to identify the test case
    """

    class FakeConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake and invalid config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as exc_info:
        FakeConnectorSettings()

    assert "Error validating configuration" in str(exc_info.value)


def test_settings_should_default_connector_id():
    """The connector id MUST fall back on its unique default UUID v4."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {**MINIMAL_VALID_SETTINGS_DICT, "connector": {}},
            )

    settings = FakeConnectorSettings()

    assert settings.connector.id == "d3fcfd4d-9c8a-408b-9f06-50e508148fad"
    assert UUID(settings.connector.id).version == 4


def test_settings_should_apply_taxii2_defaults():
    """
    Test that `ConnectorSettings` applies the connector's defaults when only the required
    variables are provided. Those defaults MUST mirror the ones documented in
    `docker-compose.yml` and `config.yml.sample`.
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(MINIMAL_VALID_SETTINGS_DICT)

    settings = FakeConnectorSettings()

    assert settings.connector.name == "TAXII2"
    assert settings.connector.log_level == "error"
    assert settings.connector.duration_period == timedelta(minutes=60)
    assert settings.taxii2.v21 is True
    assert settings.taxii2.verify_ssl is True
    assert settings.taxii2.collections == ["*.*"]
    assert settings.taxii2.initial_history == 24
    assert settings.taxii2.interval == 1
    assert settings.taxii2.create_indicators is True
    assert settings.taxii2.create_observables is True
    assert settings.taxii2.url_query_limit == 100
    assert settings.taxii2.default_x_opencti_score == 50
    assert settings.taxii2.indicator_high_score == 80
    assert settings.taxii2.indicator_medium_score == 60
    assert settings.taxii2.indicator_low_score == 40
    assert settings.taxii2.token is None
    assert settings.taxii2.password is None
    assert settings.taxii2.characters_to_replace_in_label == []


def test_settings_should_parse_lists_and_secrets():
    """
    Test that comma-separated variables are parsed as lists and that credentials are
    wrapped into `SecretStr` so they are never leaked when the settings are dumped.
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(FULL_VALID_SETTINGS_DICT)

    settings = FakeConnectorSettings()

    assert settings.connector.scope == [
        "ipv4-addr",
        "ipv6-addr",
        "vulnerability",
        "domain",
        "url",
        "file-sha256",
        "file-md5",
        "file-sha1",
    ]
    assert settings.taxii2.collections == ["root_a.collection_a", "root_b.collection_b"]
    assert settings.taxii2.indicator_high_score_labels == ["high", "critical"]
    assert settings.taxii2.pattern_types_to_ignore == ["yara", "sigma"]

    assert settings.taxii2.password.get_secret_value() == "test-password"
    assert settings.taxii2.token.get_secret_value() == "test-bearer-token"
    assert settings.taxii2.apikey_value.get_secret_value() == "test-apikey-value"
    assert "test-password" not in str(settings.taxii2.password)
