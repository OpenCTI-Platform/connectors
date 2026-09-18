from datetime import timedelta
from typing import Any

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from livehunt import ConnectorSettings


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
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "virustotal_livehunt_notifications": {
                    "api_key": "test-api-key",
                    "create_alert": True,
                    "alert_prefix": "test-alert-prefix-",
                    "delete_notification": False,
                    "filter_with_tag": "",
                    "create_file": True,
                    "extensions": ".exe,.dll",
                    "max_age_days": 42,
                    "min_file_size": 100,
                    "max_file_size": 1_000,
                    "min_positives": 42,
                    "upload_artifact": True,
                    "create_yara_rule": True,
                    "av_list": "list_1,list_2",
                    "livehunt_tag_prefix": "test-tag-prefix-",
                    "yara_label_prefix": "test-yara-label-prefix-",
                    "livehunt_label_prefix": "test-livehunt-label-prefix-",
                    "enable_label_enrichment": False,
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "virustotal_livehunt_notifications": {
                    "api_key": "test-api-key",
                },
            },
            id="minimal_valid_settings_dict",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) accepts valid input.
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
    assert (
        isinstance(settings.virustotal_livehunt_notifications, BaseConfigModel) is True
    )


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param(
            {},
            "settings",
            id="empty_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "virustotal_livehunt_notifications": {
                    "api_key": "test-api-key",
                    "create_alert": True,
                    "alert_prefix": "test-alert-prefix-",
                    "delete_notification": False,
                    "filter_with_tag": "",
                    "create_file": True,
                    "extensions": ".exe,.dll",
                    "max_age_days": 42,
                    "min_file_size": 100,
                    "max_file_size": 1_000,
                    "min_positives": 42,
                    "upload_artifact": True,
                    "create_yara_rule": True,
                    "av_list": "list_1,list_2",
                    "livehunt_tag_prefix": "test-tag-prefix-",
                    "yara_label_prefix": "test-yara-label-prefix-",
                    "livehunt_label_prefix": "test-livehunt-label-prefix-",
                    "enable_label_enrichment": False,
                },
            },
            "opencti.token",
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": 123456,
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "virustotal_livehunt_notifications": {
                    "api_key": "test-api-key",
                    "create_alert": True,
                    "alert_prefix": "test-alert-prefix-",
                    "delete_notification": False,
                    "filter_with_tag": "",
                    "create_file": True,
                    "extensions": ".exe,.dll",
                    "max_age_days": 42,
                    "min_file_size": 100,
                    "max_file_size": 1_000,
                    "min_positives": 42,
                    "upload_artifact": True,
                    "create_yara_rule": True,
                    "av_list": "list_1,list_2",
                    "livehunt_tag_prefix": "test-tag-prefix-",
                    "yara_label_prefix": "test-yara-label-prefix-",
                    "livehunt_label_prefix": "test-livehunt-label-prefix-",
                    "enable_label_enrichment": False,
                },
            },
            "connector.id",
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "virustotal_livehunt_notifications": {
                    "create_alert": True,
                    "alert_prefix": "test-alert-prefix-",
                    "delete_notification": False,
                    "filter_with_tag": "",
                    "create_file": True,
                    "extensions": ".exe,.dll",
                    "max_age_days": 42,
                    "min_file_size": 100,
                    "max_file_size": 1_000,
                    "min_positives": 42,
                    "upload_artifact": True,
                    "create_yara_rule": True,
                    "av_list": "list_1,list_2",
                    "livehunt_tag_prefix": "test-tag-prefix-",
                    "yara_label_prefix": "test-yara-label-prefix-",
                    "livehunt_label_prefix": "test-livehunt-label-prefix-",
                    "enable_label_enrichment": False,
                },
            },
            "virustotal_livehunt_notifications.api_key",
            id="missing_virustotal_livehunt_notifications_api_key",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) raises on invalid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake and invalid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

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

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert str("Error validating configuration") in str(err)


class TestMigrateDeprecatedInterval:
    """Tests for the `migrate_deprecated_interval` model validator."""

    @pytest.fixture
    def base_config(self):
        """Return a minimal valid config dict for reuse."""
        return {
            "opencti": {"url": "http://localhost:8080", "token": "test-token"},
            "connector": {
                "id": "connector-id",
                "name": "Test Connector",
                "scope": "test,connector",
                "log_level": "error",
            },
            "virustotal_livehunt_notifications": {"api_key": "test-api-key"},
        }

    def test_migrate_interval_sec_to_duration_period(self, base_config):
        """When only `interval_sec` is set, it should be migrated to `duration_period`."""
        base_config["virustotal_livehunt_notifications"]["interval_sec"] = 300

        class FakeConnectorSettings(ConnectorSettings):
            @classmethod
            def _load_config_dict(cls, _, handler) -> dict[str, Any]:
                return handler(base_config)

        settings = FakeConnectorSettings()
        assert settings.connector.duration_period == timedelta(seconds=300)

    def test_interval_sec_with_existing_duration_period_warns(self, base_config):
        """When both `interval_sec` and `duration_period` are set, `duration_period` takes precedence."""
        base_config["virustotal_livehunt_notifications"]["interval_sec"] = 300
        base_config["connector"]["duration_period"] = "PT10M"

        class FakeConnectorSettings(ConnectorSettings):
            @classmethod
            def _load_config_dict(cls, _, handler) -> dict[str, Any]:
                return handler(base_config)

        with pytest.warns(
            UserWarning,
            match="Both 'VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_INTERVAL_SEC' and 'CONNECTOR_DURATION_PERIOD'",
        ):
            settings = FakeConnectorSettings()

        # duration_period should remain PT10M, not be overwritten by interval_sec
        assert settings.connector.duration_period == timedelta(minutes=10)

    def test_no_interval_sec_does_nothing(self, base_config):
        """When `interval_sec` is absent, the validator should not modify anything."""

        class FakeConnectorSettings(ConnectorSettings):
            @classmethod
            def _load_config_dict(cls, _, handler) -> dict[str, Any]:
                return handler(base_config)

        settings = FakeConnectorSettings()
        # duration_period should be the default (5 minutes)
        assert settings.connector.duration_period == timedelta(minutes=5)
