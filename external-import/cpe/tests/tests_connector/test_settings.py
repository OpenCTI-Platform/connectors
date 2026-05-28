from typing import Any

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from cpe import ConnectorSettings


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "cpe": {
                    "base_url": "https://services.nvd.nist.gov/rest/json/cpes/2.0",
                    "api_key": "test-api-key",
                    "interval": "6h",
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                },
                "cpe": {
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
    assert isinstance(settings.cpe, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param({}, "settings", id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "cpe": {
                    "base_url": "https://services.nvd.nist.gov/rest/json/cpes/2.0",
                    "api_key": "test-api-key",
                    "interval": "6h",
                },
            },
            "opencti.token",
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": 123456,
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "cpe": {
                    "base_url": "https://services.nvd.nist.gov/rest/json/cpes/2.0",
                    "api_key": "test-api-key",
                    "interval": "6h",
                },
            },
            "connector.id",
            id="invalid_connector_id",
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


def _make_fake_settings(settings_dict: dict[str, Any]) -> ConnectorSettings:
    """Build ConnectorSettings with injected config dict for testing."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    return FakeConnectorSettings()


def test_nist_api_key_deprecated_migrates_to_cpe_api_key() -> None:
    """
    When only NIST_API_KEY (nist.api_key) is set, a deprecation warning is emitted
    and the value is migrated to cpe.api_key.
    """
    settings_dict = {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "connector": {"id": "connector-id"},
        "cpe": {"base_url": "https://services.nvd.nist.gov/rest/json/cpes/2.0"},
        "nist": {"api_key": "legacy-nist-key"},
    }
    with pytest.warns(UserWarning, match="NIST_API_KEY.*deprecated.*CPE_API_KEY"):
        settings = _make_fake_settings(settings_dict)
    assert settings.cpe.api_key.get_secret_value() == "legacy-nist-key"


def test_both_nist_and_cpe_api_key_warns_cpe_takes_precedence() -> None:
    """
    When both NIST_API_KEY and CPE_API_KEY are set, a warning is emitted
    and cpe.api_key (CPE_API_KEY) is kept.
    """
    settings_dict = {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "connector": {"id": "connector-id"},
        "cpe": {"api_key": "preferred-cpe-key"},
        "nist": {"api_key": "legacy-nist-key"},
    }
    with pytest.warns(UserWarning, match="Both 'NIST_API_KEY' and 'CPE_API_KEY'"):
        settings = _make_fake_settings(settings_dict)
    assert settings.cpe.api_key.get_secret_value() == "preferred-cpe-key"


def test_cpe_api_key_only_used_without_warning() -> None:
    """
    When only CPE_API_KEY (cpe.api_key) is set, settings load and the key is used;
    no NIST deprecation path is involved.
    """
    settings_dict = {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "connector": {"id": "connector-id"},
        "cpe": {"api_key": "cpe-key-only"},
    }
    settings = _make_fake_settings(settings_dict)
    assert settings.cpe.api_key.get_secret_value() == "cpe-key-only"
