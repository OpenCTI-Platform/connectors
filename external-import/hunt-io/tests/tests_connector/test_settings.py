from typing import Any

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from external_import_connector.settings import ConnectorSettings


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
                    "name": "Hunt IO",
                    "scope": "Hunt IO",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "hunt_io": {
                    "api_base_url": "https://api.hunt.io/v1/feeds/c2",
                    "api_key": "test-api-key",
                    "tlp_level": "amber",
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
                "connector": {
                    "id": "connector-id",
                    "scope": "Hunt IO",
                },
                "hunt_io": {
                    "api_key": "test-api-key",
                },
            },
            id="minimal_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "scope": "Hunt IO",
                },
                "hunt_io": {
                    "api_version": "v3",
                    "api_base_url": "https://a.hunt.io/feeds/c2",
                    "api_key": "ak_test-api-key",
                },
            },
            id="valid_v3_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "scope": "Hunt IO",
                },
                "hunt_io": {
                    "api_version": "",
                    "api_key": "test-api-key",
                },
            },
            id="blank_api_version_falls_back_to_default",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "scope": "Hunt IO",
                },
                "hunt_io": {
                    "api_version": "V3",
                    "api_base_url": "https://a.hunt.io/feeds/c2",
                    "api_key": "ak_test-api-key",
                },
            },
            id="uppercase_api_version_is_normalized",
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
    assert isinstance(settings.hunt_io, BaseConfigModel) is True


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
                    "url": "http://localhost:PORT",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "scope": "Hunt IO",
                },
                "hunt_io": {
                    "api_key": "test-api-key",
                },
            },
            "opencti.url",
            id="invalid_opencti_url",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "scope": "Hunt IO",
                },
                "hunt_io": {},
            },
            "hunt_io.api_key",
            id="missing_hunt_io_api_key",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "scope": "Hunt IO",
                },
                "hunt_io": {
                    "api_version": "v4",
                    "api_key": "test-api-key",
                },
            },
            "hunt_io.api_version",
            id="unknown_hunt_io_api_version",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "scope": "Hunt IO",
                },
                "hunt_io": {
                    "api_version": "v3",
                    "api_base_url": "https://a.hunt.io/feeds/c2",
                    "api_key": "test-api-key",
                },
            },
            "hunt_io.api_key",
            id="v3_api_key_missing_ak_prefix",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) raises on invalid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake and invalid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConnectorSettings` input
    :param field_name: The field expected to be reported as invalid
    """

    class FakeConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake and invalid config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert str("Error validating configuration") in str(err)


@pytest.mark.parametrize(
    "raw_api_version, expected",
    [
        pytest.param("", "v2", id="blank_falls_back_to_default"),
        pytest.param("  ", "v2", id="whitespace_falls_back_to_default"),
        pytest.param("V3", "v3", id="uppercase_is_normalized"),
        pytest.param(" v2 ", "v2", id="surrounding_whitespace_is_stripped"),
    ],
)
def test_api_version_normalization(raw_api_version, expected):
    """
    A compose passthrough like `HUNT_IO_API_VERSION=${HUNT_IO_API_VERSION}` sets the
    variable to an empty string when it is undefined, which must fall back to the
    default rather than fail validation.
    """
    settings_dict = {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "connector": {"id": "connector-id", "scope": "Hunt IO"},
        "hunt_io": {
            "api_version": raw_api_version,
            "api_base_url": "https://a.hunt.io/feeds/c2",
            "api_key": "ak_test-api-key",
        },
    }

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    assert FakeConnectorSettings().hunt_io.api_version == expected
