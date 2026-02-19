import pytest
from models import ConfigLoader
from pydantic import ValidationError
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource


class FakeConfigLoader(ConfigLoader):
    """
    Subclass of `ConfigLoader` for testing purpose.
    Overrides `settings_customise_sources` to only use init_settings,
    avoiding file/env loading.
    """

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource]:
        return (init_settings,)


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
                    "scope": "feedly",
                    "log_level": "error",
                },
                "feedly": {
                    "stream_ids": "stream/123,stream/456",
                    "api_key": "test-api-key",
                    "interval": 60,
                    "days_to_back_fill": 7,
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
                "connector": {},
                "feedly": {
                    "stream_ids": "stream/123",
                    "api_key": "test-api-key",
                },
            },
            id="minimal_valid_settings_dict",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """
    Test that `ConfigLoader` accepts valid input.
    For the test purpose, `settings_customise_sources` is overridden to only use
    init_settings (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConfigLoader` input
    """
    settings = FakeConfigLoader(**settings_dict)
    assert settings.opencti is not None
    assert settings.connector is not None
    assert settings.feedly is not None


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {},
                "feedly": {
                    "api_key": "test-api-key",
                },
            },
            "stream_ids",
            id="missing_mandatory_stream_ids",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {},
                "feedly": {
                    "stream_ids": "stream/123",
                },
            },
            "api_key",
            id="missing_mandatory_api_key",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:PORT",
                    "token": "test-token",
                },
                "connector": {},
                "feedly": {
                    "stream_ids": "stream/123",
                    "api_key": "test-api-key",
                },
            },
            "url",
            id="invalid_opencti_url",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    """
    Test that `ConfigLoader` raises on invalid input.
    For the test purpose, `settings_customise_sources` is overridden to only use
    init_settings (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConfigLoader` input
    :param field_name: The field name expected in the validation error
    """
    with pytest.raises(
        ValidationError,
        match=rf"(?s)1 validation error for FakeConfigLoader.*\.{field_name}.*",
    ):
        FakeConfigLoader(**settings_dict)
