import pytest
from models.configs.config_loader import ConfigLoader, ConfigLoaderConnector
from models.configs.connector_configs import _ConfigLoaderOCTI
from models.configs.recorded_future_configs import (
    _ConfigLoaderAlert,
    _ConfigLoaderPlaybookAlert,
    _ConfigLoaderRecordedFuture,
)
from pydantic import ValidationError


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            "full_settings_dict",
            id="full_valid_settings_dict",
        ),
        pytest.param(
            "minimal_settings_dict",
            id="minimal_valid_settings_dict",
        ),
    ],
)
def test_settings_should_accept_valid_input(request, settings_dict):
    """
    Test that `ConfigLoader` accepts valid input.
    For the test purpose, `ConfigLoader.settings_customise_sources` is overridden to return
    a fake but valid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConfigLoader` input
    """

    class FakeConfigLoader(ConfigLoader):
        """
        Subclass of `ConfigLoader` for testing purpose.
        It overrides `ConfigLoader.settings_customise_sources`
        to return a fake but valid config dict.
        """

        @classmethod
        def settings_customise_sources(
            cls,
            settings_cls,
            init_settings,
            env_settings,
            dotenv_settings,
            file_secret_settings,
        ):
            def yml_settings() -> dict:
                return request.getfixturevalue(settings_dict)

            return (yml_settings, env_settings, dotenv_settings, file_secret_settings)

    settings = FakeConfigLoader()

    assert isinstance(settings.opencti, _ConfigLoaderOCTI) is True
    assert isinstance(settings.connector, ConfigLoaderConnector) is True
    assert isinstance(settings.recorded_future, _ConfigLoaderRecordedFuture) is True
    assert isinstance(settings.alert, _ConfigLoaderAlert) is True
    assert isinstance(settings.playbook_alert, _ConfigLoaderPlaybookAlert) is True


@pytest.mark.parametrize(
    "settings_dict, error_message",
    [
        pytest.param(
            {},
            "ExceptionInfo 2 validation errors for _ConfigLoaderOCTI",
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
                },
                "rf": {
                    "token": "test-token",
                },
            },
            "Input should be a valid URL, invalid port number",
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
                },
            },
            """token
  Field required [type=missing, input_value={}, input_type=dict]""",
            id="missing_connector_token",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(
    request, settings_dict, error_message
):
    """
    Test that `ConfigLoader` raises on invalid input.
    For the test purpose, `ConfigLoader.settings_customise_sources` is overridden to return
    a fake and invalid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConfigLoader` input
    """

    class FakeConfigLoader(ConfigLoader):
        """
        Subclass of `ConfigLoader` for testing purpose.
        It overrides `ConfigLoader.settings_customise_sources`
        to return a fake but valid config dict.
        """

        @classmethod
        def settings_customise_sources(
            cls,
            settings_cls,
            init_settings,
            env_settings,
            dotenv_settings,
            file_secret_settings,
        ):
            def yml_settings() -> dict:
                return settings_dict

            return (yml_settings, env_settings, dotenv_settings, file_secret_settings)

    with pytest.raises(ValidationError) as err:
        FakeConfigLoader()

    assert error_message in str(err)


def _minimal_kwargs():
    # Provide required token field so the model can be constructed
    return {
        "token": "test-token",
    }


def test_missing_keys_get_default_values():
    """If no config value are provided, the defaults should be entered automatically."""
    config = _ConfigLoaderRecordedFuture(**_minimal_kwargs())

    assert isinstance(config.interval, int)
    assert isinstance(config.last_published_notes, int)
    assert isinstance(config.analyst_notes_guess_relationships, bool)


@pytest.mark.parametrize(
    "field, value, error_message",
    [
        ("interval", None, "Input should be a valid integer"),
        ("last_published_notes", "", "Input should be a valid integer"),
        ("analyst_notes_guess_relationships", "   ", "Input should be a valid boolean"),
    ],
)
def test_none_or_empty_raises_value_error(field, value, error_message):
    """Explicit None or empty strings should raise an error."""
    kwargs = _minimal_kwargs()
    kwargs[field] = value

    with pytest.raises(ValidationError) as err:
        _ConfigLoaderRecordedFuture(**kwargs)

    assert error_message in str(err)
