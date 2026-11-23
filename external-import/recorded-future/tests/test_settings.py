import pytest
from models.configs.config_loader import ConfigLoader, ConfigLoaderConnector
from models.configs.connector_configs import _ConfigLoaderOCTI
from models.configs.recorded_future_configs import (
    _ConfigLoaderAlert,
    _ConfigLoaderPlaybookAlert,
    _ConfigLoaderRecordedFuture,
)
from pydantic import ValidationError
from pydantic_settings import EnvSettingsSource


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
    assert config.analyst_notes_include_context_entities is False


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


def test_analyst_notes_include_context_entities_accepts_true():
    kwargs = _minimal_kwargs()
    kwargs["analyst_notes_include_context_entities"] = True

    config = _ConfigLoaderRecordedFuture(**kwargs)

    assert config.analyst_notes_include_context_entities is True


def test_analyst_notes_include_context_entities_rejects_blank_string():
    kwargs = _minimal_kwargs()
    kwargs["analyst_notes_include_context_entities"] = "   "

    with pytest.raises(ValidationError) as err:
        _ConfigLoaderRecordedFuture(**kwargs)

    assert "Input should be a valid boolean" in str(err.value)


def test_ta_to_intrusion_set_default_is_false():
    config = _ConfigLoaderRecordedFuture(**_minimal_kwargs())

    assert config.ta_to_intrusion_set is False


def test_ta_to_intrusion_set_accepts_true():
    kwargs = _minimal_kwargs()
    kwargs["ta_to_intrusion_set"] = True

    config = _ConfigLoaderRecordedFuture(**kwargs)

    assert config.ta_to_intrusion_set is True


def test_ta_to_intrusion_set_accepts_false():
    kwargs = _minimal_kwargs()
    kwargs["ta_to_intrusion_set"] = False

    config = _ConfigLoaderRecordedFuture(**kwargs)

    assert config.ta_to_intrusion_set is False


def test_risk_threshold_default_is_60():
    """Regression guard: also passes at base, the default stays 60."""
    config = _ConfigLoaderRecordedFuture(**_minimal_kwargs())

    assert config.risk_threshold == 60


@pytest.mark.parametrize("value", [0, 1, 60, 100])
def test_risk_threshold_accepts_non_negative_integers(value):
    kwargs = _minimal_kwargs()
    kwargs["risk_threshold"] = value

    config = _ConfigLoaderRecordedFuture(**kwargs)

    assert config.risk_threshold == value


def test_risk_threshold_accepts_none():
    """Regression guard: also passes at base, `None` stays accepted."""
    kwargs = _minimal_kwargs()
    kwargs["risk_threshold"] = None

    config = _ConfigLoaderRecordedFuture(**kwargs)

    assert config.risk_threshold is None


class _EnvConfigLoader(ConfigLoader):
    """
    Subclass of `ConfigLoader` for testing purpose.
    It always uses the environment variables source, built like the one of
    `ConfigLoader.settings_customise_sources` (`env_ignore_empty=True`), so the test
    does not depend on any `.env` or `config.yml` file present on the filesystem.
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
        return (EnvSettingsSource(settings_cls, env_ignore_empty=True),)


def _given_required_env_vars(monkeypatch):
    monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
    monkeypatch.setenv("CONNECTOR_ID", "connector-id")
    monkeypatch.setenv("RECORDED_FUTURE_TOKEN", "test-token")


def test_risk_threshold_env_var_not_set_keeps_default(monkeypatch):
    """Regression guard: also passes at base, an unset variable keeps the default 60."""
    _given_required_env_vars(monkeypatch)
    monkeypatch.delenv("RECORDED_FUTURE_RISK_THRESHOLD", raising=False)

    settings = _EnvConfigLoader()

    assert settings.recorded_future.risk_threshold == 60


def test_risk_threshold_empty_env_var_keeps_default(monkeypatch):
    """An empty environment variable is ignored (`env_ignore_empty`): the default 60 applies.

    Regression guard: also passes at base.
    """
    _given_required_env_vars(monkeypatch)
    monkeypatch.setenv("RECORDED_FUTURE_RISK_THRESHOLD", "")

    settings = _EnvConfigLoader()

    assert settings.recorded_future.risk_threshold == 60


def test_risk_threshold_env_var_zero_disables_filtering(monkeypatch):
    _given_required_env_vars(monkeypatch)
    monkeypatch.setenv("RECORDED_FUTURE_RISK_THRESHOLD", "0")

    settings = _EnvConfigLoader()

    assert settings.recorded_future.risk_threshold == 0


def test_risk_threshold_rejects_negative_value():
    kwargs = _minimal_kwargs()
    kwargs["risk_threshold"] = -1

    with pytest.raises(ValidationError) as err:
        _ConfigLoaderRecordedFuture(**kwargs)

    assert "greater than or equal to 0" in str(err.value)


def test_risk_threshold_rejects_value_above_100():
    kwargs = _minimal_kwargs()
    kwargs["risk_threshold"] = 101

    with pytest.raises(ValidationError) as err:
        _ConfigLoaderRecordedFuture(**kwargs)

    assert "less than or equal to 100" in str(err.value)
