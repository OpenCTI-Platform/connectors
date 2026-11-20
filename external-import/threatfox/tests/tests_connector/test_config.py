import traceback

import pytest
from pydantic import ValidationError
from src.models.configs.config_loader import ConfigLoader
from src.models.configs.threatfox_configs import _ConfigLoaderThreatFox


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in (
        "AUTH_KEY",
        "CSV_URL",
        "SPAMHAUS_USERNAME",
        "SPAMHAUS_PASSWORD",
        "THREATFOX_AUTH_KEY",
        "THREATFOX_CSV_URL",
        "THREATFOX_SPAMHAUS_USERNAME",
        "THREATFOX_SPAMHAUS_PASSWORD",
    ):
        monkeypatch.delenv(name, raising=False)


def test_export_url_is_built_from_auth_key():
    config = _ConfigLoaderThreatFox(auth_key="my-secret-key")

    assert config.export_url == (
        "https://threatfox-api.abuse.ch/v2/files/exports/my-secret-key/recent.csv"
    )


def test_auth_key_is_encoded_in_export_url():
    config = _ConfigLoaderThreatFox(auth_key="a/b?c#d%e")

    assert config.export_url == (
        "https://threatfox-api.abuse.ch/v2/files/exports/a%2Fb%3Fc%23d%25e/recent.csv"
    )


def test_auth_key_is_hidden_when_dumped():
    config = _ConfigLoaderThreatFox(auth_key="my-secret-key")

    assert "my-secret-key" not in str(config)
    assert "my-secret-key" not in str(config.model_dump(mode="json"))


def test_csv_url_takes_precedence_for_existing_setups():
    url = "https://threatfox-api.abuse.ch/v2/files/exports/legacy-key/recent.csv"

    config = _ConfigLoaderThreatFox(csv_url=url, auth_key="other-key")

    assert not config.has_legacy_csv_url
    assert config.export_url == url


def test_csv_url_is_hidden_when_dumped():
    config = _ConfigLoaderThreatFox(
        csv_url="https://threatfox-api.abuse.ch/v2/files/exports/legacy-key/recent.csv"
    )

    assert "legacy-key" not in str(config)
    assert "legacy-key" not in str(config.model_dump(mode="json"))


@pytest.mark.parametrize(
    "legacy_url",
    [
        "https://threatfox.abuse.ch/export/csv/recent/",
        "http://threatfox.abuse.ch/export/csv/full/",
    ],
)
def test_legacy_csv_url_falls_back_to_auth_key(legacy_url):
    config = _ConfigLoaderThreatFox(csv_url=legacy_url, auth_key="my-secret-key")

    assert config.has_legacy_csv_url
    assert config.export_url == (
        "https://threatfox-api.abuse.ch/v2/files/exports/my-secret-key/recent.csv"
    )


def test_legacy_csv_url_without_auth_key_is_rejected():
    with pytest.raises(ValidationError, match="retired public export"):
        _ConfigLoaderThreatFox(csv_url="https://threatfox.abuse.ch/export/csv/recent/")


def test_missing_credentials_are_rejected_with_both_options_named():
    with pytest.raises(ValidationError) as exc_info:
        _ConfigLoaderThreatFox()

    message = str(exc_info.value)
    assert "THREATFOX_AUTH_KEY" in message
    assert "THREATFOX_SPAMHAUS_USERNAME" in message
    assert "THREATFOX_SPAMHAUS_PASSWORD" in message


def test_spamhaus_credentials_are_enough():
    config = _ConfigLoaderThreatFox(
        spamhaus_username="analyst@example.com", spamhaus_password="pw"
    )

    assert config.use_commercial is True
    assert config.community_configured is False
    assert config.export_url is None


def test_spamhaus_credentials_are_read_from_the_environment(monkeypatch):
    monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "00000000-0000-4000-8000-000000000000")
    monkeypatch.setenv("THREATFOX_SPAMHAUS_USERNAME", "analyst@example.com")
    monkeypatch.setenv("THREATFOX_SPAMHAUS_PASSWORD", "pw")

    config = ConfigLoader().threatfox

    assert config.use_commercial is True
    assert config.spamhaus_password.get_secret_value() == "pw"


def test_spamhaus_credentials_are_hidden_when_dumped():
    config = _ConfigLoaderThreatFox(
        spamhaus_username="analyst@example.com", spamhaus_password="pw-secret"
    )

    dumped = str(config) + str(config.model_dump(mode="json"))
    assert "pw-secret" not in dumped
    assert "analyst@example.com" not in dumped


def test_commercial_wins_and_the_auth_key_stays_the_fallback():
    config = _ConfigLoaderThreatFox(
        auth_key="my-secret-key",
        spamhaus_username="analyst@example.com",
        spamhaus_password="pw",
    )

    assert config.use_commercial is True
    assert config.community_configured is True
    assert config.export_url.endswith("/my-secret-key/recent.csv")


def test_csv_url_alone_counts_as_a_community_setup():
    config = _ConfigLoaderThreatFox(
        csv_url="https://threatfox-api.abuse.ch/v2/files/exports/legacy-key/recent.csv"
    )

    assert config.community_configured is True
    assert config.use_commercial is False


def test_legacy_csv_url_does_not_count_as_community_with_commercial_credentials():
    config = _ConfigLoaderThreatFox(
        csv_url="https://threatfox.abuse.ch/export/csv/recent/",
        spamhaus_username="analyst@example.com",
        spamhaus_password="pw",
    )

    assert config.community_configured is False
    assert config.export_url is None


def test_username_without_password_is_rejected():
    with pytest.raises(ValidationError, match="THREATFOX_SPAMHAUS_PASSWORD"):
        _ConfigLoaderThreatFox(auth_key="k", spamhaus_username="analyst@example.com")


@pytest.mark.parametrize(
    "env",
    [
        {"THREATFOX_SPAMHAUS_PASSWORD": "pw-do-not-leak"},
        {
            "THREATFOX_SPAMHAUS_PASSWORD": "pw-do-not-leak",
            "THREATFOX_AUTH_KEY": "community-key-do-not-leak",
        },
        {"THREATFOX_SPAMHAUS_USERNAME": "user-do-not-leak"},
        {
            "THREATFOX_SPAMHAUS_USERNAME": "user-do-not-leak",
            "THREATFOX_AUTH_KEY": "community-key-do-not-leak",
        },
    ],
)
def test_partial_credentials_never_reach_the_startup_traceback(monkeypatch, env):
    """The whole formatted chain (section and loader) must not echo the raw input."""
    monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "00000000-0000-4000-8000-000000000000")
    for name, value in env.items():
        monkeypatch.setenv(name, value)

    with pytest.raises(ValidationError) as excinfo:
        ConfigLoader()

    formatted = "".join(traceback.format_exception(excinfo.value))
    for secret in (
        "pw-do-not-leak",
        "user-do-not-leak",
        "community-key-do-not-leak",
        "00000000-0000-4000-8000-000000000000",
    ):
        assert secret not in formatted
    assert "THREATFOX_SPAMHAUS" in formatted  # the message still names the variables


def test_the_section_alone_does_not_echo_its_input():
    # Passed through a variable: the traceback prints the source line of the call.
    values = {"spamhaus_password": "pw-do-not-leak"}

    with pytest.raises(ValidationError) as excinfo:
        _ConfigLoaderThreatFox(**values)

    assert "pw-do-not-leak" not in "".join(traceback.format_exception(excinfo.value))
