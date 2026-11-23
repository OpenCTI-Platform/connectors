import pytest
from pydantic import ValidationError
from src.models.configs.threatfox_configs import _ConfigLoaderThreatFox


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in ("AUTH_KEY", "CSV_URL"):
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


def test_missing_auth_key_is_rejected():
    with pytest.raises(ValidationError, match="THREATFOX_AUTH_KEY is required"):
        _ConfigLoaderThreatFox()
