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


def test_auth_key_is_hidden_when_dumped():
    config = _ConfigLoaderThreatFox(auth_key="my-secret-key")

    assert "my-secret-key" not in str(config)
    assert "my-secret-key" not in str(config.model_dump(mode="json"))


def test_csv_url_takes_precedence_for_existing_setups():
    url = "https://threatfox-api.abuse.ch/v2/files/exports/legacy-key/recent.csv"

    config = _ConfigLoaderThreatFox(csv_url=url, auth_key="other-key")

    assert config.export_url == url


def test_missing_auth_key_is_rejected():
    with pytest.raises(ValidationError, match="THREATFOX_AUTH_KEY is required"):
        _ConfigLoaderThreatFox()
