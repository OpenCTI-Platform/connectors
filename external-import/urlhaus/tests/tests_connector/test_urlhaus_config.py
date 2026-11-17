import pytest
from external_import_connector.settings import UrlhausConfig
from pydantic import ValidationError

EXPORT_URL = "https://urlhaus-api.abuse.ch/v2/files/exports/my-secret-key/recent.csv"


def test_export_url_is_built_from_auth_key():
    config = UrlhausConfig(auth_key="my-secret-key")

    assert config.export_url == EXPORT_URL


def test_auth_key_is_encoded_in_export_url():
    config = UrlhausConfig(auth_key="a/b?c#d%e")

    assert config.export_url == (
        "https://urlhaus-api.abuse.ch/v2/files/exports/a%2Fb%3Fc%23d%25e/recent.csv"
    )


@pytest.mark.parametrize(
    "kwargs",
    [{"auth_key": "my-secret-key"}, {"csv_url": EXPORT_URL}],
    ids=["auth_key", "csv_url"],
)
def test_secrets_are_hidden_when_dumped(kwargs):
    config = UrlhausConfig(**kwargs)

    assert "my-secret-key" not in str(config)
    assert "my-secret-key" not in str(config.model_dump(mode="json"))


def test_csv_url_takes_precedence_for_existing_setups():
    url = "https://urlhaus-api.abuse.ch/v2/files/exports/legacy-key/recent.csv"

    config = UrlhausConfig(csv_url=url, auth_key="other-key")

    assert not config.has_legacy_csv_url
    assert config.export_url == url


@pytest.mark.parametrize(
    "legacy_url",
    [
        "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "http://urlhaus.abuse.ch/downloads/csv/",
    ],
)
def test_legacy_csv_url_falls_back_to_auth_key_with_a_warning(legacy_url):
    with pytest.warns(UserWarning, match="retired public feed"):
        config = UrlhausConfig(csv_url=legacy_url, auth_key="my-secret-key")

    assert config.has_legacy_csv_url
    assert config.export_url == EXPORT_URL


def test_legacy_csv_url_without_auth_key_is_rejected():
    with pytest.raises(ValidationError, match="retired public feed"):
        UrlhausConfig(csv_url="https://urlhaus.abuse.ch/downloads/csv_recent/")


def test_missing_auth_key_is_rejected():
    with pytest.raises(ValidationError, match="URLHAUS_AUTH_KEY is required"):
        UrlhausConfig()
