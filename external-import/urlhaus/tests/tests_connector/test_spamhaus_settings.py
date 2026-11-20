from datetime import datetime, timedelta, timezone

import pytest
from external_import_connector.settings import UrlhausConfig

AUTH_KEY = "community-auth-key"
USERNAME = "analyst@example.com"
PASSWORD = "s3cr3t-password"


def test_should_accept_commercial_credentials_when_no_auth_key():
    config = UrlhausConfig(spamhaus_username=USERNAME, spamhaus_password=PASSWORD)

    assert config.commercial_configured is True
    assert config.community_configured is False
    assert config.auth_key is None


def test_should_accept_auth_key_when_no_commercial_credentials():
    config = UrlhausConfig(auth_key=AUTH_KEY)

    assert config.commercial_configured is False
    assert config.community_configured is True


def test_should_accept_both_modes_when_both_are_configured():
    config = UrlhausConfig(
        auth_key=AUTH_KEY, spamhaus_username=USERNAME, spamhaus_password=PASSWORD
    )

    assert config.commercial_configured is True
    assert config.community_configured is True


def test_should_name_both_options_when_no_mode_is_configured():
    with pytest.raises(ValueError) as err:
        UrlhausConfig()

    message = str(err.value)
    assert "URLHAUS_AUTH_KEY" in message
    assert "URLHAUS_SPAMHAUS_USERNAME" in message
    assert "URLHAUS_SPAMHAUS_PASSWORD" in message


@pytest.mark.parametrize(
    "values",
    [
        pytest.param({"spamhaus_username": USERNAME}, id="username_only"),
        pytest.param({"spamhaus_password": PASSWORD}, id="password_only"),
    ],
)
def test_should_reject_spamhaus_credentials_when_username_or_password_is_missing(
    values,
):
    with pytest.raises(ValueError, match="is set but"):
        UrlhausConfig(auth_key=AUTH_KEY, **values)


def test_should_treat_spamhaus_values_as_unset_when_blank():
    # An empty `${VAR}` in docker compose gives an empty string
    config = UrlhausConfig(
        auth_key=AUTH_KEY, spamhaus_username=" ", spamhaus_password=""
    )

    assert config.commercial_configured is False


def test_should_accept_retired_csv_url_when_commercial_credentials_are_set():
    config = UrlhausConfig(
        csv_url="https://urlhaus.abuse.ch/downloads/csv_recent/",
        spamhaus_username=USERNAME,
        spamhaus_password=PASSWORD,
    )

    assert config.commercial_configured is True
    # The retired URL cannot be used as a community fallback
    assert config.community_configured is False


def test_should_use_commercial_mode_when_both_modes_are_configured():
    config = UrlhausConfig(
        auth_key=AUTH_KEY, spamhaus_username=USERNAME, spamhaus_password=PASSWORD
    )

    assert config.use_commercial is True


def test_should_accept_csv_url_alone_when_it_is_a_mirror_of_the_export():
    config = UrlhausConfig(csv_url="https://mirror.example/key/recent.csv")

    assert config.community_configured is True
    assert config.commercial_configured is False


def test_should_reject_csv_url_when_spamhaus_credentials_are_incomplete():
    with pytest.raises(ValueError, match="is set but"):
        UrlhausConfig(
            csv_url="https://mirror.example/key/recent.csv",
            spamhaus_username=USERNAME,
        )


def test_should_hide_password_when_config_is_printed_or_dumped():
    config = UrlhausConfig(spamhaus_username=USERNAME, spamhaus_password=PASSWORD)

    assert PASSWORD not in repr(config)
    assert PASSWORD not in config.model_dump_json()
    assert USERNAME not in repr(config)
    assert config.spamhaus_password.get_secret_value() == PASSWORD


def test_should_start_first_import_30_days_back_when_no_date_is_set():
    config = UrlhausConfig(auth_key=AUTH_KEY)

    expected = datetime.now(timezone.utc) - timedelta(days=30)
    assert abs(config.spamhaus_import_from - expected) < timedelta(minutes=1)


def test_should_parse_import_from_date_when_an_iso_date_is_given():
    config = UrlhausConfig(auth_key=AUTH_KEY, spamhaus_import_from="2026-01-01")

    assert config.spamhaus_import_from == datetime(2026, 1, 1, tzinfo=timezone.utc)
