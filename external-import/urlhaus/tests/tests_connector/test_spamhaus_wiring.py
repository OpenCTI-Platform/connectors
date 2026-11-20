from unittest.mock import MagicMock

import pytest
import requests
from connectors_sdk import (
    SpamhausAuthenticationError,
    SpamhausClient,
    SpamhausUnavailableError,
)
from connectors_sdk.exceptions.error import DataRetrievalError
from external_import_connector.client_api import ConnectorClient
from external_import_connector.connector import ConnectorState, ConnectorURLhaus
from external_import_connector.settings import UrlhausConfig

AUTH_KEY = "community-auth-key"
USERNAME = "analyst@example.com"
PASSWORD = "s3cr3t-password"
CSV_BODY = (
    '"1","2026-01-01 10:00:00","http://community.example/x","online","",'
    '"malware_download","tag","https://urlhaus.abuse.ch/url/1/","reporter"\n'
)
ITEM = {
    "id": 2,
    "urlhaus_reference": "https://urlhaus.abuse.ch/url/2/",
    "url": "http://commercial.example/x",
    "url_status": "online",
    "host": "commercial.example",
    "first_seen": "2026-01-02T10:00:00Z",
    "threat": "malware_download",
    "blacklists": {"spamhaus_dbl": "not listed"},
    "reporter": "reporter",
    "larted": False,
    "tags": ["tag"],
}


def make_client(**config_values) -> ConnectorClient:
    config = MagicMock()
    config.urlhaus = UrlhausConfig(**config_values)
    client = ConnectorClient(MagicMock(), config, ConnectorState())
    response = MagicMock()
    response.text = CSV_BODY
    client.session = MagicMock()
    client.session.get.return_value = response
    return client


def rows_of(client: ConnectorClient) -> list[str]:
    return [row[2] for batch in client.get_entities() for row in batch]


def test_should_not_create_a_spamhaus_client_when_only_the_auth_key_is_set():
    client = make_client(auth_key=AUTH_KEY)

    assert client.spamhaus is None
    assert rows_of(client) == ["http://community.example/x"]


def test_should_create_the_spamhaus_client_with_an_explicit_user_agent():
    client = make_client(spamhaus_username=USERNAME, spamhaus_password=PASSWORD)

    assert isinstance(client.spamhaus, SpamhausClient)
    assert client.spamhaus.session_headers == {"User-Agent": "OpenCTI-urlhaus/rolling"}


def test_should_send_the_explicit_user_agent_when_downloading_the_community_export():
    client = ConnectorClient(
        MagicMock(),
        MagicMock(urlhaus=UrlhausConfig(auth_key=AUTH_KEY)),
        ConnectorState(),
    )

    assert client.session.headers["User-Agent"] == "OpenCTI-urlhaus/rolling"


def test_should_import_from_spamhaus_when_commercial_credentials_are_set():
    client = make_client(spamhaus_username=USERNAME, spamhaus_password=PASSWORD)
    client.spamhaus = MagicMock()
    client.spamhaus.paginate.return_value = iter([[ITEM]])

    assert rows_of(client) == ["http://commercial.example/x"]
    client.session.get.assert_not_called()


def test_should_prefer_commercial_mode_when_both_modes_are_configured():
    client = make_client(
        auth_key=AUTH_KEY, spamhaus_username=USERNAME, spamhaus_password=PASSWORD
    )
    client.spamhaus = MagicMock()
    client.spamhaus.paginate.return_value = iter([[ITEM]])

    assert rows_of(client) == ["http://commercial.example/x"]
    client.session.get.assert_not_called()


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(SpamhausUnavailableError("Spamhaus cannot answer"), id="down"),
        pytest.param(
            SpamhausAuthenticationError("Spamhaus rejected the login"), id="rejected"
        ),
    ],
)
def test_should_fall_back_to_the_community_export_when_commercial_mode_fails(error):
    client = make_client(
        auth_key=AUTH_KEY, spamhaus_username=USERNAME, spamhaus_password=PASSWORD
    )
    client.spamhaus = MagicMock()
    client.spamhaus.paginate.side_effect = error

    assert rows_of(client) == ["http://community.example/x"]
    client.helper.connector_logger.warning.assert_called_once()


def test_should_not_leak_secrets_when_falling_back_to_the_community_export():
    client = make_client(
        auth_key=AUTH_KEY, spamhaus_username=USERNAME, spamhaus_password=PASSWORD
    )
    client.spamhaus = MagicMock()
    client.spamhaus.paginate.side_effect = SpamhausUnavailableError("cannot answer")

    rows_of(client)

    logged = str(client.helper.connector_logger.warning.call_args)
    assert PASSWORD not in logged
    assert USERNAME not in logged
    assert AUTH_KEY not in logged


def test_should_fall_back_from_the_checkpoint_when_commercial_mode_fails_mid_run():
    client = make_client(
        auth_key=AUTH_KEY, spamhaus_username=USERNAME, spamhaus_password=PASSWORD
    )
    client.state.last_processed_entry_old = 100.0
    client.state.last_processed_entry_new = 100.0

    def pages():
        yield [ITEM]
        raise SpamhausUnavailableError("cannot answer")

    client.spamhaus = MagicMock()
    client.spamhaus.paginate.return_value = pages()
    response = MagicMock()
    response.text = CSV_BODY.replace("2026-01-01", "2026-03-01")
    client.session.get.return_value = response

    urls = rows_of(client)

    # The page already read is kept, the export is read in full from the checkpoint
    assert urls == ["http://commercial.example/x", "http://community.example/x"]


def test_should_raise_the_credentials_hint_when_only_commercial_mode_is_set():
    client = make_client(spamhaus_username=USERNAME, spamhaus_password=PASSWORD)
    client.spamhaus = MagicMock()
    client.spamhaus.paginate.side_effect = SpamhausAuthenticationError(
        "Spamhaus rejected the login (HTTP 401): check the Spamhaus credentials"
    )

    with pytest.raises(SpamhausAuthenticationError, match="check the Spamhaus"):
        rows_of(client)

    client.session.get.assert_not_called()


def test_should_report_the_credentials_hint_on_the_work_without_secrets():
    connector = ConnectorURLhaus.__new__(ConnectorURLhaus)
    connector.helper = MagicMock()
    connector.helper.get_state.return_value = None
    connector.helper.api.work.initiate_work.return_value = "work-1"
    connector.state = ConnectorState()
    connector.client = make_client(
        spamhaus_username=USERNAME, spamhaus_password=PASSWORD
    )
    connector.client.spamhaus = MagicMock()
    connector.client.spamhaus.paginate.side_effect = SpamhausAuthenticationError(
        "Spamhaus rejected the login (HTTP 401): check the Spamhaus credentials"
    )
    connector.converter_to_stix = MagicMock()

    connector.process_message()

    args, kwargs = connector.helper.api.work.to_processed.call_args
    assert kwargs.get("in_error") is True
    assert "check the Spamhaus credentials" in args[1]
    assert PASSWORD not in args[1]
    connector.helper.set_state.assert_not_called()


def test_should_raise_when_the_community_download_fails():
    """The fallback only covers the commercial errors: a community failure fails the run."""
    client = make_client(auth_key=AUTH_KEY)
    client.session.get.side_effect = requests.ConnectionError("down")

    with pytest.raises(DataRetrievalError):
        rows_of(client)
