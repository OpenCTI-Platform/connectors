"""Runs of the connector over the real SDK `SpamhausClient`, with only the HTTP
transport faked: the acceptance scenarios of the Spamhaus commercial mode."""

import time
from unittest.mock import MagicMock, patch

import requests
from external_import_connector.client_api import ConnectorClient
from external_import_connector.connector import ConnectorState, ConnectorURLhaus
from external_import_connector.converter_to_stix import ConverterToStix
from external_import_connector.settings import UrlhausConfig
from spamhaus_client import SpamhausClient

USERNAME = "analyst@example.com"
PASSWORD = "p4ssw0rd-do-not-leak"
TOKEN = "jwt-token-do-not-leak"
NEW_TOKEN = "jwt-token-renewed-do-not-leak"


def response(status_code=200, body=None) -> requests.Response:
    fake = MagicMock(spec=requests.Response)
    fake.status_code = status_code
    fake.ok = 200 <= status_code < 400
    fake.json.return_value = body
    fake.text = "" if body is None else str(body)
    fake.headers = {"Content-Type": "application/json"}
    fake.content = fake.text.encode()
    return fake


def login(token=TOKEN) -> requests.Response:
    return response(
        200, {"code": 200, "token": token, "expires": int(time.time()) + 86400}
    )


def item(item_id: int, first_seen: str) -> dict:
    return {
        "id": item_id,
        "urlhaus_reference": f"https://urlhaus.abuse.ch/url/{item_id}/",
        "url": f"http://malware.example/{item_id}",
        "url_status": "online",
        "host": "malware.example",
        "first_seen": first_seen,
        "threat": "malware_download",
        "blacklists": {"spamhaus_dbl": "not listed"},
        "reporter": "reporter",
        "larted": False,
        "tags": ["elf"],
    }


def page(items: list, next_cursor: str | None = None) -> requests.Response:
    meta = {"page_size": 100, "total_items": len(items)}
    if next_cursor:
        meta["next_cursor"] = next_cursor
        meta["next_page"] = f"/urlhaus/v1/urls?after={next_cursor}"
    return response(200, {"items": items, "meta": meta})


def build_connector(**config_values) -> ConnectorURLhaus:
    config = MagicMock()
    config.urlhaus = UrlhausConfig(
        spamhaus_username=USERNAME,
        spamhaus_password=PASSWORD,
        threats_from_labels=False,
        **config_values,
    )
    helper = MagicMock()
    stored = {}
    helper.get_state.side_effect = lambda: dict(stored) or None
    helper.set_state.side_effect = lambda state: stored.update(state)
    helper.api.work.initiate_work.return_value = "work-1"
    connector = ConnectorURLhaus.__new__(ConnectorURLhaus)
    connector.config = config
    connector.helper = helper
    connector.state = ConnectorState()
    connector.client = ConnectorClient(helper, config, connector.state)
    connector.converter_to_stix = ConverterToStix(
        helper, config, connector.state.threat_cache
    )
    connector.client.spamhaus._max_retries = 0
    return connector


def sent_values(connector: ConnectorURLhaus) -> list[str]:
    objects = [
        obj
        for call in connector.helper.stix2_create_bundle.call_args_list
        for obj in call.args[0]
    ]
    return [obj.value for obj in objects if obj.type == "url"]


def requests_made(raw) -> list[tuple[str, str]]:
    return [(call.args[0], call.args[1]) for call in raw.call_args_list]


def test_should_import_every_page_with_a_bearer_jwt_when_credentials_are_valid():
    connector = build_connector(spamhaus_import_from="2026-10-01")
    answers = [
        login(),
        page([item(1, "2026-10-30T10:00:00Z")], next_cursor="c1"),
        page([item(2, "2026-10-31T10:00:00Z")]),
    ]

    with patch.object(SpamhausClient, "_raw_request", side_effect=answers) as raw:
        connector.process_message()

    assert requests_made(raw) == [
        ("POST", "/v1/login"),
        ("GET", "/urlhaus/v1/urls"),
        ("GET", "/urlhaus/v1/urls"),
    ]
    first, second = raw.call_args_list[1], raw.call_args_list[2]
    assert first.kwargs["headers"] == {"Authorization": f"Bearer {TOKEN}"}
    assert first.kwargs["params"] == {"since": "2026-10-01T00:00:00Z", "page_size": 100}
    assert second.kwargs["params"]["after"] == "c1"
    assert sent_values(connector) == [
        "http://malware.example/1",
        "http://malware.example/2",
    ]


def test_should_reuse_the_jwt_and_request_since_the_checkpoint_on_the_next_run():
    connector = build_connector(spamhaus_import_from="2026-10-01")
    first_run = [login(), page([item(1, "2026-10-30T10:00:00Z")])]
    with patch.object(SpamhausClient, "_raw_request", side_effect=first_run):
        connector.process_message()

    with patch.object(SpamhausClient, "_raw_request", side_effect=[page([])]) as raw:
        connector.process_message()

    assert requests_made(raw) == [("GET", "/urlhaus/v1/urls")]
    assert raw.call_args.kwargs["params"]["since"] == "2026-10-30T10:00:00Z"


def test_should_log_in_once_more_and_retry_when_the_api_answers_401():
    connector = build_connector()
    answers = [
        login(),
        response(401, {"message": "expired"}),
        login(NEW_TOKEN),
        page([item(1, "2026-10-30T10:00:00Z")]),
    ]

    with patch.object(SpamhausClient, "_raw_request", side_effect=answers) as raw:
        connector.process_message()

    assert requests_made(raw) == [
        ("POST", "/v1/login"),
        ("GET", "/urlhaus/v1/urls"),
        ("POST", "/v1/login"),
        ("GET", "/urlhaus/v1/urls"),
    ]
    assert raw.call_args.kwargs["headers"] == {"Authorization": f"Bearer {NEW_TOKEN}"}
    assert sent_values(connector) == ["http://malware.example/1"]


def test_should_fail_the_work_without_secrets_when_the_credentials_are_rejected():
    connector = build_connector()

    with patch.object(
        SpamhausClient, "_raw_request", return_value=response(401, {"message": "no"})
    ):
        connector.process_message()

    args, kwargs = connector.helper.api.work.to_processed.call_args
    assert kwargs["in_error"] is True
    assert "check the Spamhaus credentials" in args[1]
    connector.helper.set_state.assert_not_called()
    everything = str(connector.helper.mock_calls)
    assert PASSWORD not in everything
    assert TOKEN not in everything
