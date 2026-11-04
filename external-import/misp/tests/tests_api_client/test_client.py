"""Tests for the MISP API client."""

import json
import socket
import threading
import time
from contextlib import contextmanager
from contextlib import nullcontext as does_not_raise
from datetime import date, datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
import requests
import responses
from api_client.client import MISPClient
from pydantic import HttpUrl

# Minimal HTTP response: empty JSON array (valid MISP restSearch response)
_HTTP_200_JSON = (
    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n[]"
)


@contextmanager
def _delayed_tcp_server(delay_seconds: float):
    """
    Start a TCP server that accepts, waits delay_seconds (simulated hang),
    then sends a valid HTTP JSON response (empty list). Client must use
    a timeout longer than delay_seconds to not raise.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]
    server.listen(1)
    done = threading.Event()

    def accept_delay_then_respond():
        try:
            while not done.is_set():
                server.settimeout(0.5)
                try:
                    conn, _ = server.accept()
                    try:
                        conn.recv(65536)  # consume request
                        time.sleep(delay_seconds)
                        if not done.is_set():
                            conn.sendall(_HTTP_200_JSON)
                    finally:
                        conn.close()
                except socket.timeout:
                    continue
        except OSError:
            pass

    thread = threading.Thread(target=accept_delay_then_respond, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        done.set()
        server.close()
        thread.join(timeout=1.0)


def _add_pymisp_init_mocks(rsps: responses.RequestsMock, base_url: str) -> None:
    """Register responses for PyMISP constructor (getVersion, users/view/me)."""
    rsps.add(
        responses.GET,
        f"{base_url}/servers/getVersion",
        json={"version": "2.4.200", "pymisp_recommended_version": "2.4.200"},
    )
    rsps.add(
        responses.GET,
        f"{base_url}/users/view/me",
        json={
            "User": {"id": 1, "email": "test@test.local"},
            "Role": {"id": 1, "name": "admin"},
            "UserSetting": {},
        },
    )


@pytest.mark.parametrize(
    ("server_delay_seconds", "client_timeout_seconds", "expected_exception"),
    [
        (1, 0.5, pytest.raises(requests.exceptions.Timeout)),
        (0.5, 1.0, does_not_raise()),
    ],
)
def test_search_events_timeout_behavior(
    server_delay_seconds, client_timeout_seconds, expected_exception
) -> None:
    """
    Simulate a non-responding server: a real TCP server accepts the connection but
    never sends data. The client (requests) must raise Timeout after the configured
    timeout.
    """
    with _delayed_tcp_server(server_delay_seconds) as base_url:
        with responses.RequestsMock(
            passthru_prefixes=(base_url,),
            assert_all_requests_are_fired=False,
        ) as rsps:
            _add_pymisp_init_mocks(rsps, base_url)
            # POST goes to delayed server: it hangs briefly then returns [] -> no timeout
            client = MISPClient(
                url=HttpUrl(base_url),
                key="test-api-key",
                timeout=client_timeout_seconds,
            )

            gen = client.search_events(
                date_field_filter="timestamp",
                date_value_filter=datetime.now(timezone.utc),
                datetime_attribute="timestamp",
                keyword="",
                included_tags=[],
                excluded_tags=[],
                included_org_creators=[],
                excluded_org_creators=[],
                enforce_warning_list=False,
                with_attachments=False,
                limit=10,
                page=1,
            )

            # No exception: server answered before timeout
            with expected_exception:
                list(gen)


def _run_search(client: MISPClient, date_field_filter: str, date_value) -> None:
    """Consume search_events with the given date filter."""
    list(
        client.search_events(
            date_field_filter=date_field_filter,
            date_value_filter=date_value,
            datetime_attribute="date",
            keyword="",
            included_tags=[],
            excluded_tags=[],
            included_org_creators=[],
            excluded_org_creators=[],
            enforce_warning_list=False,
            with_attachments=False,
            limit=10,
            page=1,
        )
    )


def _mocked_client(mock_pymisp, pages: list) -> MISPClient:
    """A client whose PyMISP.search() answers the given pages in order."""
    mock_pymisp.return_value.search.side_effect = pages
    return MISPClient(
        url=HttpUrl("https://misp.local"), key="k", timeout=1, logger=MagicMock()
    )


def _sent(client: MISPClient, field: str) -> list:
    """(page, value of the date filter) of every search() call, in order."""
    return [
        (call.kwargs["page"], call.kwargs[field])
        for call in client._client.search.call_args_list
    ]


# Not a valid event for the model: skipped with a warning, still a non-empty page.
_PAGE = [{"Event": {"id": "1"}}]
_START = datetime(2026, 1, 1, 13, 45, tzinfo=timezone.utc)


@pytest.mark.filterwarnings("ignore::UserWarning")
@patch("api_client.client.PyMISP")
def test_date_from_keeps_the_datetime_when_misp_answers_it(mock_pymisp) -> None:
    """Recent MISP versions answer the timestamp: no fallback request."""
    client = _mocked_client(mock_pymisp, [_PAGE, _PAGE, []])

    _run_search(client, "date_from", _START)

    assert _sent(client, "date_from") == [(1, _START), (2, _START), (3, _START)]
    assert client._client.search.call_args.kwargs["order"] == "Event.id ASC"


@pytest.mark.filterwarnings("ignore::UserWarning")
@patch("api_client.client.PyMISP")
def test_date_from_falls_back_to_the_date_string_and_keeps_it(mock_pymisp) -> None:
    """Page 1 empty with the timestamp: retried as YYYY-MM-DD, kept for page 2+."""
    client = _mocked_client(mock_pymisp, [[], _PAGE, _PAGE, []])

    _run_search(client, "date_from", _START)

    assert _sent(client, "date_from") == [
        (1, _START),
        (1, "2026-01-01"),
        (2, "2026-01-01"),
        (3, "2026-01-01"),
    ]


@pytest.mark.filterwarnings("ignore::UserWarning")
@patch("api_client.client.PyMISP")
def test_date_from_tries_the_format_that_worked_first_on_the_next_run(
    mock_pymisp,
) -> None:
    """The format that answered is remembered and tried first on the next run."""
    client = _mocked_client(mock_pymisp, [[], _PAGE, [], _PAGE, []])
    _run_search(client, "date_from", _START)
    client._client.search.reset_mock()

    _run_search(client, "date_from", _START)

    assert _sent(client, "date_from") == [(1, "2026-01-01"), (2, "2026-01-01")]


@patch("api_client.client.PyMISP")
def test_date_from_logs_a_warning_when_both_formats_return_nothing(
    mock_pymisp,
) -> None:
    """Nothing in either format: one warning naming both formats, no more calls."""
    client = _mocked_client(mock_pymisp, [[], []])

    _run_search(client, "date_from", _START)

    assert _sent(client, "date_from") == [(1, _START), (1, "2026-01-01")]
    client._logger.warning.assert_called_once()
    assert "2026-01-01" in client._logger.warning.call_args.args[0]
    assert client._logger.debug.call_count == 2


@patch("api_client.client.PyMISP")
def test_date_from_string_is_the_utc_date(mock_pymisp) -> None:
    """2026-01-02T01:00+05:00 is 2026-01-01T20:00Z: the date sent is 2026-01-01."""
    client = _mocked_client(mock_pymisp, [[], []])
    start = datetime(2026, 1, 2, 1, 0, tzinfo=timezone(timedelta(hours=5)))

    _run_search(client, "date_from", start)

    assert _sent(client, "date_from")[1] == (1, "2026-01-01")


@patch("api_client.client.PyMISP")
def test_date_from_accepts_a_plain_date(mock_pymisp) -> None:
    """A plain date also gets its YYYY-MM-DD fallback."""
    client = _mocked_client(mock_pymisp, [[], []])

    _run_search(client, "date_from", date(2026, 1, 1))

    assert _sent(client, "date_from") == [(1, date(2026, 1, 1)), (1, "2026-01-01")]


@patch("api_client.client.PyMISP")
def test_timestamp_filter_has_no_fallback(mock_pymisp) -> None:
    """Other filters (timestamp, publish_timestamp) send the datetime once."""
    client = _mocked_client(mock_pymisp, [[]])

    _run_search(client, "timestamp", _START)

    assert _sent(client, "timestamp") == [(1, _START)]
    client._logger.warning.assert_not_called()


@pytest.mark.filterwarnings("ignore::UserWarning")
def test_date_from_fallback_on_the_wire() -> None:
    """What goes over HTTP: a Unix timestamp first, then "from": "2026-01-01"."""
    base_url = "https://misp.local"
    bodies = []

    def rest_search(request):
        bodies.append(json.loads(request.body))
        # Answer the date string only, as the older MISP versions do.
        matched = bodies[-1].get("from") == "2026-01-01" and bodies[-1]["page"] == 1
        return 200, {}, json.dumps(_PAGE if matched else [])

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        _add_pymisp_init_mocks(rsps, base_url)
        rsps.add_callback(
            responses.POST, f"{base_url}/events/restSearch", callback=rest_search
        )
        client = MISPClient(url=HttpUrl(base_url), key="k", timeout=1)

        _run_search(client, "date_from", _START)

    assert [(b["page"], b["from"]) for b in bodies] == [
        (1, _START.timestamp()),
        (1, "2026-01-01"),
        (2, "2026-01-01"),
    ]
