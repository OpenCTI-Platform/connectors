"""Tests for the MISP API client."""

import socket
import threading
import time
from contextlib import contextmanager
from contextlib import nullcontext as does_not_raise
from datetime import datetime, timezone

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
