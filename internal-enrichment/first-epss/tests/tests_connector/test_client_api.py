import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from connectors_sdk import ApiServerError
from internal_enrichment_connector.client_api import ConnectorClient

EPSS_RECORD = {
    "cve": "CVE-2021-44228",
    "epss": "0.999990000",
    "percentile": "1.000000000",
    "date": "2026-10-18",
}


class FakeEpssServer(ThreadingHTTPServer):
    """Local HTTP server replying with a scripted list of (status, body) responses."""

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), FakeEpssHandler)
        self.responses: list[tuple[int, dict]] = []
        self.requested_paths: list[str] = []

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_port}/data/v1/epss"


class FakeEpssHandler(BaseHTTPRequestHandler):
    server: FakeEpssServer

    def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler naming)
        self.server.requested_paths.append(self.path)
        status, body = self.server.responses.pop(0)
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass


@pytest.fixture
def server() -> Iterator[FakeEpssServer]:
    fake_server = FakeEpssServer()
    thread = threading.Thread(target=fake_server.serve_forever, daemon=True)
    thread.start()
    yield fake_server
    fake_server.shutdown()
    fake_server.server_close()


@pytest.fixture
def client(server: FakeEpssServer) -> ConnectorClient:
    # No backoff so that retries do not slow the tests down
    return ConnectorClient(server.url, backoff_factor=0)


def test_get_epss_scores_should_return_data_when_cve_is_known(server, client):
    server.responses = [(200, {"status": "OK", "data": [EPSS_RECORD]})]

    result = client.get_epss_scores("CVE-2021-44228")

    assert result == [EPSS_RECORD]
    assert server.requested_paths == ["/data/v1/epss?cve=CVE-2021-44228"]


def test_get_epss_scores_should_return_empty_list_when_cve_is_unknown(server, client):
    server.responses = [(200, {"status": "OK", "total": 0, "data": []})]

    result = client.get_epss_scores("CVE-2099-99999")

    assert result == []


def test_get_epss_scores_should_succeed_when_transient_errors_recover(server, client):
    server.responses = [
        (502, {}),
        (503, {}),
        (200, {"status": "OK", "data": [EPSS_RECORD]}),
    ]

    result = client.get_epss_scores("CVE-2021-44228")

    assert result == [EPSS_RECORD]
    assert len(server.requested_paths) == 3


def test_get_epss_scores_should_raise_when_server_errors_persist(server, client):
    server.responses = [(502, {})] * 4

    with pytest.raises(ApiServerError) as exc_info:
        client.get_epss_scores("CVE-2021-44228")

    assert exc_info.value.status_code == 502
    # One initial request plus the three retries of BaseClientApi
    assert len(server.requested_paths) == 4
