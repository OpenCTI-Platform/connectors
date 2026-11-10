"""Tests for the TAXII client, against a local HTTP server (no network)."""

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest
from conftest import make_page, make_sample_bundle
from connectors_sdk import ApiServerError
from polyswarm_client import (
    PolySwarmTaxiiClient,
    TaxiiAuthenticationError,
    TaxiiPermissionError,
    TaxiiResponseError,
)

TAXII = "application/taxii+json;version=2.1"


class FakeTaxiiServer:
    """Serves scripted responses in order and records every request."""

    def __init__(self) -> None:
        self.responses: list[tuple[int, dict, object]] = []
        self.requests: list[dict] = []
        server = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                url = urlparse(self.path)
                server.requests.append(
                    {
                        "path": url.path,
                        "query": parse_qs(url.query),
                        "headers": dict(self.headers),
                    }
                )
                status, headers, body = (
                    server.responses.pop(0) if server.responses else (404, {}, None)
                )
                payload = b""
                if body is not None:
                    payload = (
                        body if isinstance(body, bytes) else json.dumps(body).encode()
                    )
                self.send_response(status)
                self.send_header("Content-Type", TAXII)
                self.send_header("Content-Length", str(len(payload)))
                for key, value in headers.items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def add(self, status: int, body=None, headers: dict | None = None) -> None:
        self.responses.append((status, headers or {}, body))

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server():
    fake = FakeTaxiiServer()
    yield fake
    fake.close()


def make_client(server, **kwargs) -> PolySwarmTaxiiClient:
    return PolySwarmTaxiiClient(
        api_url=server.url,
        account_number="000000000000",
        api_key="secret-key",
        backoff_factor=0,
        **kwargs,
    )


def test_requests_use_basic_auth_and_taxii_accept_header(server):
    server.add(200, {"api_roots": [f"{server.url}/v3/stix/trustgroup"]})
    client = make_client(server)

    discovery = client.discovery()

    assert discovery["api_roots"] == [f"{server.url}/v3/stix/trustgroup"]
    request = server.requests[0]
    assert request["path"] == "/v3/stix/taxii2/"
    expected = base64.b64encode(b"000000000000:secret-key").decode()
    assert request["headers"]["Authorization"] == f"Basic {expected}"
    assert request["headers"]["Accept"] == TAXII


def test_api_url_with_v3_suffix_is_not_doubled(server):
    server.add(200, {"collections": []})
    client = PolySwarmTaxiiClient(
        api_url=f"{server.url}/v3/", account_number="0", api_key="k"
    )
    client.list_collections("ransomware")
    assert server.requests[0]["path"] == "/v3/stix/ransomware/collections/"


def test_get_collection_id_returns_first_readable_collection_and_caches(server):
    server.add(
        200,
        {
            "collections": [
                {"id": "not-readable", "can_read": False},
                {
                    "id": "3f153afb-5bf5-5cca-bfe9-ee854d92658d",
                    "can_read": True,
                    "can_write": False,
                    "title": "14-Day Feed",
                },
            ]
        },
    )
    client = make_client(server)

    assert client.get_collection_id("trustgroup") == (
        "3f153afb-5bf5-5cca-bfe9-ee854d92658d"
    )
    assert client.get_collection_id("trustgroup") == (
        "3f153afb-5bf5-5cca-bfe9-ee854d92658d"
    )
    assert len(server.requests) == 1


def test_get_collection_id_without_readable_collection_raises(server):
    server.add(200, {"collections": []})
    with pytest.raises(TaxiiPermissionError):
        make_client(server).get_collection_id("freemium")


def test_get_objects_sends_filters_and_parses_paging(server):
    server.add(
        200,
        make_page(make_sample_bundle(1), more=True, next_token="gAAAA-next"),
        headers={
            "X-TAXII-Date-Added-First": "2026-10-27T14:53:00.063063Z",
            "X-TAXII-Date-Added-Last": "2026-10-27T14:53:00.403510Z",
        },
    )
    client = make_client(server)

    page = client.get_objects(
        "trustgroup", "col-id", added_after="2026-10-27T00:00:00Z", limit=2
    )

    request = server.requests[0]
    assert request["path"] == "/v3/stix/trustgroup/collections/col-id/objects/"
    assert request["query"] == {"added_after": ["2026-10-27T00:00:00Z"], "limit": ["2"]}
    assert len(page.objects) == 1 and page.objects[0]["type"] == "bundle"
    assert page.more is True
    assert page.next == "gAAAA-next"
    assert page.date_added_first == "2026-10-27T14:53:00.063063Z"
    assert page.date_added_last == "2026-10-27T14:53:00.403510Z"


def test_get_objects_with_next_token(server):
    server.add(200, make_page(make_sample_bundle(2)))
    page = make_client(server).get_objects("ransomware", "c", next_token="tok", limit=5)

    assert server.requests[0]["query"] == {"next": ["tok"], "limit": ["5"]}
    assert page.more is False and page.next is None


def test_empty_object_page_is_empty(server):
    # Measured: a query past the newest data returns 200 with body `{}`.
    server.add(200, {})
    page = make_client(server).get_objects("trustgroup", "c", added_after="2099-01-01")
    assert page.objects == [] and page.more is False and page.next is None
    assert page.date_added_last is None


def test_204_is_an_empty_page(server):
    server.add(204)
    page = make_client(server).get_objects("trustgroup", "c")
    assert page.objects == []


def test_401_raises_clear_authentication_error(server):
    server.add(401, b"Unauthorized Access")
    with pytest.raises(TaxiiAuthenticationError) as err:
        make_client(server).list_collections("trustgroup")
    assert "POLYSWARM_ACCOUNT_NUMBER" in str(err.value)
    assert "secret-key" not in str(err.value)


def test_403_raises_permission_error(server):
    server.add(403, {"title": "Forbidden"})
    with pytest.raises(TaxiiPermissionError) as err:
        make_client(server).list_collections("ransomware")
    assert "ransomware" in str(err.value)


@pytest.mark.parametrize("status", [429, 500, 502, 503])
def test_transient_errors_are_retried(server, status):
    server.add(status, {"title": "busy"})
    server.add(status, {"title": "busy"})
    server.add(200, {"collections": [{"id": "c", "can_read": True}]})

    assert make_client(server, max_retries=3).get_collection_id("trustgroup") == "c"
    assert len(server.requests) == 3


def test_server_error_after_retries_raises(server):
    for _ in range(3):
        server.add(500, {"title": "InternalError", "http_status": "500"})
    with pytest.raises(ApiServerError):
        make_client(server, max_retries=2).get_objects(
            "trustgroup", "c", next_token="x"
        )
    assert len(server.requests) == 3


def test_non_json_body_raises_response_error(server):
    server.add(200, b"<html>not json</html>")
    with pytest.raises(TaxiiResponseError):
        make_client(server).get_objects("trustgroup", "c")


def test_non_list_objects_raises_response_error(server):
    server.add(200, {"objects": {"type": "bundle"}})
    with pytest.raises(TaxiiResponseError):
        make_client(server).get_objects("trustgroup", "c")
