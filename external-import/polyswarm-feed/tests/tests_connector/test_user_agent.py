"""Every request to PolySwarm carries the connector's own User-Agent.

Each client is run against a local HTTP server (no network) that records the
headers of every request, one test per call path.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import pycti
import pytest
import requests
from polyswarm_client import PolySwarmAccountClient, PolySwarmTaxiiClient
from polyswarm_client.hunting_client import PolySwarmHuntingClient
from polyswarm_client.user_agent import USER_AGENT

EXPECTED = f"PolySwarm-OpenCTI-Feed/{pycti.__version__} (OpenCTI)"


class RecordingServer:
    """Answers every GET with the body registered for its path."""

    def __init__(self) -> None:
        self.bodies: dict[str, object] = {}
        self.requests: list[dict] = []
        server = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                path = urlparse(self.path).path
                server.requests.append({"path": path, "headers": dict(self.headers)})
                payload = json.dumps(server.bodies.get(path, {})).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def user_agents(self) -> list[str | None]:
        return [request["headers"].get("User-Agent") for request in self.requests]

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server():
    fake = RecordingServer()
    yield fake
    fake.close()


def _taxii_client(server) -> PolySwarmTaxiiClient:
    return PolySwarmTaxiiClient(
        api_url=server.url, account_number="0", api_key="k", backoff_factor=0
    )


def test_user_agent_value_is_stable_and_versioned():
    assert USER_AGENT == EXPECTED
    assert pycti.__version__ in USER_AGENT
    assert not USER_AGENT.startswith("python-requests")
    assert not USER_AGENT.startswith("polyswarm_api")
    assert USER_AGENT != requests.utils.default_user_agent()


def test_taxii_discovery_sends_user_agent(server):
    _taxii_client(server).discovery()
    assert server.requests[0]["path"] == "/v3/stix/taxii2/"
    assert server.user_agents() == [EXPECTED]


def test_taxii_collections_sends_user_agent(server):
    server.bodies["/v3/stix/trustgroup/collections/"] = {
        "collections": [{"id": "c1", "can_read": True}]
    }
    assert _taxii_client(server).get_collection_id("trustgroup") == "c1"
    assert server.user_agents() == [EXPECTED]


def test_taxii_objects_sends_user_agent(server):
    _taxii_client(server).get_objects("trustgroup", "c1", limit=10)
    assert server.requests[0]["path"] == "/v3/stix/trustgroup/collections/c1/objects/"
    assert server.user_agents() == [EXPECTED]


def test_hunting_sends_user_agent_on_every_page(server):
    server.bodies["/v3/hunt/live/list"] = {"result": [], "has_more": False}
    client = PolySwarmHuntingClient(server.url, "k" * 32, backoff_factor=0)
    client.list_live_hits(3600)
    assert server.requests[0]["path"] == "/v3/hunt/live/list"
    assert server.user_agents() == [EXPECTED]


def test_account_quota_sends_user_agent(server):
    server.bodies["/v3/public/accounts"] = {"result": {"daily_api_limit": 0}}
    client = PolySwarmAccountClient(server.url, "k", backoff_factor=0)
    client.account_features()
    assert server.requests[0]["path"] == "/v3/public/accounts"
    assert server.user_agents() == [EXPECTED]


def test_no_request_falls_back_to_a_library_default(server):
    server.bodies["/v3/hunt/live/list"] = {"result": [], "has_more": False}
    server.bodies["/v3/public/accounts"] = {"result": {}}
    _taxii_client(server).discovery()
    PolySwarmHuntingClient(server.url, "k" * 32).list_live_hits(60)
    PolySwarmAccountClient(server.url, "k").account_features()
    for agent in server.user_agents():
        assert agent == EXPECTED
        assert "python-requests" not in agent
        assert "polyswarm_api" not in agent
