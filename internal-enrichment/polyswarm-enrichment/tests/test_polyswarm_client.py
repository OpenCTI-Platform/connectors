"""Tests for the polyswarm_client SDK wrapper and the connector User-Agent.

Every HTTP request the connector makes to PolySwarm (SDK calls and the raw
polykg calls) must send ``PolySwarm-OpenCTI-Enrichment/<version> (OpenCTI)``.
Requests are caught at ``requests.Session.send``, so nothing reaches the
network and no API credits are spent.
"""

import io
import json

import polyswarm_api.settings
import pycti
import pytest
import requests
from polyswarm_api.api import PolyswarmAPI as SdkPolyswarmAPI
from polyswarm_enrichment.client_api import ConnectorClient
from polyswarm_enrichment.polyswarm_client import (
    USER_AGENT,
    PolyswarmAPI,
    polyswarm_headers,
)

EXPECTED_UA = f"PolySwarm-OpenCTI-Enrichment/{pycti.__version__} (OpenCTI)"
SHA256 = "a" * 64


def test_user_agent_value():
    assert USER_AGENT == EXPECTED_UA
    assert not USER_AGENT.startswith("polyswarm_api/")
    assert "python-requests" not in USER_AGENT


def test_sdk_instance_header_is_ours():
    """The SDK session sends our User-Agent, not the polyswarm_api default."""
    api = PolyswarmAPI(key="x", community="default")
    assert api.session.headers["User-Agent"] == EXPECTED_UA
    assert polyswarm_api.settings.DEFAULT_USER_AGENT.startswith("polyswarm_api/")
    # The plain SDK still has its own default: the subclass is what fixes it.
    assert (
        SdkPolyswarmAPI(key="x")
        .session.headers["User-Agent"]
        .startswith("polyswarm_api/")
    )


def test_polyswarm_headers_merges_extra():
    headers = polyswarm_headers({"Authorization": "Bearer k"})
    assert headers == {"Authorization": "Bearer k", "User-Agent": EXPECTED_UA}
    assert polyswarm_headers() == {"User-Agent": EXPECTED_UA}


def test_polyswarm_exceptions_importable():
    """polyswarm_exceptions module must be importable from polyswarm_client."""
    from polyswarm_enrichment.polyswarm_client import polyswarm_exceptions

    assert hasattr(polyswarm_exceptions, "NoResultsException")


# ---------------------------------------------------------------------------
# Every call path sends the User-Agent
# ---------------------------------------------------------------------------
class _Private:
    """Private community, so the client builds both SDK instances."""

    def __init__(self, base):
        self.__dict__.update(base.__dict__)
        self.community = "private"


@pytest.fixture()
def sent(monkeypatch):
    """Record every outgoing request and answer each with a 404."""
    # Drop the conftest stubs of exists() and account_features() so those
    # calls reach the (fake) transport too.
    monkeypatch.undo()
    captured = []

    def fake_send(self, request, **kwargs):
        captured.append(request)
        resp = requests.Response()
        resp.status_code = 404
        body = json.dumps({"result": None, "status": "NOT_FOUND"}).encode()
        resp._content = body
        resp.raw = io.BytesIO(body)
        resp.headers["Content-Type"] = "application/json"
        resp.request = request
        resp.url = request.url
        return resp

    monkeypatch.setattr(requests.Session, "send", fake_send)
    return captured


@pytest.fixture()
def client(sent, stub_helper, stub_config):
    c = ConnectorClient(stub_helper, _Private(stub_config))
    assert c.polyswarm_default is not None
    return c


def _assert_all_ours(sent):
    assert sent, "expected at least one HTTP request"
    for request in sent:
        assert request.headers.get("User-Agent") == EXPECTED_UA, request.url


def test_startup_requests_send_user_agent(client, sent):
    """Access check (HEAD per community) and the polykg connectivity check."""
    urls = [r.url for r in sent]
    assert any("fake-polykg" in u for u in urls)
    assert sum(r.method == "HEAD" for r in sent) == 2
    _assert_all_ours(sent)


def test_both_sdk_instances_send_user_agent(client):
    for api in (client.polyswarm, client.polyswarm_default):
        assert api.session.headers["User-Agent"] == EXPECTED_UA


SDK_CALLS = {
    "hash_search": lambda api: list(api.search(SHA256)),
    "url_search": lambda api: list(api.search_url("http://example.test/")),
    "metadata_search": lambda api: list(
        api.search_by_metadata("artifact.sha256:" + SHA256)
    ),
    "iocs_by_hash": lambda api: api.iocs_by_hash(
        "sha256", SHA256, hide_known_good=True
    ),
    "tag_link": lambda api: api.tag_link_get(SHA256),
    "rescan": lambda api: api.rescan(SHA256, hash_type="sha256"),
    "rescan_wait": lambda api: api.wait_for(12345, timeout=0),
    "download": lambda api: api.download_to_handle(
        SHA256, io.BytesIO(), hash_type="sha256"
    ),
    "yara_hunt_list": lambda api: list(api.historical_list(since=60)),
    "yara_hunt_get": lambda api: api.historical_get(hunt=1),
    "yara_hunt_results": lambda api: list(api.historical_results(hunt=1)),
    "yara_hunt_result": lambda api: api.historical_result(1),
    "account_quota": lambda api: api.account_features(),
}


@pytest.mark.parametrize("instance", ["polyswarm", "polyswarm_default"])
@pytest.mark.parametrize("call", sorted(SDK_CALLS))
def test_sdk_call_sends_user_agent(client, sent, instance, call):
    sent.clear()
    try:
        SDK_CALLS[call](getattr(client, instance))
    except Exception:  # noqa: BLE001 - the fake 404 only matters for headers
        pass
    _assert_all_ours(sent)


POLYKG_CALLS = {
    "connectivity": lambda c: c._check_polykg_connectivity(),
    "profile": lambda c: c.get_profile("Emotet"),
    "has_profiles": lambda c: c.has_profiles(),
    "attack_patterns": lambda c: c.fetch_attack_patterns(),
}


@pytest.mark.parametrize("call", sorted(POLYKG_CALLS))
def test_polykg_call_sends_user_agent(client, sent, call):
    sent.clear()
    POLYKG_CALLS[call](client)
    _assert_all_ours(sent)
    for request in sent:
        assert request.headers.get("Authorization", "").startswith("Bearer ")


def test_client_lookups_send_user_agent(client, sent):
    """The client's own lookup methods, end to end through the SDK."""
    sent.clear()
    client.query_polyswarm(SHA256)
    client.download_sample({"sha256": SHA256, "community": "default"})
    _assert_all_ours(sent)
