"""Every HTTP call the connector makes to PolySwarm carries its own User-Agent.

The transport (``HTTPAdapter.send``) is replaced with a recorder that answers
404, so no request leaves the process and no credits are spent. Each test
drives one client call path and asserts on the headers actually sent.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pycti
import pytest
import requests
from connector.polyswarm import USER_AGENT, PolyswarmAPI
from connector.polyswarm_client import PolySwarmClient
from connector.stix_builder import StixBuilder
from requests.adapters import HTTPAdapter

from tests.conftest import StubHelper

EXPECTED_UA = f"PolySwarm-OpenCTI-Sandbox/{pycti.__version__} (OpenCTI)"
API_URL = "https://api.polyswarm.network/v3"


def _response(request, status=404, body=b'{"status": "NOT_FOUND"}'):
    resp = requests.Response()
    resp.status_code = status
    resp._content = body
    resp.headers["Content-Type"] = "application/json"
    resp.request = request
    resp.url = request.url
    return resp


@pytest.fixture
def sent():
    """Record every outgoing request at the transport layer and answer 404."""
    calls = []

    def _send(adapter, request, **kwargs):
        calls.append(request)
        if request.url.endswith("/report.pdf"):
            return _response(request, 200, b"%PDF-1.4 fake")
        return _response(request)

    with patch.object(HTTPAdapter, "send", _send):
        yield calls


@pytest.fixture
def client():
    with patch("connector.polyswarm_client.time.sleep"):
        yield PolySwarmClient(
            api_key="test-key",
            api_url=API_URL,
            community="default",
            timeout=5,
            helper=StubHelper(),
        )


def _assert_ua(calls, path_fragment):
    matching = [r for r in calls if path_fragment in r.url]
    assert matching, f"no request to {path_fragment}; sent {[r.url for r in calls]}"
    for request in calls:
        assert request.headers["User-Agent"] == EXPECTED_UA, request.url


def test_user_agent_constant():
    assert USER_AGENT == EXPECTED_UA
    assert "polyswarm_api" not in USER_AGENT


def test_sdk_session_header_is_ours_not_library_default(client):
    plain = PolyswarmAPI(key="test-key", uri=API_URL)
    assert plain.session.headers["User-Agent"].startswith("polyswarm_api/")
    assert client.api.session.headers["User-Agent"] == EXPECTED_UA


def test_retry_session_header_is_ours(client):
    assert client._session.headers["User-Agent"] == EXPECTED_UA


def test_file_scan_submit(client, sent):
    client.submit_file_async(b"MZ test", "sample.exe")
    _assert_ua(sent, "/instance")


def test_file_sandbox_submit(client, sent):
    client.submit_sandbox_async(b"MZ test", "sample.exe")
    _assert_ua(sent, "/sandbox")


def test_url_sandbox_submit(client, sent):
    client.submit_sandbox_url_async("https://example.com/")
    _assert_ua(sent, "/sandbox")


def test_scan_result_poll(client, sent):
    client.get_scan_results("123456")
    _assert_ua(sent, "/submission")


def test_sandbox_task_poll(client, sent):
    client.get_sandbox_results("654321")
    _assert_ua(sent, "/sandbox")


def test_sandbox_providers(client, sent):
    client.get_available_providers()
    _assert_ua(sent, "/sandbox")


def test_llm_report_create_and_get(client, sent):
    client.create_llm_report(instance_id="123456")
    client.collect_llm_report("789", timeout=0, poll_interval=0)
    _assert_ua(sent, "/llm")


def test_pdf_report_create(client, sent):
    client.generate_pdf("123456", "scan")
    _assert_ua(sent, "/report")


def test_pdf_download(client, sent):
    client.api.report_create = MagicMock(return_value=SimpleNamespace(id="r1"))
    client.api.report_wait_for = MagicMock(
        return_value=SimpleNamespace(
            state="SUCCEEDED", url="https://reports.polyswarm.test/report.pdf"
        )
    )
    assert client.generate_pdf("654321", "sandbox") == b"%PDF-1.4 fake"
    _assert_ua(sent, "/report.pdf")


def test_polykg_profile(sent):
    StixBuilder._POLYKG_CIRCUIT_OPEN = False
    StixBuilder._POLYKG_CIRCUIT_OPENED_AT = None
    builder = StixBuilder(
        helper=MagicMock(),
        polykg_api_url="https://polykg.polyswarm.test",
        polyswarm_api_key="test-key",
    )
    builder._fetch_polykg_profile("DTrack")
    _assert_ua(sent, "/v3/kg/profile")
    assert sent[0].headers["Authorization"] == "Bearer test-key"
