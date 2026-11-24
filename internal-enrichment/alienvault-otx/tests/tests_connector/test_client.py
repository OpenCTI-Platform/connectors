import json
import logging
import socketserver
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from connectors_sdk.exceptions.error import DataRetrievalError
from otx_client import (
    ALLOWED_SECTIONS,
    OTX_HOSTNAME_SECTION,
    OTX_SECTIONS,
    REQUEST_TIMEOUT,
    OtxClient,
    OtxGeneral,
)
from pydantic import SecretStr

RESOURCES = Path(__file__).parent.parent / "resources"
FAKE_KEY = "fake-otx-key-for-tests"
# Every OTX call that fails with a retryable error is attempted 4 times (1 + 3 retries)
ATTEMPTS = 4


def _fixture(name: str) -> dict[str, Any]:
    return json.loads((RESOURCES / name).read_text(encoding="utf-8"))


@dataclass
class _Step:
    """One scripted answer of the fake OTX server."""

    status: int = 200
    body: Any = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    delay: float = 0.0
    raw: bytes | None = None


class _FakeOtx(ThreadingHTTPServer):
    """A 127.0.0.1 server that records requests and plays scripted answers."""

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.requests: list[dict[str, Any]] = []
        self.steps: list[_Step] = []
        self.default = _Step()
        self.release = threading.Event()

    def server_bind(self) -> None:
        """Bind without the reverse DNS lookup of `HTTPServer.server_bind` (slow offline)."""
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "127.0.0.1", self.server_address[1]

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}"

    def script(self, *steps: _Step, default: _Step | None = None) -> None:
        self.steps = list(steps)
        if default is not None:
            self.default = default

    def handle_error(self, request, client_address) -> None:
        """A client that gave up (timeout) is expected: stay quiet."""


class _Handler(BaseHTTPRequestHandler):
    server: _FakeOtx

    def do_GET(self) -> None:  # noqa: N802 (name imposed by BaseHTTPRequestHandler)
        self.server.requests.append(
            {
                "path": self.path,
                "headers": {k.lower(): v for k, v in self.headers.items()},
            }
        )
        step = self.server.steps.pop(0) if self.server.steps else self.server.default
        if step.delay:
            self.server.release.wait(step.delay)
        payload = (
            step.raw if step.raw is not None else json.dumps(step.body).encode("utf-8")
        )
        self.send_response(step.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        for name, value in step.headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args) -> None:  # noqa: A002
        """Keep the test output clean."""


@pytest.fixture
def otx() -> Iterator[_FakeOtx]:
    server = _FakeOtx()
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
    )
    thread.start()
    yield server
    server.release.set()
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


@pytest.fixture
def sleeps(monkeypatch) -> list[float]:
    """Record the waits of the urllib3 retries instead of sleeping."""
    recorded: list[float] = []
    monkeypatch.setattr("urllib3.util.retry.time.sleep", recorded.append)
    return recorded


@pytest.fixture
def make_client(otx, sleeps) -> Callable[..., OtxClient]:
    def _make(**kwargs: Any) -> OtxClient:
        return OtxClient(otx.url, SecretStr(FAKE_KEY), **kwargs)

    return _make


def test_request_timeout_should_be_60_seconds():
    # Given the default client
    client = OtxClient("https://otx.example", SecretStr(FAKE_KEY))

    # When reading the timeout
    # Then it is the documented one
    assert REQUEST_TIMEOUT == 60
    assert client._timeout == 60


def test_otx_sections_should_map_the_supported_entity_types():
    # Given the supported entity types
    # When reading the mapping
    # Then each one has its OTX section
    assert OTX_SECTIONS == {"IPv4-Addr": "IPv4", "Domain-Name": "domain", "Url": "url"}


def test_get_general_should_send_the_api_key_header(otx, make_client):
    # Given OTX answers
    otx.script(_Step(body=_fixture("general_ipv4_unknown.json")))

    # When fetching an indicator
    make_client().get_general("IPv4", "198.51.100.7")

    # Then the API key travels in the X-OTX-API-KEY header
    assert otx.requests[0]["headers"]["x-otx-api-key"] == FAKE_KEY


@pytest.mark.parametrize(
    "section, value, expected_path",
    [
        ("IPv4", "192.0.2.10", "/api/v1/indicators/IPv4/192.0.2.10/general"),
        (
            "domain",
            "malicious.example",
            "/api/v1/indicators/domain/malicious.example/general",
        ),
        (
            "hostname",
            "www.malicious.example",
            "/api/v1/indicators/hostname/www.malicious.example/general",
        ),
        (
            "hostname",
            "a/b.malicious.example",
            "/api/v1/indicators/hostname/a%2Fb.malicious.example/general",
        ),
        (
            "url",
            "http://malicious.example/a b?x=1&y=é#frag",
            "/api/v1/indicators/url/"
            "http%3A%2F%2Fmalicious.example%2Fa%20b%3Fx%3D1%26y%3D%C3%A9%23frag/general",
        ),
    ],
)
def test_get_general_should_encode_the_value_in_the_path(
    otx, make_client, section, value, expected_path
):
    # Given OTX answers
    otx.script(_Step(body={}))

    # When fetching an indicator
    make_client().get_general(section, value)

    # Then the value is one percent-encoded path segment of the section endpoint
    assert len(otx.requests) == 1
    assert otx.requests[0]["path"] == expected_path


def test_allowed_sections_should_add_hostname_to_the_entity_sections():
    # Given the sections of the entity types and the hostname fallback
    # When reading the sections the client accepts
    # Then hostname is accepted although it is the section of no entity type
    assert OTX_HOSTNAME_SECTION == "hostname"
    assert "hostname" not in OTX_SECTIONS.values()
    assert ALLOWED_SECTIONS == {"IPv4", "domain", "hostname", "url"}


@pytest.mark.parametrize("section", ["../IPv6", "IPv6", "file", "", "Hostname"])
def test_get_general_should_reject_an_unknown_section(otx, make_client, section):
    # Given a section that OTX does not serve here
    # When fetching with it
    # Then it fails before any request
    with pytest.raises(ValueError):
        make_client().get_general(section, "::1")
    assert otx.requests == []


def test_get_general_should_not_follow_a_redirect_and_keep_the_api_key_home(
    otx, make_client
):
    # Given OTX answers with a redirect to another path (it could be another host)
    otx.script(
        _Step(status=302, headers={"Location": "/elsewhere"}),
        default=_Step(body=_fixture("general_ipv4_known.json")),
    )

    # When fetching the indicator
    # Then the redirect is not followed and the call fails without leaking the key
    with pytest.raises(DataRetrievalError) as err:
        make_client().get_general("IPv4", "192.0.2.10")
    assert [request["path"] for request in otx.requests] == [
        "/api/v1/indicators/IPv4/192.0.2.10/general"
    ]
    assert "302" in str(err.value)
    assert err.value.__cause__ is not None
    assert FAKE_KEY not in str(err.value)
    assert FAKE_KEY not in str(err.value.__cause__)
    assert "/elsewhere" not in str(err.value)


@pytest.mark.parametrize(
    "fixture, section, value, pulses",
    [
        ("general_ipv4_known.json", "IPv4", "192.0.2.10", 2),
        ("general_ipv4_unknown.json", "IPv4", "198.51.100.7", 0),
        ("general_domain_known.json", "domain", "malicious.example", 1),
        ("general_domain_unknown.json", "domain", "www.malicious.example", 0),
        ("general_hostname_known.json", "hostname", "www.malicious.example", 1),
        ("general_url_known.json", "url", "http://malicious.example/payload.bin", 1),
    ],
)
def test_get_general_should_return_the_parsed_general_section(
    otx, make_client, fixture, section, value, pulses
):
    # Given OTX answers 200 with a general section
    otx.script(_Step(body=_fixture(fixture)))

    # When fetching the indicator
    general = make_client().get_general(section, value)

    # Then the parsed model is returned
    assert isinstance(general, OtxGeneral)
    assert general.pulse_info.count == pulses
    assert len(general.pulse_info.pulses) == pulses


def test_get_general_should_return_none_on_404(otx, make_client):
    # Given OTX does not find the indicator
    otx.script(_Step(status=404, body={"detail": "Not found."}))

    # When fetching it
    # Then there is no result, and no retry
    assert make_client().get_general("domain", "missing.example") is None
    assert len(otx.requests) == 1


def test_get_general_should_return_none_and_warn_on_400(otx, make_client, caplog):
    # Given OTX rejects the value
    otx.script(_Step(status=400, body={"detail": "IP is private."}))

    # When fetching it
    with caplog.at_level(logging.WARNING):
        general = make_client().get_general("IPv4", "10.0.0.1")

    # Then there is no result and a warning holds the OTX detail
    assert general is None
    assert len(otx.requests) == 1
    warnings = [
        r for r in caplog.records if r.getMessage() == "OTX rejected the indicator"
    ]
    assert len(warnings) == 1
    assert warnings[0].levelno == logging.WARNING
    assert warnings[0].attributes == {
        "section": "IPv4",
        "value": "10.0.0.1",
        "detail": "IP is private.",
    }


def test_get_general_should_warn_without_detail_when_the_400_body_has_none(
    otx, make_client, caplog
):
    # Given OTX rejects the value with a body that is not an object
    otx.script(_Step(status=400, raw=b"bad request"))

    # When fetching it
    with caplog.at_level(logging.WARNING):
        general = make_client().get_general("domain", "x")

    # Then the warning has no detail
    assert general is None
    warning = next(r for r in caplog.records if r.levelno == logging.WARNING)
    assert warning.attributes["detail"] is None


def test_get_general_should_keep_the_400_detail_of_an_invalid_domain(
    otx, make_client, caplog
):
    # Given OTX rejects an invalid domain with detail and error
    otx.script(
        _Step(
            status=400,
            body={
                "detail": "Invalid domain (x)",
                "error": "unable to parse domain or hostname",
            },
        )
    )

    # When fetching it
    with caplog.at_level(logging.WARNING):
        assert make_client().get_general("domain", "x") is None

    # Then the detail is logged
    warning = next(r for r in caplog.records if r.levelno == logging.WARNING)
    assert warning.attributes["detail"] == "Invalid domain (x)"


def test_get_general_should_wait_for_retry_after_on_429_then_succeed(
    otx, make_client, sleeps
):
    # Given OTX rate limits once, then answers
    otx.script(
        _Step(status=429, headers={"Retry-After": "2"}, body={"detail": "slow down"}),
        _Step(body=_fixture("general_ipv4_known.json")),
    )

    # When fetching the indicator
    general = make_client().get_general("IPv4", "192.0.2.10")

    # Then the call is retried after the requested wait and succeeds
    assert general is not None
    assert general.pulse_info.count == 2
    assert len(otx.requests) == 2
    assert sleeps == [2.0]


def test_get_general_should_raise_when_429_persists(otx, make_client):
    # Given OTX always rate limits
    otx.script(default=_Step(status=429, headers={"Retry-After": "1"}))

    # When fetching the indicator
    # Then it fails once the retries are exhausted
    with pytest.raises(DataRetrievalError) as err:
        make_client().get_general("IPv4", "192.0.2.10")
    assert len(otx.requests) == ATTEMPTS
    assert "429" in str(err.value)


def test_get_general_should_raise_after_the_retries_on_503(otx, make_client):
    # Given OTX is down
    otx.script(default=_Step(status=503, body={"detail": "unavailable"}))

    # When fetching the indicator
    # Then it is attempted 4 times then fails
    with pytest.raises(DataRetrievalError) as err:
        make_client().get_general("domain", "malicious.example")
    assert len(otx.requests) == ATTEMPTS
    assert "503" in str(err.value)
    assert err.value.__cause__ is not None


@pytest.mark.parametrize("status", [401, 403])
def test_get_general_should_raise_on_authentication_errors(otx, make_client, status):
    # Given OTX refuses the key
    otx.script(_Step(status=status, body={"detail": "refused"}))

    # When fetching the indicator
    # Then it fails at once, without retry
    with pytest.raises(DataRetrievalError):
        make_client().get_general("IPv4", "192.0.2.10")
    assert len(otx.requests) == 1


def test_get_general_should_retry_a_slow_answer_then_succeed(otx, make_client):
    # Given OTX is too slow once, then answers
    otx.script(
        _Step(delay=2, body={}),
        _Step(body=_fixture("general_ipv4_known.json")),
    )

    # When fetching the indicator with a short timeout
    general = make_client(timeout=0.3).get_general("IPv4", "192.0.2.10")

    # Then the timed-out GET is retried and succeeds
    assert general is not None
    assert general.pulse_info.count == 2
    assert len(otx.requests) == 2


def test_get_general_should_raise_when_every_attempt_is_too_slow(otx, make_client):
    # Given OTX never answers in time
    otx.script(default=_Step(delay=2, body={}))

    # When fetching the indicator with a short timeout
    # Then it fails once the retries are exhausted
    with pytest.raises(DataRetrievalError) as err:
        make_client(timeout=0.3).get_general("IPv4", "192.0.2.10")
    assert len(otx.requests) == ATTEMPTS
    assert err.value.__cause__ is not None


def test_get_general_should_raise_when_the_server_is_unreachable(make_client, otx):
    # Given nothing listens on the OTX address
    otx.shutdown()
    otx.server_close()

    # When fetching the indicator
    # Then the network failure becomes a DataRetrievalError
    with pytest.raises(DataRetrievalError):
        make_client().get_general("IPv4", "192.0.2.10")


@pytest.mark.parametrize(
    "step",
    [
        _Step(body={"pulse_info": "oops"}),
        _Step(body={"pulse_info": {"count": "many"}}),
        _Step(body=[]),
        _Step(raw=b"<html>not json</html>"),
        _Step(raw=b"{broken"),
    ],
)
def test_get_general_should_raise_on_an_invalid_response(otx, make_client, step):
    # Given OTX answers 200 with something that is not a general section
    otx.script(step)

    # When fetching the indicator
    # Then it fails with a DataRetrievalError
    with pytest.raises(DataRetrievalError) as err:
        make_client().get_general("IPv4", "192.0.2.10")
    assert err.value.__cause__ is not None


def test_get_general_should_never_leak_the_api_key(otx, make_client, caplog):
    # Given OTX refuses the key, rejects a value and then fails
    otx.script(
        _Step(status=400, body={"detail": "IP is private."}),
        _Step(status=401, body={"detail": "Invalid API key"}),
        _Step(status=500, body={"detail": "boom"}),
        _Step(status=500, body={"detail": "boom"}),
        _Step(status=500, body={"detail": "boom"}),
        _Step(status=500, body={"detail": "boom"}),
        _Step(body={"pulse_info": "oops"}),
    )
    client = make_client()

    # When fetching
    errors = []
    with caplog.at_level(logging.DEBUG):
        assert client.get_general("IPv4", "10.0.0.1") is None
        for value in ("192.0.2.10", "192.0.2.11", "192.0.2.12"):
            with pytest.raises(DataRetrievalError) as err:
                client.get_general("IPv4", value)
            errors.append(err.value)

    # Then the key is neither in the logs nor in the errors (nor their causes)
    assert FAKE_KEY not in caplog.text
    assert all(FAKE_KEY not in str(r.__dict__) for r in caplog.records)
    for error in errors:
        assert FAKE_KEY not in str(error)
        assert FAKE_KEY not in repr(error)
        assert FAKE_KEY not in str(error.__cause__)
    assert FAKE_KEY not in repr(client._api_key)
