import re

from vulners_client.api_client import VulnersClient, _distribution_version

_USER_AGENT_RE = re.compile(
    r"^Vulners OpenCTI Connector \S+ \(Vulners Python API \S+\)$"
)


class _FakeHttpClient:
    """Stand-in for the SDK's underlying httpx.Client, exposing only `.headers`."""

    def __init__(self) -> None:
        # Pre-seeded with a fake default UA, as the real SDK would set one.
        self.headers = {"User-Agent": "Vulners Python API 0.0.0"}


class _FakeVulnersApi:
    """Stand-in for `vulners.VulnersApi`, exposing only what the client touches."""

    def __init__(self, api_key: str, server_url: str) -> None:
        self.api_key = api_key
        self.server_url = server_url
        self._client = _FakeHttpClient()


def test_client_sets_identifying_user_agent(monkeypatch):
    """The underlying HTTP client's User-Agent identifies the connector to Vulners."""
    monkeypatch.setattr("vulners_client.api_client.VulnersApi", _FakeVulnersApi)

    client = VulnersClient("dummy-key")

    user_agent = client._api._client.headers["User-Agent"]

    assert _USER_AGENT_RE.match(user_agent) is not None
    assert "Vulners" in user_agent


def test_distribution_version_falls_back_to_unknown():
    """A missing distribution must not break User-Agent construction."""
    assert (
        _distribution_version("definitely-not-an-installed-distribution") == "unknown"
    )
