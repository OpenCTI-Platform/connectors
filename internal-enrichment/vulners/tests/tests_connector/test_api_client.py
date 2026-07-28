import re

from vulners_client.api_client import VulnersClient

_USER_AGENT_RE = re.compile(
    r"^Vulners OpenCTI Connector \S+ \(Vulners Python API \S+\)$"
)


def test_client_sets_identifying_user_agent():
    """The underlying HTTP client's User-Agent identifies the connector to Vulners."""
    client = VulnersClient("dummy-key")

    user_agent = client._api._client.headers["User-Agent"]

    assert _USER_AGENT_RE.match(user_agent) is not None
    assert "Vulners" in user_agent
