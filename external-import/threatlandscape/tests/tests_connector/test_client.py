from unittest.mock import MagicMock

import pytest
import requests
import responses as resp_mock
from conftest import SAMPLE_API_ROWS, SAMPLE_STIX_BUNDLE
from threatlandscape_client.api_client import ThreatLandscapeClient


def _make_client(api_key: str = "test-key") -> ThreatLandscapeClient:
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    return ThreatLandscapeClient(
        helper=helper,
        base_url="https://api.threatlandscape.io/rest/v1",
        api_key=api_key,
    )


@resp_mock.activate
def test_get_stix_bundles_sends_apikey_header():
    """The apikey header must be present on every request."""
    resp_mock.add(
        resp_mock.GET,
        "https://api.threatlandscape.io/rest/v1/stix_bundles",
        json=SAMPLE_API_ROWS,
        status=200,
    )

    client = _make_client(api_key="my-secret-key")
    client.get_stix_bundles()

    assert resp_mock.calls[0].request.headers["apikey"] == "my-secret-key"


@resp_mock.activate
def test_get_stix_bundles_since_seq_id_param():
    """since_seq_id is translated to seq_id=gt.<value>."""
    resp_mock.add(
        resp_mock.GET,
        "https://api.threatlandscape.io/rest/v1/stix_bundles",
        json=[],
        status=200,
    )

    client = _make_client()
    client.get_stix_bundles(since_seq_id=500)

    assert "seq_id=gt.500" in resp_mock.calls[0].request.url


def test_get_stix_bundles_requires_exactly_one_cursor_or_date():
    """Providing both cursor and date filters should be rejected."""
    client = _make_client()

    with pytest.raises(ValueError, match="exactly one"):
        client.get_stix_bundles(since_seq_id=500, since_date="2026-04-01T00:00:00Z")


@resp_mock.activate
def test_get_stix_bundles_since_date_param():
    """since_date is translated to stix_published_at=gte.<value>."""
    resp_mock.add(
        resp_mock.GET,
        "https://api.threatlandscape.io/rest/v1/stix_bundles",
        json=[],
        status=200,
    )

    client = _make_client()
    client.get_stix_bundles(since_date="2026-04-01T00:00:00Z")

    assert (
        "stix_published_at=gte.2026-04-01T00%3A00%3A00Z"
        in resp_mock.calls[0].request.url
        or "stix_published_at=gte.2026-04-01T00:00:00Z"
        in resp_mock.calls[0].request.url
    )


@resp_mock.activate
def test_get_stix_bundles_source_type_filter():
    """source_type is translated to source_type=eq.<value>."""
    resp_mock.add(
        resp_mock.GET,
        "https://api.threatlandscape.io/rest/v1/stix_bundles",
        json=[],
        status=200,
    )

    client = _make_client()
    client.get_stix_bundles(source_type="darknet")

    assert "source_type=eq.darknet" in resp_mock.calls[0].request.url


@resp_mock.activate
def test_get_stix_bundles_returns_rows():
    """A 200 response body is parsed and returned as a list."""
    resp_mock.add(
        resp_mock.GET,
        "https://api.threatlandscape.io/rest/v1/stix_bundles",
        json=SAMPLE_API_ROWS,
        status=200,
    )

    client = _make_client()
    rows = client.get_stix_bundles()

    assert len(rows) == 2
    assert rows[0]["seq_id"] == 1001
    assert rows[0]["stix_bundle"] == SAMPLE_STIX_BUNDLE


@resp_mock.activate
def test_get_stix_bundles_raises_on_non_2xx():
    """A 401 response raises requests.HTTPError."""
    resp_mock.add(
        resp_mock.GET,
        "https://api.threatlandscape.io/rest/v1/stix_bundles",
        json={"message": "Invalid API key"},
        status=401,
    )

    client = _make_client()
    with pytest.raises(requests.HTTPError):
        client.get_stix_bundles()


@resp_mock.activate
def test_get_stix_bundles_pagination_offset():
    """offset is forwarded as a query parameter."""
    resp_mock.add(
        resp_mock.GET,
        "https://api.threatlandscape.io/rest/v1/stix_bundles",
        json=[],
        status=200,
    )

    client = _make_client()
    client.get_stix_bundles(page_size=50, offset=150)

    assert "offset=150" in resp_mock.calls[0].request.url
    assert "limit=50" in resp_mock.calls[0].request.url


# ---------------------------------------------------------------------------
# get_actionable_iocs
# ---------------------------------------------------------------------------


@resp_mock.activate
def test_get_actionable_iocs_sends_apikey_header():
    """The apikey header must be present on IOC requests."""
    resp_mock.add(
        resp_mock.GET,
        "https://api.threatlandscape.io/rest/v1/actionable_iocs",
        json=SAMPLE_API_ROWS,
        status=200,
    )

    client = _make_client(api_key="my-ioc-key")
    client.get_actionable_iocs()

    assert resp_mock.calls[0].request.headers["apikey"] == "my-ioc-key"


@resp_mock.activate
def test_get_actionable_iocs_since_seq_id_param():
    """since_seq_id is translated to seq_id=gt.<value>."""
    resp_mock.add(
        resp_mock.GET,
        "https://api.threatlandscape.io/rest/v1/actionable_iocs",
        json=[],
        status=200,
    )

    client = _make_client()
    client.get_actionable_iocs(since_seq_id=999)

    assert "seq_id=gt.999" in resp_mock.calls[0].request.url


@resp_mock.activate
def test_get_actionable_iocs_since_date_param():
    """since_date is translated to created_at=gte.<value>."""
    resp_mock.add(
        resp_mock.GET,
        "https://api.threatlandscape.io/rest/v1/actionable_iocs",
        json=[],
        status=200,
    )

    client = _make_client()
    client.get_actionable_iocs(since_date="2026-01-01T00:00:00Z")

    assert (
        "created_at=gte.2026-01-01T00%3A00%3A00Z" in resp_mock.calls[0].request.url
        or "created_at=gte.2026-01-01T00:00:00Z" in resp_mock.calls[0].request.url
    )


@resp_mock.activate
def test_get_actionable_iocs_returns_rows():
    """A 200 response body is parsed and returned as a list."""
    resp_mock.add(
        resp_mock.GET,
        "https://api.threatlandscape.io/rest/v1/actionable_iocs",
        json=SAMPLE_API_ROWS,
        status=200,
    )

    client = _make_client()
    rows = client.get_actionable_iocs()

    assert len(rows) == 2
    assert rows[0]["seq_id"] == 1001


@resp_mock.activate
def test_get_actionable_iocs_raises_on_non_2xx():
    """A 403 response raises requests.HTTPError."""
    resp_mock.add(
        resp_mock.GET,
        "https://api.threatlandscape.io/rest/v1/actionable_iocs",
        json={"message": "Forbidden"},
        status=403,
    )

    client = _make_client()
    with pytest.raises(requests.HTTPError):
        client.get_actionable_iocs()


@resp_mock.activate
def test_get_actionable_iocs_pagination_offset():
    """offset and limit are forwarded as query parameters."""
    resp_mock.add(
        resp_mock.GET,
        "https://api.threatlandscape.io/rest/v1/actionable_iocs",
        json=[],
        status=200,
    )

    client = _make_client()
    client.get_actionable_iocs(page_size=25, offset=75)

    assert "offset=75" in resp_mock.calls[0].request.url
    assert "limit=25" in resp_mock.calls[0].request.url
