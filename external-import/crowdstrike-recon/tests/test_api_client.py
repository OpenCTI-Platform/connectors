from unittest.mock import MagicMock

import pytest
from crowdstrike_client.api_client import CrowdstrikeReconClient


def _client(filter_topic="", filter_type="", filter_priority=""):
    """Build a client without constructing the real falconpy Recon object."""
    client = CrowdstrikeReconClient.__new__(CrowdstrikeReconClient)
    client.helper = MagicMock()
    client.filter_topic = filter_topic
    client.filter_type = filter_type
    client.filter_priority = filter_priority
    client.cs = MagicMock()
    return client


def test_build_fql_filter_combines_fields():
    client = _client(filter_topic="SA_BRAND", filter_priority="high,medium")

    fql = client._build_fql_filter(from_date="2026-05-01T00:00:00Z")

    assert "topic:['SA_BRAND']" in fql
    assert "priority:['high','medium']" in fql
    assert "created_date:>'2026-05-01T00:00:00Z'" in fql
    assert "+" in fql


def test_build_fql_filter_escapes_single_quotes():
    client = _client(filter_topic="a'b")

    fql = client._build_fql_filter(from_date="2026-05-01T00:00:00Z")

    # The single quote in the value must be escaped so it cannot break out of
    # (or inject into) the FQL string.
    assert "topic:['a\\'b']" in fql


def test_build_fql_filter_only_created_date_when_no_filters():
    client = _client()

    fql = client._build_fql_filter(from_date="2026-05-01T00:00:00Z")

    assert fql == "created_date:>'2026-05-01T00:00:00Z'"


def test_raise_for_status_raises_on_error():
    client = _client()

    with pytest.raises(RuntimeError):
        client._raise_for_status(
            {"status_code": 403, "body": {"errors": ["forbidden"]}}, "query"
        )


def test_raise_for_status_passes_on_success():
    client = _client()

    # Should not raise
    client._raise_for_status({"status_code": 200, "body": {}}, "query")


def test_query_notifications_paginates_and_stops_on_total():
    client = _client()
    page1 = {
        "status_code": 200,
        "body": {
            "resources": [f"id-{i}" for i in range(100)],
            "meta": {"pagination": {"total": 150}},
        },
    }
    page2 = {
        "status_code": 200,
        "body": {
            "resources": [f"id-{i}" for i in range(100, 150)],
            "meta": {"pagination": {"total": 150}},
        },
    }
    client.cs.query_notifications.side_effect = [page1, page2]

    ids = client.query_notifications(from_date="2026-05-01T00:00:00Z")

    assert len(ids) == 150
    assert client.cs.query_notifications.call_count == 2


def test_query_notifications_stops_on_short_page():
    client = _client()
    client.cs.query_notifications.return_value = {
        "status_code": 200,
        "body": {"resources": ["a", "b"], "meta": {"pagination": {"total": 999}}},
    }

    ids = client.query_notifications(from_date="2026-05-01T00:00:00Z")

    # A page shorter than the limit means there is no next page.
    assert ids == ["a", "b"]
    assert client.cs.query_notifications.call_count == 1


def test_query_notifications_empty_first_page():
    client = _client()
    client.cs.query_notifications.return_value = {
        "status_code": 200,
        "body": {"resources": [], "meta": {"pagination": {"total": 0}}},
    }

    ids = client.query_notifications(from_date="2026-05-01T00:00:00Z")

    assert ids == []
    assert client.cs.query_notifications.call_count == 1


def test_query_notifications_stops_on_total_with_full_pages():
    client = _client()
    page1 = {
        "status_code": 200,
        "body": {
            "resources": [f"id-{i}" for i in range(100)],
            "meta": {"pagination": {"total": 200}},
        },
    }
    page2 = {
        "status_code": 200,
        "body": {
            "resources": [f"id-{i}" for i in range(100, 200)],
            "meta": {"pagination": {"total": 200}},
        },
    }
    client.cs.query_notifications.side_effect = [page1, page2]

    ids = client.query_notifications(from_date="2026-05-01T00:00:00Z")

    # Both pages are full (== limit), so the loop stops on the reported total.
    assert len(ids) == 200
    assert client.cs.query_notifications.call_count == 2


def test_query_notifications_missing_total_continues_until_short_page():
    client = _client()
    full = {
        "status_code": 200,
        "body": {"resources": [f"id-{i}" for i in range(100)], "meta": {}},
    }
    short = {"status_code": 200, "body": {"resources": ["last"], "meta": {}}}
    client.cs.query_notifications.side_effect = [full, short]

    ids = client.query_notifications(from_date="2026-05-01T00:00:00Z")

    # A missing/zero total must not stop pagination after a full first page.
    assert len(ids) == 101
    assert client.cs.query_notifications.call_count == 2


def test_query_notifications_raises_on_api_error():
    client = _client()
    client.cs.query_notifications.return_value = {
        "status_code": 401,
        "body": {"errors": ["unauthorized"]},
    }

    with pytest.raises(RuntimeError):
        client.query_notifications(from_date="2026-05-01T00:00:00Z")


def test_get_notifications_details_batches_requests():
    client = _client()
    client.cs.get_notifications_detailed.return_value = {
        "status_code": 200,
        "body": {"resources": [{"notification": {"id": "x"}}]},
    }
    ids = [f"id-{i}" for i in range(250)]

    details = client.get_notifications_details(ids)

    # 250 ids chunked by 100 -> 3 requests
    assert client.cs.get_notifications_detailed.call_count == 3
    assert len(details) == 3
