"""Tests for avoiding repeated source index requests during recovery."""

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from connector.api_client import DeferredPostWindow, PostBatch, RansomLookAPIError

from .test_connector import make_connector


def window_record(start="2026-01-01", end="2026-01-01"):
    return {"status": "pending", "start": start, "end": end}


def test_successful_matching_deferred_window_fetches_index_once():
    connector = make_connector(enrich_actor_profiles=False)
    connector.client._get = MagicMock(return_value={"posts": []})
    start = datetime(2026, 1, 1, 6, tzinfo=timezone.utc)
    end = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)

    cycle = connector._collect_cycle(
        start, end, {}, deferred_windows={"old": window_record()}
    )

    connector.client._get.assert_called_once_with(
        "posts", params={"from": "2026-01-01", "to": "2026-01-01"}
    )
    assert cycle.resolved_deferred_keys == {"old"}
    assert cycle.deferred_windows == []


def test_populated_matching_window_preserves_records_when_budget_is_full():
    connector = make_connector(
        enrich_actor_profiles=False,
        import_torrents=False,
        import_leaks=False,
        import_analyses=False,
        max_records_per_endpoint=1,
    )
    post = {
        "group_name": "group",
        "post_title": "victim",
        "discovered": "2026-01-01T10:00:00Z",
    }
    connector.client._get = MagicMock(return_value={"posts": [post]})
    connector.client.get_group = MagicMock(return_value=({}, []))
    connector.client.get_post = MagicMock(return_value={"description": "detail"})
    start = datetime(2026, 1, 1, 6, tzinfo=timezone.utc)
    end = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)

    cycle = connector._collect_cycle(
        start, end, {}, deferred_windows={"old": window_record()}
    )

    assert connector.client._get.call_count == 1
    assert connector.metrics.fetched_posts == 1
    assert len([obj for obj in cycle.claims if obj.type == "report"]) == 1
    assert cycle.resolved_deferred_keys == {"old"}
    assert not cycle.deferred_windows


def test_matching_retry_preserves_identity_for_a_corrected_timestamp():
    connector = make_connector(
        enrich_actor_profiles=False,
        import_torrents=False,
        import_leaks=False,
        import_analyses=False,
    )
    post = {
        "group_name": "group",
        "post_title": "victim",
        "discovered": "2026-01-01T10:00:00Z",
    }
    old = "2026-01-01T09:00:00+00:00"
    route = connector._claim_state_key(connector.converter.claim_route_identity(post))
    occurrence = connector._claim_state_key(old)
    registry = {
        route: {
            "occurrences": {
                occurrence: {
                    "identity_discovered": old,
                    "last_seen": old,
                    "aliases": [old],
                    "source_ids": [],
                }
            }
        }
    }
    connector.client._get = MagicMock(return_value={"posts": [post]})
    connector.client.get_group = MagicMock(return_value=({}, []))
    connector.client.get_post = MagicMock(return_value={"description": "detail"})
    start = datetime(2026, 1, 1, 6, tzinfo=timezone.utc)
    end = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)

    cycle = connector._collect_cycle(
        start,
        end,
        {},
        deferred_windows={"old": window_record()},
        route_registry=registry,
    )

    assert connector.client._get.call_count == 1
    assert list(cycle.route_registry_updates[route]["occurrences"]) == [occurrence]


def test_matching_window_still_processes_reserved_pending_claims():
    connector = make_connector(
        enrich_actor_profiles=False,
        import_torrents=False,
        import_leaks=False,
        import_analyses=False,
        max_records_per_endpoint=2,
    )
    post = {
        "group_name": "group",
        "post_title": "new victim",
        "discovered": "2026-01-01T10:00:00Z",
    }
    pending = {
        "status": "pending",
        "group_name": "group",
        "post_title": "pending victim",
        "discovered": "2025-12-20T10:00:00Z",
    }
    connector.client._get = MagicMock(return_value={"posts": [post]})
    connector.client.get_group = MagicMock(return_value=({}, []))
    connector.client.get_post = MagicMock(return_value={"description": "detail"})
    start = datetime(2026, 1, 1, 6, tzinfo=timezone.utc)
    end = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)

    cycle = connector._collect_cycle(
        start,
        end,
        {},
        pending_claims={"pending": pending},
        deferred_windows={"old": window_record()},
    )

    assert connector.client._get.call_count == 1
    assert len([obj for obj in cycle.claims if obj.type == "report"]) == 2
    assert not cycle.incomplete_claims
    assert not cycle.deferred_windows


def test_partial_matching_window_still_fetches_normal_window():
    connector = make_connector(enrich_actor_profiles=False)
    child = DeferredPostWindow("2026-01-01", "2026-01-01", "limit")
    connector.client.get_posts = MagicMock(
        side_effect=[PostBatch([], [child]), PostBatch([], [])]
    )
    day = datetime(2026, 1, 1, tzinfo=timezone.utc)

    cycle = connector._collect_cycle(
        day, day, {}, deferred_windows={"old": window_record()}
    )

    assert connector.client.get_posts.call_count == 2
    assert cycle.resolved_deferred_keys == {"old"}
    assert len(cycle.deferred_windows) == 1


def test_different_deferred_window_does_not_skip_normal_window():
    connector = make_connector(enrich_actor_profiles=False)
    connector.client._get = MagicMock(return_value={"posts": []})
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    end = datetime(2026, 1, 2, tzinfo=timezone.utc)

    connector._collect_cycle(start, end, {}, deferred_windows={"old": window_record()})

    assert connector.client._get.call_count == 2
    assert connector.client._get.call_args_list[1].kwargs["params"] == {
        "from": "2026-01-01",
        "to": "2026-01-02",
    }


def test_deferred_request_failure_is_propagated():
    connector = make_connector(enrich_actor_profiles=False)
    connector.client._get = MagicMock(side_effect=RansomLookAPIError("failure"))
    day = datetime(2026, 1, 1, tzinfo=timezone.utc)

    with pytest.raises(RansomLookAPIError, match="failure"):
        connector._collect_cycle(
            day, day, {}, deferred_windows={"old": window_record()}
        )


def test_invalid_window_is_not_hidden_by_a_successful_retry():
    connector = make_connector(enrich_actor_profiles=False)
    connector.client._get = MagicMock(return_value={"posts": []})
    start = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
    end = datetime(2026, 1, 1, 6, tzinfo=timezone.utc)

    with pytest.raises(RansomLookAPIError, match="start is after"):
        connector._collect_cycle(
            start, end, {}, deferred_windows={"old": window_record()}
        )
