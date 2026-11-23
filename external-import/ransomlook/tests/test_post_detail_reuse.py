"""Regression tests for reusing repeated claim detail within a collection run."""

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from connector.api_client import RansomLookAPIError

from .test_connector import make_connector


def setup_connector(posts, history=None):
    connector = make_connector(
        enrich_actor_profiles=False,
        import_post_evidence=False,
        import_torrents=False,
        import_leaks=False,
        import_analyses=False,
    )
    connector.client.get_posts = MagicMock(return_value=posts)
    connector.client.get_group = MagicMock(return_value=({}, history or []))
    return connector


def collect(connector):
    return connector._collect_cycle(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 6, tzinfo=timezone.utc),
        {},
    )


def row(title, hour):
    return {
        "group_name": "akira",
        "post_title": title,
        "discovered": f"2026-01-02T0{hour}:00:00Z",
    }


def test_reuses_detail_and_preserves_occurrences_even_at_request_limit():
    posts = [row("Repeated Victim", 1), row("Other", 2), row("Repeated Victim", 3)]
    history = [
        {**posts[0], "website": "https://one.example"},
        {**posts[2], "website": "https://two.example"},
    ]
    connector = setup_connector(posts, history)
    build_graph = MagicMock(wraps=connector._create_claim_graph)
    connector._create_claim_graph = build_graph

    def use_remaining_budget(*_args):
        connector.client.request_attempts = connector.client.max_requests_per_run
        return {"description": "shared detail"}

    connector.client.get_post = MagicMock(side_effect=use_remaining_budget)
    cycle = collect(connector)

    connector.client.get_post.assert_called_once_with("akira", "Repeated Victim")
    reports = [item for item in cycle.claims if item.type == "report"]
    assert len(reports) == 2
    assert len({report.id for report in reports}) == 2
    created_posts = [call.args[1] for call in build_graph.call_args_list]
    assert [post["website"] for post in created_posts] == [
        "https://one.example",
        "https://two.example",
    ]
    assert all(post["description"] == "shared detail" for post in created_posts)
    assert [item["post_title"] for item in cycle.incomplete_claims.values()] == [
        "Other"
    ]
    assert [item["reasons"] for item in cycle.incomplete_claims.values()] == [
        ["request-budget"]
    ]


def test_failed_and_empty_details_are_not_cached_and_success_is_reused():
    posts = [row("Repeated Victim", hour) for hour in (1, 2, 3, 4)]
    connector = setup_connector(posts)
    connector.client.get_post = MagicMock(
        side_effect=[RansomLookAPIError("temporary"), {}, {"description": "recovered"}]
    )

    cycle = collect(connector)

    assert connector.client.get_post.call_count == 3
    assert len(cycle.incomplete_claims) == 2
    assert all(
        item["reasons"] == ["detail"] for item in cycle.incomplete_claims.values()
    )
    assert len([item for item in cycle.claims if item.type == "report"]) == 4


@pytest.mark.parametrize("limiting_bound", ["response", "cache"])
def test_oversized_detail_is_not_retained(limiting_bound):
    posts = [row("Repeated Victim", hour) for hour in (1, 2)]
    connector = setup_connector(posts)
    if limiting_bound == "response":
        connector.client.max_response_bytes = 64
    else:
        connector.POST_DETAIL_CACHE_MAX_BYTES = 64
    connector.client.get_post = MagicMock(return_value={"description": "x" * 100})

    cycle = collect(connector)

    assert connector.client.get_post.call_count == 2
    assert not cycle.incomplete_claims


def test_detail_reuse_is_scoped_to_group_and_collection_run():
    posts = [row("Repeated Victim", hour) for hour in (1, 2)]
    posts += [{**post, "group_name": "other"} for post in posts]
    connector = setup_connector(posts)
    connector.client.get_post = MagicMock(
        side_effect=lambda group, _title: {"description": group}
    )

    first = collect(connector)
    second = collect(connector)

    assert connector.client.get_post.call_args_list == [
        (("akira", "Repeated Victim"), {}),
        (("other", "Repeated Victim"), {}),
        (("akira", "Repeated Victim"), {}),
        (("other", "Repeated Victim"), {}),
    ]
    for cycle in (first, second):
        assert len([item for item in cycle.claims if item.type == "report"]) == 4
        assert not cycle.incomplete_claims
