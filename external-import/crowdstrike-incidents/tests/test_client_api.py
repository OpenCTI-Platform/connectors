"""Tests for the CrowdStrike Alerts API client."""

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from crowdstrike_incidents.client_api import (
    MAX_WINDOW,
    USER_AGENT,
    CrowdstrikeAlertsClient,
    CrowdstrikeApiError,
    timestamp_sort_key,
)


def _alert(index: int, updated: str) -> dict:
    return {"composite_id": f"alert-{index}", "updated_timestamp": updated}


def _ok(resources: list) -> dict:
    return {"status_code": 200, "body": {"resources": resources, "errors": []}}


class FakeAlerts:
    """In-memory stand-in for falconpy.Alerts, sorted by updated_timestamp."""

    def __init__(self, alerts: list[dict]) -> None:
        self.alerts = sorted(alerts, key=lambda a: a["updated_timestamp"])
        self.queries: list[dict] = []
        self.query_alerts_v2 = MagicMock(side_effect=self._query)
        self.get_alerts_v2 = MagicMock(side_effect=self._get)
        self.on_get = None

    def _query(self, filter, sort, limit, offset, include_hidden):  # noqa: A002
        self.queries.append(
            {"filter": filter, "sort": sort, "limit": limit, "offset": offset}
        )
        since = filter.split("updated_timestamp:>='")[1].rstrip("'")
        matching = [a for a in self.alerts if a["updated_timestamp"] >= since]
        return _ok([a["composite_id"] for a in matching[offset : offset + limit]])

    def _get(self, composite_ids, include_hidden):
        if self.on_get:
            self.on_get(self)
        by_id = {a["composite_id"]: a for a in self.alerts}
        # The API does not guarantee the order of the entities
        return _ok([by_id[i] for i in reversed(composite_ids)])


@pytest.fixture
def make_client(mocker):
    def _make(
        alerts: list[dict],
        page_size: int = 2,
        now: datetime = datetime(2030, 1, 1, tzinfo=timezone.utc),
    ) -> tuple:
        fake = FakeAlerts(alerts)
        alerts_cls = mocker.patch(
            "crowdstrike_incidents.client_api.Alerts", return_value=fake
        )
        client = CrowdstrikeAlertsClient(
            base_url="https://api.example.org",
            client_id="synthetic-id",
            client_secret="synthetic-secret",
            page_size=page_size,
            now=lambda: now,
        )
        return client, fake, alerts_cls

    return _make


def _ids(pages) -> list[list[str]]:
    return [[a["composite_id"] for a in page.alerts] for page in pages]


def test_falconpy_is_configured(make_client):
    _, _, alerts_cls = make_client([])

    alerts_cls.assert_called_once_with(
        client_id="synthetic-id",
        client_secret="synthetic-secret",
        base_url="https://api.example.org",
        user_agent=USER_AGENT,
    )


def test_query_filter_and_sort(make_client):
    client, fake, _ = make_client([_alert(1, "2025-01-01T00:00:01Z")])

    list(client.iter_alert_pages(since="2025-01-01T00:00:00Z", products=["ngsiem"]))

    assert fake.queries[0] == {
        "filter": "product:['ngsiem']+updated_timestamp:>='2025-01-01T00:00:00Z'",
        "sort": "updated_timestamp|asc",
        "limit": 2,
        "offset": 0,
    }


def test_include_hidden_is_forwarded(make_client):
    client, fake, _ = make_client([_alert(1, "2025-01-01T00:00:01Z")])

    list(
        client.iter_alert_pages(
            since="2025-01-01T00:00:00Z", products=["ngsiem"], include_hidden=True
        )
    )

    assert fake.query_alerts_v2.call_args.kwargs["include_hidden"] is True
    assert fake.get_alerts_v2.call_args.kwargs["include_hidden"] is True


def test_pages_are_sorted_and_cursor_advances(make_client):
    client, fake, _ = make_client(
        [
            _alert(1, "2025-01-01T00:00:01Z"),
            _alert(2, "2025-01-01T00:00:02Z"),
            _alert(3, "2025-01-01T00:00:03Z"),
            _alert(4, "2025-01-01T00:00:04Z"),
            _alert(5, "2025-01-01T00:00:05Z"),
        ]
    )

    pages = list(
        client.iter_alert_pages(since="2025-01-01T00:00:00Z", products=["ngsiem"])
    )

    # The inclusive cursor re-returns the boundary alert, which is filtered out:
    # every alert is yielded exactly once, oldest first.
    assert [i for page in _ids(pages) for i in page] == [
        "alert-1",
        "alert-2",
        "alert-3",
        "alert-4",
        "alert-5",
    ]
    # Keyset pagination: every query restarts at offset 0 from the last cursor
    assert all(q["offset"] == 0 for q in fake.queries)
    assert "'2025-01-01T00:00:02Z'" in fake.queries[1]["filter"]


def test_boundary_alerts_are_not_yielded_twice(make_client):
    client, _, _ = make_client(
        [
            _alert(1, "2025-01-01T00:00:01Z"),
            _alert(2, "2025-01-01T00:00:02Z"),
            _alert(3, "2025-01-01T00:00:02Z"),
            _alert(4, "2025-01-01T00:00:03Z"),
        ]
    )

    pages = list(
        client.iter_alert_pages(since="2025-01-01T00:00:00Z", products=["ngsiem"])
    )

    flat = [i for page in _ids(pages) for i in page]
    assert sorted(flat) == ["alert-1", "alert-2", "alert-3", "alert-4"]
    assert len(flat) == len(set(flat))


def test_full_page_with_identical_timestamps_falls_back_to_offset(make_client):
    same = "2025-01-01T00:00:01Z"
    client, fake, _ = make_client(
        [_alert(i, same) for i in range(1, 6)] + [_alert(6, "2025-01-01T00:00:02Z")]
    )

    pages = list(client.iter_alert_pages(since=same, products=["ngsiem"]))

    flat = [i for page in _ids(pages) for i in page]
    assert sorted(flat) == [f"alert-{i}" for i in range(1, 7)]
    assert len(flat) == len(set(flat))
    assert any(q["offset"] > 0 for q in fake.queries)


def test_too_many_alerts_with_the_same_timestamp_raise(make_client, mocker):
    mocker.patch("crowdstrike_incidents.client_api.MAX_WINDOW", 4)
    same = "2025-01-01T00:00:01Z"
    client, _, _ = make_client([_alert(i, same) for i in range(1, 10)])

    with pytest.raises(CrowdstrikeApiError, match="same updated_timestamp"):
        list(client.iter_alert_pages(since=same, products=["ngsiem"]))


def test_empty_result(make_client):
    client, fake, _ = make_client([])

    assert (
        list(client.iter_alert_pages(since="2025-01-01T00:00:00Z", products=["ngsiem"]))
        == []
    )
    fake.get_alerts_v2.assert_not_called()


def test_consumer_can_stop_early(make_client):
    client, fake, _ = make_client(
        [_alert(i, f"2025-01-01T00:00:0{i}Z") for i in range(1, 7)]
    )

    pages = client.iter_alert_pages(since="2025-01-01T00:00:00Z", products=["ngsiem"])
    next(pages)
    pages.close()

    assert len(fake.queries) == 1


@pytest.mark.parametrize("status_code", [401, 403, 429, 500])
def test_api_errors_raise(make_client, status_code):
    client, fake, _ = make_client([])
    fake.query_alerts_v2.side_effect = None
    fake.query_alerts_v2.return_value = {
        "status_code": status_code,
        "body": {"resources": [], "errors": [{"code": status_code, "message": "boom"}]},
    }

    with pytest.raises(CrowdstrikeApiError) as error:
        list(client.iter_alert_pages(since="2025-01-01T00:00:00Z", products=["ngsiem"]))

    assert error.value.status_code == status_code
    assert "boom" in str(error.value)


def test_forbidden_error_mentions_the_required_scope(make_client):
    client, fake, _ = make_client([])
    fake.query_alerts_v2.side_effect = None
    fake.query_alerts_v2.return_value = {
        "status_code": 403,
        "body": {"resources": [], "errors": [{"code": 403, "message": "denied"}]},
    }

    with pytest.raises(CrowdstrikeApiError, match="Alerts: Read"):
        list(client.iter_alert_pages(since="2025-01-01T00:00:00Z", products=["ngsiem"]))


def test_default_page_size_respects_the_api_window():
    assert CrowdstrikeAlertsClient.DEFAULT_PAGE_SIZE <= MAX_WINDOW


@pytest.mark.parametrize(
    "earlier, later",
    [
        ("2025-01-01T00:00:56.5897592Z", "2025-01-01T00:00:56.589759201Z"),
        ("2025-01-01T00:00:56.1Z", "2025-01-01T00:00:56.123Z"),
        ("2025-01-01T00:00:56Z", "2025-01-01T00:00:56.000000001Z"),
        ("2025-01-01T00:00:56.999999999Z", "2025-01-01T00:00:57Z"),
    ],
)
def test_timestamp_sort_key_handles_variable_precision(earlier, later):
    assert timestamp_sort_key(earlier) < timestamp_sort_key(later)


def test_pages_carry_the_cursor_and_boundary_ids(make_client):
    client, _, _ = make_client(
        [
            _alert(1, "2025-01-01T00:00:01Z"),
            _alert(2, "2025-01-01T00:00:02Z"),
            _alert(3, "2025-01-01T00:00:02Z"),
        ],
        page_size=3,
    )

    (page,) = list(
        client.iter_alert_pages(since="2025-01-01T00:00:00Z", products=["ngsiem"])
    )

    assert page.cursor == "2025-01-01T00:00:02Z"
    assert page.boundary_ids == {"alert-2", "alert-3"}


def test_skip_ids_are_not_yielded_again(make_client):
    client, _, _ = make_client(
        [_alert(1, "2025-01-01T00:00:01Z"), _alert(2, "2025-01-01T00:00:02Z")]
    )

    pages = list(
        client.iter_alert_pages(
            since="2025-01-01T00:00:01Z", products=["ngsiem"], skip_ids=["alert-1"]
        )
    )

    assert _ids(pages) == [["alert-2"]]


def test_alert_updated_after_the_query_does_not_skip_alerts(make_client):
    """Regression: an update between the ID query and the detail call must not
    move the cursor past alerts that were not fetched yet."""
    alerts = [_alert(i, f"2025-01-01T00:00:0{i}Z") for i in range(10)]
    client, fake, _ = make_client(
        alerts,
        page_size=3,
        # The query runs at 00:05:20: the cursor may only advance up to 00:00:20
        now=datetime(2025, 1, 1, 0, 5, 20, tzinfo=timezone.utc),
    )

    def update_alert_1_once(fake_alerts):
        alert = next(a for a in fake_alerts.alerts if a["composite_id"] == "alert-1")
        if alert["updated_timestamp"] != "2025-01-01T00:00:50Z":
            alert["updated_timestamp"] = "2025-01-01T00:00:50Z"
            fake_alerts.alerts.sort(key=lambda a: a["updated_timestamp"])

    fake.on_get = update_alert_1_once

    pages = list(
        client.iter_alert_pages(since="2025-01-01T00:00:00Z", products=["ngsiem"])
    )

    yielded = {i for page in _ids(pages) for i in page}
    assert yielded == {f"alert-{i}" for i in range(10)}
    # The checkpoint never jumps to the updated timestamp before alert-9 is sent
    cursors = [page.cursor for page in pages]
    last_page_with_alert_9 = next(
        index for index, page in enumerate(_ids(pages)) if "alert-9" in page
    )
    assert all(
        cursor < "2025-01-01T00:00:50Z" for cursor in cursors[:last_page_with_alert_9]
    )


def test_recent_alerts_do_not_move_the_cursor(make_client):
    client, _, _ = make_client(
        [_alert(1, "2025-01-01T00:00:01Z"), _alert(2, "2025-01-01T00:09:00Z")],
        page_size=5,
        now=datetime(2025, 1, 1, 0, 10, tzinfo=timezone.utc),
    )

    (page,) = list(
        client.iter_alert_pages(since="2025-01-01T00:00:00Z", products=["ngsiem"])
    )

    # alert-2 is within the clock skew margin: yielded, but the cursor stays on
    # alert-1 so that alert-2 is fetched again on the next run
    assert [a["composite_id"] for a in page.alerts] == ["alert-1", "alert-2"]
    assert page.cursor == "2025-01-01T00:00:01Z"
    assert page.boundary_ids == {"alert-1"}
