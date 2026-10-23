"""Tests for the CrowdStrike Alerts API client."""

import re
from unittest.mock import MagicMock

import pytest
from crowdstrike_incidents.client_api import (
    MAX_PAGE_SIZE,
    USER_AGENT,
    CrowdstrikeAlertsClient,
    CrowdstrikeApiError,
    timestamp_sort_key,
)


def _alert(index: int, updated: str, show_in_ui: bool = True) -> dict:
    return {
        "composite_id": f"alert-{index}",
        "updated_timestamp": updated,
        "show_in_ui": show_in_ui,
    }


class FakeAlerts:
    """In-memory stand-in for falconpy.Alerts.get_alerts_combined.

    Understands the two time filters sent by the client:
    ``updated_timestamp:>='C'`` and
    ``(updated_timestamp:>'C',(updated_timestamp:'C'+composite_id:![...]))``.
    Returns at most ``limit`` alerts sorted by updated_timestamp, with an
    ``after`` token when more results are available.
    """

    def __init__(self, alerts: list[dict]) -> None:
        self.alerts = alerts
        self.bodies: list[dict] = []
        self.on_call = None
        self.get_alerts_combined = MagicMock(side_effect=self._combined)

    def _matches(self, fql: str, alert: dict) -> bool:
        if "show_in_ui:true" in fql and not alert.get("show_in_ui", True):
            return False
        key = timestamp_sort_key(alert["updated_timestamp"])
        inclusive = re.search(r"updated_timestamp:>='([^']+)'", fql)
        if inclusive:
            return key >= timestamp_sort_key(inclusive.group(1))
        cursor = re.search(r"updated_timestamp:>'([^']+)'", fql).group(1)
        excluded = re.findall(r"'([^']+)'", fql.split("composite_id:![")[1])
        cursor_key = timestamp_sort_key(cursor)
        return key > cursor_key or (
            key == cursor_key and alert["composite_id"] not in excluded
        )

    def _combined(self, body):
        self.bodies.append(dict(body))
        if self.on_call:
            self.on_call(self)
        matching = sorted(
            (a for a in self.alerts if self._matches(body["filter"], a)),
            key=lambda a: timestamp_sort_key(a["updated_timestamp"]),
        )
        limit = body["limit"]
        pagination = {"total": len(matching), "limit": limit}
        if len(matching) > limit:
            pagination["after"] = "opaque-token"
        # The API does not guarantee the order inside the response
        return {
            "status_code": 200,
            "body": {
                "meta": {"pagination": pagination},
                "resources": list(reversed(matching[:limit])),
                "errors": [],
            },
        }


@pytest.fixture
def make_client(mocker):
    def _make(alerts: list[dict], page_size: int = 2) -> tuple:
        fake = FakeAlerts(alerts)
        alerts_cls = mocker.patch(
            "crowdstrike_incidents.client_api.Alerts", return_value=fake
        )
        client = CrowdstrikeAlertsClient(
            base_url="https://api.example.org",
            client_id="synthetic-id",
            client_secret="synthetic-secret",
            page_size=page_size,
        )
        return client, fake, alerts_cls

    return _make


def _pages(client, since="2025-01-01T00:00:00Z", **kwargs) -> list:
    return list(client.iter_alert_pages(since=since, products=["ngsiem"], **kwargs))


def _ids(pages) -> list[str]:
    return [a["composite_id"] for page in pages for a in page.alerts]


def test_falconpy_is_configured(make_client):
    _, _, alerts_cls = make_client([])

    alerts_cls.assert_called_once_with(
        client_id="synthetic-id",
        client_secret="synthetic-secret",
        base_url="https://api.example.org",
        user_agent=USER_AGENT,
    )


def test_request_body(make_client):
    client, fake, _ = make_client([_alert(1, "2025-01-01T00:00:01Z")])

    _pages(client)

    assert fake.bodies[0] == {
        "filter": "product:['ngsiem']+updated_timestamp:>='2025-01-01T00:00:00Z'"
        "+show_in_ui:true",
        "sort": "updated_timestamp|asc",
        "limit": 2,
    }


def test_hidden_alerts_are_excluded_by_default(make_client):
    client, _, _ = make_client(
        [
            _alert(1, "2025-01-01T00:00:01Z"),
            _alert(2, "2025-01-01T00:00:02Z", show_in_ui=False),
        ]
    )

    assert _ids(_pages(client)) == ["alert-1"]


def test_hidden_alerts_are_included_on_demand(make_client):
    client, fake, _ = make_client(
        [
            _alert(1, "2025-01-01T00:00:01Z"),
            _alert(2, "2025-01-01T00:00:02Z", show_in_ui=False),
        ]
    )

    assert _ids(_pages(client, include_hidden=True)) == ["alert-1", "alert-2"]
    assert "show_in_ui" not in fake.bodies[0]["filter"]


def test_pages_are_fresh_queries_excluding_processed_alerts(make_client):
    client, fake, _ = make_client(
        [_alert(i, f"2025-01-01T00:00:0{i}Z") for i in range(1, 6)]
    )

    pages = _pages(client)

    # Every alert is yielded exactly once, oldest first
    assert _ids(pages) == [f"alert-{i}" for i in range(1, 6)]
    # No after token: each page restarts from the cursor and excludes the
    # alerts already processed at the cursor timestamp only
    assert all("after" not in body for body in fake.bodies)
    assert (
        "(updated_timestamp:>'2025-01-01T00:00:02Z',"
        "(updated_timestamp:'2025-01-01T00:00:02Z'+composite_id:!['alert-2']))"
        in fake.bodies[1]["filter"]
    )


def test_pages_carry_the_cursor_and_boundary_ids(make_client):
    client, _, _ = make_client(
        [
            _alert(1, "2025-01-01T00:00:01Z"),
            _alert(2, "2025-01-01T00:00:02Z"),
            _alert(3, "2025-01-01T00:00:02Z"),
        ],
        page_size=3,
    )

    (page,) = _pages(client)

    assert page.cursor == "2025-01-01T00:00:02Z"
    assert page.boundary_ids == {"alert-2", "alert-3"}


def test_boundary_alerts_are_not_yielded_twice(make_client):
    client, _, _ = make_client(
        [
            _alert(1, "2025-01-01T00:00:01Z"),
            _alert(2, "2025-01-01T00:00:02Z"),
            _alert(3, "2025-01-01T00:00:02Z"),
            _alert(4, "2025-01-01T00:00:03Z"),
        ]
    )

    ids = _ids(_pages(client))

    assert sorted(ids) == ["alert-1", "alert-2", "alert-3", "alert-4"]
    assert len(ids) == len(set(ids))


def test_skip_ids_are_not_yielded_again(make_client):
    client, _, _ = make_client(
        [_alert(1, "2025-01-01T00:00:01Z"), _alert(2, "2025-01-01T00:00:02Z")]
    )

    pages = _pages(client, since="2025-01-01T00:00:01Z", skip_ids=["alert-1"])

    assert _ids(pages) == ["alert-2"]


def test_boundary_alert_updated_between_runs_is_imported_again(make_client):
    """Regression (review): boundary IDs only apply at the cursor timestamp, so
    the newer version of an updated boundary alert is not dropped."""
    client, _, _ = make_client(
        [_alert(1, "2025-01-01T00:00:05Z"), _alert(2, "2025-01-01T00:00:03Z")]
    )

    # alert-1 was processed at 00:00:01 in a previous run, then updated
    pages = _pages(client, since="2025-01-01T00:00:01Z", skip_ids=["alert-1"])

    assert _ids(pages) == ["alert-2", "alert-1"]
    assert pages[-1].cursor == "2025-01-01T00:00:05Z"


def test_boundary_alert_updated_during_pagination_is_imported_again(make_client):
    client, fake, _ = make_client(
        [_alert(i, f"2025-01-01T00:00:0{i}Z") for i in range(1, 6)]
    )

    def update_alert_2_after_first_page(fake_alerts):
        if len(fake_alerts.bodies) == 2:
            alert_2 = next(
                a for a in fake_alerts.alerts if a["composite_id"] == "alert-2"
            )
            alert_2["updated_timestamp"] = "2025-01-01T00:00:09Z"

    fake.on_call = update_alert_2_after_first_page

    ids = _ids(_pages(client))

    # alert-2 is yielded twice: its first version, then its update
    assert ids.count("alert-2") == 2
    assert set(ids) == {f"alert-{i}" for i in range(1, 6)}


def test_identical_timestamps_are_drained_by_exclusion(make_client):
    same = "2025-01-01T00:00:01Z"
    client, fake, _ = make_client(
        [_alert(i, same) for i in range(1, 6)] + [_alert(6, "2025-01-01T00:00:02Z")]
    )

    ids = _ids(_pages(client, since=same))

    assert sorted(ids) == [f"alert-{i}" for i in range(1, 7)]
    assert len(ids) == len(set(ids))
    assert all("after" not in body for body in fake.bodies)


def test_tie_draining_survives_an_update(make_client):
    """Regression (review): an alert of a timestamp tie updated while the tie is
    drained must not shift the pagination and skip another alert."""
    tie = "2025-01-01T00:00:01Z"
    client, fake, _ = make_client(
        [_alert(i, tie) for i in range(1, 6)] + [_alert(6, "2025-01-01T00:00:02Z")]
    )

    def update_alert_1_after_first_page(fake_alerts):
        if len(fake_alerts.bodies) == 2:
            alert_1 = next(
                a for a in fake_alerts.alerts if a["composite_id"] == "alert-1"
            )
            alert_1["updated_timestamp"] = "2025-01-01T00:00:03Z"

    fake.on_call = update_alert_1_after_first_page

    ids = _ids(_pages(client, since=tie))

    assert set(ids) == {f"alert-{i}" for i in range(1, 7)}


def test_alert_updated_between_pages_is_not_lost(make_client):
    client, fake, _ = make_client(
        [_alert(i, f"2025-01-01T00:00:0{i}Z") for i in range(10)], page_size=3
    )

    def update_alert_5_after_first_page(fake_alerts):
        if len(fake_alerts.bodies) == 2:
            alert_5 = next(
                a for a in fake_alerts.alerts if a["composite_id"] == "alert-5"
            )
            alert_5["updated_timestamp"] = "2025-01-01T00:00:50Z"

    fake.on_call = update_alert_5_after_first_page

    ids = _ids(_pages(client))

    assert set(ids) == {f"alert-{i}" for i in range(10)}


@pytest.mark.parametrize("missing", ["updated_timestamp", "composite_id"])
def test_alerts_missing_a_key_are_skipped_and_reported(make_client, missing):
    """Regression (review): one invalid alert must not block the connector."""
    invalid = _alert(1, "2025-01-01T00:00:01Z")
    invalid.pop(missing)
    client, fake, _ = make_client([_alert(2, "2025-01-01T00:00:02Z")], page_size=5)
    fake.alerts.append(invalid)
    # The fake filters on updated_timestamp: inject the invalid alert directly
    original = fake._combined

    def with_invalid(body):
        response = original(body)
        response["body"]["resources"].append(invalid)
        return response

    fake.get_alerts_combined.side_effect = with_invalid
    fake.alerts = [a for a in fake.alerts if a is not invalid]

    pages = _pages(client)

    assert _ids(pages) == ["alert-2"]
    assert pages[0].skipped_ids == (
        ("alert-1",) if missing == "updated_timestamp" else ("<unknown>",)
    )


def test_too_many_identical_timestamps_raise(make_client, mocker):
    mocker.patch("crowdstrike_incidents.client_api.MAX_EXCLUDED_IDS", 3)
    same = "2025-01-01T00:00:01Z"
    client, _, _ = make_client([_alert(i, same) for i in range(1, 10)])

    with pytest.raises(CrowdstrikeApiError, match="same updated_timestamp"):
        _pages(client, since=same)


def test_empty_result(make_client):
    client, fake, _ = make_client([])

    assert _pages(client) == []
    assert fake.get_alerts_combined.call_count == 1


def test_consumer_can_stop_early(make_client):
    client, fake, _ = make_client(
        [_alert(i, f"2025-01-01T00:00:0{i}Z") for i in range(1, 7)]
    )

    pages = client.iter_alert_pages(since="2025-01-01T00:00:00Z", products=["ngsiem"])
    next(pages)
    pages.close()

    assert fake.get_alerts_combined.call_count == 1


@pytest.mark.parametrize("status_code", [401, 403, 429, 500])
def test_api_errors_raise(make_client, status_code):
    client, fake, _ = make_client([])
    fake.get_alerts_combined.side_effect = None
    fake.get_alerts_combined.return_value = {
        "status_code": status_code,
        "body": {"resources": [], "errors": [{"code": status_code, "message": "boom"}]},
    }

    with pytest.raises(CrowdstrikeApiError) as error:
        _pages(client)

    assert error.value.status_code == status_code
    assert "boom" in str(error.value)


def test_forbidden_error_mentions_the_required_scope(make_client):
    client, fake, _ = make_client([])
    fake.get_alerts_combined.side_effect = None
    fake.get_alerts_combined.return_value = {
        "status_code": 403,
        "body": {"resources": [], "errors": [{"code": 403, "message": "denied"}]},
    }

    with pytest.raises(CrowdstrikeApiError, match="Alerts: Read"):
        _pages(client)


def test_default_page_size_is_the_api_maximum():
    assert CrowdstrikeAlertsClient.DEFAULT_PAGE_SIZE == MAX_PAGE_SIZE == 1000


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


# ---------------------------------------------------------------------------
# LogScale source events client
# ---------------------------------------------------------------------------

from datetime import datetime, timezone  # noqa: E402

from crowdstrike_incidents.client_api import (  # noqa: E402
    EVENT_SEARCH_TIMEOUT_SECONDS,
    EVENT_SEARCH_VIEW,
    MAX_IDS_PER_SEARCH,
    CrowdstrikeEventsClient,
)

SINCE = datetime(2025, 1, 15, 9, 0, tzinfo=timezone.utc)


class FakeNgsiem:
    """Stand-in for falconpy.NGSIEM: start_search answers under ``resources``,
    get_search_status under ``body``, like the real API."""

    def __init__(self, events=None, polls_before_done=0):
        self.events = events or []
        self.polls_before_done = polls_before_done
        self.queries: list[dict] = []
        self.start_search = MagicMock(side_effect=self._start)
        self.get_search_status = MagicMock(side_effect=self._status)
        self.stop_search = MagicMock(return_value={"status_code": 204})

    def _start(self, repository, body):
        self.queries.append({"repository": repository, **body})
        return {"status_code": 200, "resources": {"id": f"job-{len(self.queries)}"}}

    def _status(self, repository, search_id):
        if self.polls_before_done > 0:
            self.polls_before_done -= 1
            return {"status_code": 200, "body": {"done": False, "events": []}}
        return {"status_code": 200, "body": {"done": True, "events": self.events}}


@pytest.fixture
def make_events_client(mocker):
    def _make(fake: FakeNgsiem, clock_step: float = 1.0) -> tuple:
        ngsiem_cls = mocker.patch(
            "crowdstrike_incidents.client_api.NGSIEM", return_value=fake
        )
        now = {"t": 0.0}

        def monotonic():
            now["t"] += clock_step
            return now["t"]

        client = CrowdstrikeEventsClient(
            base_url="https://api.example.org",
            client_id="synthetic-id",
            client_secret="synthetic-secret",
            sleep=lambda _: None,
            monotonic=monotonic,
        )
        return client, ngsiem_cls

    return _make


def test_events_client_is_configured(make_events_client):
    _, ngsiem_cls = make_events_client(FakeNgsiem())

    ngsiem_cls.assert_called_once_with(
        client_id="synthetic-id",
        client_secret="synthetic-secret",
        base_url="https://api.example.org",
        user_agent=USER_AGENT,
    )


def test_source_events_query(make_events_client):
    fake = FakeNgsiem(events=[{"Ngsiem.indicator.id": "a"}])
    client, _ = make_events_client(fake)

    events = client.get_source_events(["a", "b", "a"], since=SINCE)

    assert events == [{"Ngsiem.indicator.id": "a"}]
    (query,) = fake.queries
    assert query["repository"] == EVENT_SEARCH_VIEW == "search-all"
    assert query["queryString"] == (
        'Ngsiem.event.type="ngsiem-rule-match-event"'
        ' | in(field="Ngsiem.indicator.id", values=["a","b"])'
        " | head(limit=6)"
    )
    assert query["start"] == int(SINCE.timestamp() * 1000)
    assert query["end"] == "now"
    assert query["isLive"] is False


def test_source_events_are_searched_by_batches(make_events_client):
    fake = FakeNgsiem()
    client, _ = make_events_client(fake)

    client.get_source_events(
        [f"{i:032x}" for i in range(MAX_IDS_PER_SEARCH + 5)], since=SINCE
    )

    assert len(fake.queries) == 2
    assert f"head(limit={MAX_IDS_PER_SEARCH * 3})" in fake.queries[0]["queryString"]
    assert "head(limit=15)" in fake.queries[1]["queryString"]
    # 1000 indicator IDs stay below the 66 000 characters query limit
    assert len(fake.queries[0]["queryString"]) < 66_000


def test_source_events_search_is_polled_until_done(make_events_client):
    fake = FakeNgsiem(events=[{"Ngsiem.indicator.id": "a"}], polls_before_done=3)
    client, _ = make_events_client(fake)

    assert client.get_source_events(["a"], since=SINCE) == [
        {"Ngsiem.indicator.id": "a"}
    ]
    assert fake.get_search_status.call_count == 4


def test_source_events_search_timeout_stops_the_search(make_events_client):
    fake = FakeNgsiem(polls_before_done=10**6)
    client, _ = make_events_client(fake, clock_step=EVENT_SEARCH_TIMEOUT_SECONDS / 3)

    with pytest.raises(CrowdstrikeApiError, match="not completed"):
        client.get_source_events(["a"], since=SINCE)

    fake.stop_search.assert_called_once_with(repository="search-all", id="job-1")


def test_no_search_without_ids(make_events_client):
    fake = FakeNgsiem()
    client, _ = make_events_client(fake)

    assert client.get_source_events([], since=SINCE) == []
    fake.start_search.assert_not_called()


@pytest.mark.parametrize("status_code", [403, "403"])
def test_source_events_forbidden_mentions_the_ngsiem_scope(
    make_events_client, status_code
):
    fake = FakeNgsiem()
    fake.start_search.side_effect = None
    fake.start_search.return_value = {
        "status_code": status_code,
        "resources": {"errors": [{"code": 403, "message": "scope not permitted"}]},
    }
    client, _ = make_events_client(fake)

    with pytest.raises(CrowdstrikeApiError, match="NGSIEM: Write") as error:
        client.get_source_events(["a"], since=SINCE)

    assert error.value.status_code == 403
    assert "scope not permitted" in str(error.value)


def test_cancelled_search_raises(make_events_client):
    fake = FakeNgsiem()
    fake.get_search_status.side_effect = None
    fake.get_search_status.return_value = {
        "status_code": 200,
        "body": {"done": False, "cancelled": True, "events": []},
    }
    client, _ = make_events_client(fake)

    with pytest.raises(CrowdstrikeApiError, match="cancelled"):
        client.get_source_events(["a"], since=SINCE)


def test_stop_search_failure_does_not_hide_the_timeout(make_events_client):
    fake = FakeNgsiem(polls_before_done=10**6)
    fake.stop_search.side_effect = RuntimeError("network down")
    client, _ = make_events_client(fake, clock_step=EVENT_SEARCH_TIMEOUT_SECONDS / 3)

    with pytest.raises(CrowdstrikeApiError, match="not completed"):
        client.get_source_events(["a"], since=SINCE)


def test_unexpected_indicator_ids_are_not_sent(make_events_client):
    fake = FakeNgsiem()
    client, _ = make_events_client(fake)

    client.get_source_events(["abc123", 'bad"id', "bad\\", "", "ok_id-1"], since=SINCE)

    assert 'values=["abc123","ok_id-1"]' in fake.queries[0]["queryString"]


def test_cursor_never_moves_backwards(make_client):
    """If the API returned alerts older than a high-precision cursor, the page
    must not move the cursor back (which would loop on the same page)."""
    cursor = "2025-01-01T00:00:01.123456789Z"
    client, fake, _ = make_client([])
    fake.get_alerts_combined.side_effect = None
    fake.get_alerts_combined.return_value = {
        "status_code": 200,
        "body": {
            "meta": {"pagination": {"total": 2}},
            "resources": [
                _alert(1, "2025-01-01T00:00:01.123Z"),
                _alert(2, "2025-01-01T00:00:01.1Z"),
            ],
            "errors": [],
        },
    }

    pages = _pages(client, since=cursor)

    assert all(
        timestamp_sort_key(page.cursor) >= timestamp_sort_key(cursor) for page in pages
    )
