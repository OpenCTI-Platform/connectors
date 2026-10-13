"""Tests for the CrowdStrike Alerts API client."""

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

    Sorts by updated_timestamp and pages with an opaque ``after`` token, like
    POST /alerts/combined/alerts/v1.
    """

    def __init__(self, alerts: list[dict]) -> None:
        self.alerts = alerts
        self.bodies: list[dict] = []
        self.on_call = None
        self.get_alerts_combined = MagicMock(side_effect=self._combined)

    def _combined(self, body):
        self.bodies.append(dict(body))
        if self.on_call:
            self.on_call(self)
        fql = body["filter"]
        since = fql.split("updated_timestamp:>='")[1].split("'")[0]
        matching = sorted(
            (
                a
                for a in self.alerts
                if timestamp_sort_key(a["updated_timestamp"])
                >= timestamp_sort_key(since)
                and ("show_in_ui:true" not in fql or a["show_in_ui"])
            ),
            key=lambda a: timestamp_sort_key(a["updated_timestamp"]),
        )
        offset = int(body.get("after") or 0)
        limit = body["limit"]
        page = matching[offset : offset + limit]
        pagination = {"total": len(matching), "limit": limit}
        if offset + limit < len(matching):
            pagination["after"] = str(offset + limit)
        # The API does not guarantee the order inside the response
        return {
            "status_code": 200,
            "body": {
                "meta": {"pagination": pagination},
                "resources": list(reversed(page)),
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


def test_pages_are_chained_by_keyset_not_after_token(make_client):
    client, fake, _ = make_client(
        [_alert(i, f"2025-01-01T00:00:0{i}Z") for i in range(1, 6)]
    )

    pages = _pages(client)

    # Every alert is yielded exactly once, oldest first
    assert _ids(pages) == [f"alert-{i}" for i in range(1, 6)]
    # Each page restarts from the last timestamp, without after token
    assert all("after" not in body for body in fake.bodies)
    assert "'2025-01-01T00:00:02Z'" in fake.bodies[1]["filter"]


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


def test_full_page_with_identical_timestamps_uses_the_after_token(make_client):
    same = "2025-01-01T00:00:01Z"
    client, fake, _ = make_client(
        [_alert(i, same) for i in range(1, 6)] + [_alert(6, "2025-01-01T00:00:02Z")]
    )

    ids = _ids(_pages(client, since=same))

    assert sorted(ids) == [f"alert-{i}" for i in range(1, 7)]
    assert len(ids) == len(set(ids))
    assert any("after" in body for body in fake.bodies)


def test_alert_updated_between_pages_is_not_lost(make_client):
    """An alert updated during the run moves to a later position: it must be
    yielded again later, and no other alert may be skipped."""
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
