import json
from datetime import date, datetime, timezone
from unittest.mock import patch

import pytest
from conftest import JARM, SEARCH_URL, make_settings, scout_ip
from connectors_sdk.connectors.internal_hunt import (
    HuntAccessDeniedError,
    HuntLimits,
    HuntTimeWindow,
    NativeQuery,
)
from cymru_scout_hunt import CymruScoutHuntConnector
from cymru_scout_hunt.connector import _today, scout_window

SDK_CONNECTOR = "connectors_sdk.connectors.internal_hunt.internal_hunt_connector"
TODAY = "cymru_scout_hunt.connector._today"


def _window(start: str, end: str) -> HuntTimeWindow:
    return HuntTimeWindow(
        start=datetime.fromisoformat(start), end=datetime.fromisoformat(end)
    )


def test_the_plan_searches_each_fingerprint_apart(
    connector_factory, helper, hunt_event, requests_mock
):
    # Given a preview of a hunt with a JARM, a certificate subject and an ASN
    hunt_event["mode"] = "preview"

    # When it is processed
    connector_factory().process_message(hunt_event)

    # Then each fingerprint Scout indexes is one search, the commas of the subject escaped
    assert requests_mock.call_count == 0
    kwargs = helper.report_hunt_run.call_args.kwargs
    assert json.loads(kwargs["translated_query"]) == [
        f'fingerprints.hash = "{JARM}"',
        'x509.subject = "CN=Major Cobalt Strike\\, OU=AdvancedPenTesting\\, O=cobaltstrike"',
    ]


@pytest.mark.parametrize(
    ("start", "end", "expected"),
    [
        pytest.param(
            "2026-10-03T06:00:00+00:00",
            "2026-10-03T12:00:00+00:00",
            (date(2026, 10, 3), date(2026, 10, 3)),
            id="sub_day",
        ),
        pytest.param(
            "2026-06-01T00:00:00+00:00",
            "2026-10-04T00:00:00+00:00",
            (date(2026, 9, 4), date(2026, 10, 3)),
            id="longer_than_30_days",
        ),
        pytest.param(
            "2026-06-01T00:00:00+00:00",
            "2026-06-02T00:00:00+00:00",
            None,
            id="older_than_the_history",
        ),
    ],
)
def test_scout_window_keeps_the_most_recent_searchable_days(start, end, expected):
    # Given/When/Then the window is clamped to the 90 days of history, 30 at a time
    assert scout_window(_window(start, end), date(2026, 10, 3)) == expected


def test_today_is_the_utc_date():
    assert _today() == datetime.now(timezone.utc).date()


@patch(TODAY, return_value=date(2026, 10, 4))
def test_process_message_keeps_the_ip_addresses_of_the_days_searched(
    _, connector_factory, helper, requests_mock, hunt_event
):
    # Given Scout IP addresses dated by the day of a six-hour window
    requests_mock.get(SEARCH_URL, json={"total": 1, "ips": [scout_ip()]})

    # When the hunt run is processed
    connector_factory().process_message(hunt_event)

    # Then each fingerprint is one search of the day, and the IP address seen that day is a hit
    assert requests_mock.call_count == 2
    assert {
        request.qs["start_date"][0] for request in requests_mock.request_history
    } == {"2026-10-03"}
    kwargs = helper.report_hunt_run.call_args.kwargs
    assert kwargs["hits_count"] == 1
    assert kwargs["queries_count"] == 2
    sent = helper.stix2_create_bundle.call_args.args[0]
    assert [o["value"] for o in sent if o["type"] == "ipv4-addr"] == ["8.8.8.8"]
    (infrastructure,) = [obj for obj in sent if obj["type"] == "infrastructure"]
    assert "found on Team Cymru Scout by hunt run run-1" in (
        infrastructure["description"]
    )


@patch(TODAY, return_value=date(2026, 10, 4))
def test_a_window_older_than_the_history_is_not_searched(
    _, connector_factory, requests_mock
):
    # Given a run window older than the 90 days Scout holds
    connector = connector_factory()
    window = _window("2026-06-01T00:00:00+00:00", "2026-06-02T00:00:00+00:00")

    # When the plan runs
    result = connector.execute(
        NativeQuery(language="fingerprint", query='["q"]'), window, HuntLimits()
    )

    # Then nothing is searched, and the empty result proves nothing
    assert requests_mock.call_count == 0
    assert (result.events, result.truncated, result.queries_count) == ([], True, 0)


@patch(TODAY, return_value=date(2026, 10, 4))
def test_a_clipped_window_is_flagged(_, connector_factory, requests_mock):
    # Given a window longer than the 30 days Scout searches at a time
    requests_mock.get(SEARCH_URL, json={"total": 1, "ips": [scout_ip()]})
    window = _window("2026-08-01T00:00:00+00:00", "2026-10-04T00:00:00+00:00")

    # When the plan runs
    result = connector_factory().execute(
        NativeQuery(language="fingerprint", query='["q"]'), window, HuntLimits()
    )

    # Then the days left out make the result partial
    assert requests_mock.last_request.qs["start_date"] == ["2026-09-05"]
    assert len(result.events) == 1 and result.truncated is True


def test_a_refused_key_names_the_setting(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given a key Scout refuses
    requests_mock.get(SEARCH_URL, status_code=401, json={"detail": "Invalid token."})

    # When/Then the run fails, naming the setting to fix
    with patch(TODAY, return_value=date(2026, 10, 4)):
        with pytest.raises(HuntAccessDeniedError):
            connector_factory().process_message(hunt_event)
    assert "CYMRU_SCOUT_HUNT_API_KEY" in (
        helper.report_hunt_run.call_args.kwargs["error"]
    )


def test_execute_needs_the_client():
    # Given a connector that was not started
    connector = CymruScoutHuntConnector(make_settings())

    # When/Then a search fails
    with pytest.raises(RuntimeError):
        connector.execute(
            NativeQuery(language="fingerprint", query='["q"]'),
            _window("2026-10-03T00:00:00+00:00", "2026-10-04T00:00:00+00:00"),
            HuntLimits(),
        )


def test_start_registers_the_cymru_scout_platform_and_listens():
    # Given a pycti providing the hunt API
    connector = CymruScoutHuntConnector(make_settings())
    with (
        patch(f"{SDK_CONNECTOR}.ensure_pycti_hunt_support"),
        patch(f"{SDK_CONNECTOR}.OpenCTIConnectorHelper") as helper_cls,
    ):
        # When the connector starts
        connector.start()

    # Then the platform is registered without a Security Platform
    kwargs = helper_cls.return_value.register_hunt_platform.call_args.kwargs
    assert kwargs["platform"] == "cymru-scout"
    assert kwargs["languages"] == ["fingerprint"]
    assert kwargs["security_platform_name"] is None
    assert kwargs["max_concurrent_runs"] == 1
