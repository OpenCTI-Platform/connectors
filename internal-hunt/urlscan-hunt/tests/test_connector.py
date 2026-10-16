import json
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from conftest import SEARCH_URL, make_settings, scan
from connectors_sdk.connectors.internal_hunt import (
    HuntAccessDeniedError,
    HuntLimits,
    HuntTimeWindow,
    NativeQuery,
)
from urlscan_hunt import UrlscanHuntConnector

SDK_CONNECTOR = "connectors_sdk.connectors.internal_hunt.internal_hunt_connector"
WINDOW = HuntTimeWindow(
    start=datetime(2026, 10, 3, tzinfo=timezone.utc),
    end=datetime(2026, 10, 4, tzinfo=timezone.utc),
)


def test_the_plan_matches_the_fingerprints_urlscan_indexes(
    connector_factory, helper, hunt_event, requests_mock
):
    # Given a preview of a hunt with an HTTP title, an ASN and a JARM
    hunt_event["mode"] = "preview"

    # When it is processed
    connector_factory().process_message(hunt_event)

    # Then the JARM, which urlscan.io does not index, is left out of the one query
    assert requests_mock.call_count == 0
    kwargs = helper.report_hunt_run.call_args.kwargs
    assert json.loads(kwargs["translated_query"]) == [
        '(page.title:"Sign in to your account") OR (page.asn:AS20473)'
    ]


def test_process_message_keeps_the_scans_of_a_sub_day_window(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given scans of the day of a six-hour window, one of them after the window
    requests_mock.get(
        SEARCH_URL,
        json={
            "results": [
                scan(),
                scan("9.9.9.9", "late.example", time="2026-10-03T20:00:00Z"),
            ],
            "total": 2,
        },
    )

    # When the hunt run is processed
    connector_factory().process_message(hunt_event)

    # Then the search covers the day, and only the scan within the window is a hit
    assert requests_mock.last_request.qs["q"][0].endswith(
        "date:[2026-10-03 to 2026-10-03]"
    )
    kwargs = helper.report_hunt_run.call_args.kwargs
    assert kwargs["hits_count"] == 1
    assert kwargs["queries_count"] == 1
    sent = helper.stix2_create_bundle.call_args.args[0]
    assert [o["value"] for o in sent if o["type"] == "ipv4-addr"] == ["8.8.8.8"]
    assert [o["value"] for o in sent if o["type"] == "domain-name"] == [
        "login.update-cdn.net"
    ]
    assert "x509-certificate" not in {obj["type"] for obj in sent}


def test_a_refused_key_names_the_setting(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given a key urlscan.io refuses
    requests_mock.get(SEARCH_URL, status_code=401, json={"message": "Unauthorized"})

    # When/Then the run fails, naming the setting to fix
    with pytest.raises(HuntAccessDeniedError):
        connector_factory().process_message(hunt_event)
    assert "URLSCAN_HUNT_API_KEY" in helper.report_hunt_run.call_args.kwargs["error"]


def test_execute_needs_the_client():
    # Given a connector that was not started
    connector = UrlscanHuntConnector(make_settings())

    # When/Then a search fails
    with pytest.raises(RuntimeError):
        connector.execute(
            NativeQuery(language="fingerprint", query='["q"]'), WINDOW, HuntLimits()
        )


def test_start_registers_the_urlscan_platform_and_listens():
    # Given a pycti providing the hunt API
    connector = UrlscanHuntConnector(make_settings())
    with (
        patch(f"{SDK_CONNECTOR}.ensure_pycti_hunt_support"),
        patch(f"{SDK_CONNECTOR}.OpenCTIConnectorHelper") as helper_cls,
    ):
        # When the connector starts
        connector.start()

    # Then the platform is registered without a Security Platform
    kwargs = helper_cls.return_value.register_hunt_platform.call_args.kwargs
    assert kwargs["platform"] == "urlscan"
    assert kwargs["languages"] == ["fingerprint"]
    assert kwargs["security_platform_name"] is None
    assert kwargs["max_concurrent_runs"] == 2
