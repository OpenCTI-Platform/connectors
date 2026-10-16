import json
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from conftest import JARM, SEARCH_URL, make_settings, scan, scans_answer
from connectors_sdk.connectors.internal_hunt import (
    HuntAccessDeniedError,
    HuntLimits,
    HuntTimeWindow,
    HuntTranslationError,
    NativeQuery,
)
from silentpush_hunt import SilentPushHuntConnector

SDK_CONNECTOR = "connectors_sdk.connectors.internal_hunt.internal_hunt_connector"
WINDOW = HuntTimeWindow(
    start=datetime(2026, 10, 3, tzinfo=timezone.utc),
    end=datetime(2026, 10, 4, tzinfo=timezone.utc),
)


def test_the_plan_matches_the_fingerprints_silent_push_indexes(
    connector_factory, helper, hunt_event, requests_mock
):
    # Given a preview of a hunt with a JARM, an HTTP title and a JA4X
    hunt_event["mode"] = "preview"

    # When it is processed
    connector_factory().process_message(hunt_event)

    # Then the JA4X, which Silent Push does not index, is left out of the one SPQL query
    assert requests_mock.call_count == 0
    kwargs = helper.report_hunt_run.call_args.kwargs
    assert json.loads(kwargs["translated_query"]) == [
        f'(jarm = "{JARM}") OR (htmltitle = "Sign in")'
    ]


def test_a_hunt_without_indexed_fingerprint_needs_a_raw_query(
    connector_factory, helper, hunt_event
):
    # Given a hunt holding a JA4X only
    hunt_event["hunt"]["native_query"][
        "query"
    ] = "fingerprints: [{kind: ja4x, value: a373a9f83c6b_2bab15409345_7bf9a7bf7029}]"

    # When/Then the run fails, asking for a raw query
    with pytest.raises(HuntTranslationError, match="raw query for the 'silentpush'"):
        connector_factory().process_message(hunt_event)
    assert helper.report_hunt_run.call_args.args == ("run-1", "failed")


def test_process_message_maps_the_hosts_scanned_within_the_window(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given a scan within the window and one before it
    requests_mock.post(
        SEARCH_URL,
        json=scans_answer(
            [
                scan(),
                scan("9.9.9.9", "old.example", scan_date="2026-09-01T00:00:00Z"),
            ]
        ),
    )

    # When the hunt run is processed
    connector_factory().process_message(hunt_event)

    # Then the host of the window is the hit, and its observables are sent
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "completed")
    assert kwargs["hits_count"] == 1
    assert kwargs["queries_count"] == 1
    sent = helper.stix2_create_bundle.call_args.args[0]
    assert sorted(o["value"] for o in sent if o["type"] == "domain-name") == [
        "c2.update-cdn.net",
        "update-cdn.net",
    ]
    assert [o["value"] for o in sent if o["type"] == "ipv4-addr"] == ["8.8.8.8"]
    (infrastructure,) = [obj for obj in sent if obj["type"] == "infrastructure"]
    assert "found on Silent Push by hunt run run-1" in infrastructure["description"]


def test_a_refused_key_names_the_setting(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given a key Silent Push refuses
    requests_mock.post(SEARCH_URL, status_code=401, json={"error": "invalid key"})

    # When/Then the run fails, naming the setting to fix
    with pytest.raises(HuntAccessDeniedError):
        connector_factory().process_message(hunt_event)
    assert "SILENTPUSH_HUNT_API_KEY" in helper.report_hunt_run.call_args.kwargs["error"]


def test_execute_needs_the_client():
    # Given a connector that was not started
    connector = SilentPushHuntConnector(make_settings())

    # When/Then a search fails
    with pytest.raises(RuntimeError):
        connector.execute(
            NativeQuery(language="fingerprint", query='["q"]'), WINDOW, HuntLimits()
        )


def test_start_registers_the_silentpush_platform_and_listens():
    # Given a pycti providing the hunt API
    connector = SilentPushHuntConnector(make_settings())
    with (
        patch(f"{SDK_CONNECTOR}.ensure_pycti_hunt_support"),
        patch(f"{SDK_CONNECTOR}.OpenCTIConnectorHelper") as helper_cls,
    ):
        # When the connector starts
        connector.start()

    # Then the platform is registered without a Security Platform
    kwargs = helper_cls.return_value.register_hunt_platform.call_args.kwargs
    assert kwargs["platform"] == "silentpush"
    assert kwargs["languages"] == ["fingerprint"]
    assert kwargs["security_platform_name"] is None
    assert kwargs["max_concurrent_runs"] == 2
