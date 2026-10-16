import json
from collections import Counter
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from conftest import JARM, SEARCH_URL, banner, make_settings
from connectors_sdk.connectors.internal_hunt import (
    HuntAccessDeniedError,
    HuntLimits,
    HuntTimeWindow,
    NativeQuery,
)
from shodan_hunt import ShodanHuntConnector
from shodan_hunt.connector import common_name

SDK_CONNECTOR = "connectors_sdk.connectors.internal_hunt.internal_hunt_connector"
WINDOW = HuntTimeWindow(
    start=datetime(2026, 10, 3, tzinfo=timezone.utc),
    end=datetime(2026, 10, 4, tzinfo=timezone.utc),
)


def test_the_plan_searches_each_fingerprint_apart(
    connector_factory, helper, hunt_event, requests_mock
):
    # Given a preview of a hunt with a JARM, a certificate subject and a JA4X
    hunt_event["mode"] = "preview"

    # When it is processed
    connector_factory().process_message(hunt_event)

    # Then each fingerprint Shodan indexes is one search, the subject matched on its common name
    assert requests_mock.call_count == 0
    kwargs = helper.report_hunt_run.call_args.kwargs
    assert json.loads(kwargs["translated_query"]) == [
        f'ssl.jarm:"{JARM}"',
        'ssl.cert.subject.cn:"Major Cobalt Strike"',
    ]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param("CN=Evil, O=Org", "Evil", id="first"),
        pytest.param("O=Org, cn = Evil ", "Evil", id="last"),
        pytest.param("Evil Corp CA", "Evil Corp CA", id="bare_name"),
        pytest.param("O=Org", "O=Org", id="no_common_name"),
    ],
)
def test_common_name(value, expected):
    assert common_name(value) == expected


def test_process_message_merges_the_services_of_a_host(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given two services of one host, and a banner older than the window
    requests_mock.get(
        SEARCH_URL,
        json={
            "total": 3,
            "matches": [
                banner(port=443),
                banner(port=8443),
                banner("9.9.9.9", timestamp="2026-09-01T00:00:00"),
            ],
        },
    )

    # When the hunt run is processed
    connector_factory().process_message(hunt_event)

    # Then the host is one hit found by both searches, with its two ports
    kwargs = helper.report_hunt_run.call_args.kwargs
    assert kwargs["hits_count"] == 1
    assert kwargs["queries_count"] == 2
    sent = helper.stix2_create_bundle.call_args.args[0]
    types = Counter(obj["type"] for obj in sent)
    assert types["ipv4-addr"] == 1 and types["x509-certificate"] == 1
    assert sorted(o["value"] for o in sent if o["type"] == "domain-name") == [
        "c2.update-cdn.net",
        "update-cdn.net",
    ]
    (infrastructure,) = [obj for obj in sent if obj["type"] == "infrastructure"]
    assert "found on Shodan by hunt run run-1" in infrastructure["description"]


def test_a_refused_key_names_the_setting(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given a key Shodan refuses
    requests_mock.get(SEARCH_URL, status_code=401, json={"error": "Invalid API key"})

    # When/Then the run fails, naming the setting to fix, without the key
    with pytest.raises(HuntAccessDeniedError):
        connector_factory().process_message(hunt_event)
    error = helper.report_hunt_run.call_args.kwargs["error"]
    assert "SHODAN_HUNT_API_KEY" in error and "shodan-secret-key" not in error


def test_execute_needs_the_client():
    # Given a connector that was not started
    connector = ShodanHuntConnector(make_settings())

    # When/Then a search fails
    with pytest.raises(RuntimeError):
        connector.execute(
            NativeQuery(language="fingerprint", query='["q"]'), WINDOW, HuntLimits()
        )


def test_start_registers_the_shodan_platform_and_listens():
    # Given a pycti providing the hunt API
    connector = ShodanHuntConnector(make_settings())
    with (
        patch(f"{SDK_CONNECTOR}.ensure_pycti_hunt_support"),
        patch(f"{SDK_CONNECTOR}.OpenCTIConnectorHelper") as helper_cls,
    ):
        # When the connector starts
        connector.start()

    # Then the platform is registered without a Security Platform
    kwargs = helper_cls.return_value.register_hunt_platform.call_args.kwargs
    assert kwargs["platform"] == "shodan"
    assert kwargs["languages"] == ["fingerprint"]
    assert kwargs["security_platform_name"] is None
    assert kwargs["max_concurrent_runs"] == 1
