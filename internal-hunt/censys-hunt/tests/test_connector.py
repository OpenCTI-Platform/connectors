import json
from collections import Counter
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from censys_hunt import CensysHuntConnector
from censys_hunt.connector import FINGERPRINT_MATCHES
from conftest import (
    CERT_SHA256,
    CERT_SUBJECT,
    JARM,
    SEARCH_URL,
    censys_answer,
    censys_host,
    make_settings,
)
from connectors_sdk.connectors.internal_hunt import (
    Fingerprint,
    HuntAccessDeniedError,
    HuntLimits,
    HuntTimeWindow,
    HuntTranslationError,
    NativeQuery,
    infrastructure_stix_id,
)

SDK_CONNECTOR = "connectors_sdk.connectors.internal_hunt.internal_hunt_connector"
WINDOW = HuntTimeWindow(
    start=datetime(2026, 10, 3, tzinfo=timezone.utc),
    end=datetime(2026, 10, 4, tzinfo=timezone.utc),
)


def test_the_plan_matches_every_fingerprint_in_one_query(
    connector_factory, helper, hunt_event, requests_mock
):
    # Given a preview of a hunt with a JARM, a certificate subject and an ASN
    hunt_event["mode"] = "preview"

    # When it is processed
    connector_factory().process_message(hunt_event)

    # Then Censys is not searched and the one CenQL query is reported
    assert requests_mock.call_count == 0
    kwargs = helper.report_hunt_run.call_args.kwargs
    assert kwargs["query_language"] == "fingerprint"
    assert json.loads(kwargs["translated_query"]) == [
        f'(host.services.jarm.fingerprint = "{JARM}") or '
        f'(host.services.cert.parsed.subject_dn = "{CERT_SUBJECT}") or '
        '(host.autonomous_system.asn = "20473")'
    ]


@pytest.mark.parametrize(
    ("kind", "value", "match"),
    [
        pytest.param(
            "http_server",
            'nginx "x"',
            'host.services.endpoints.http.headers: (key = "Server" and value = "nginx \\"x\\"")',
            id="server_header",
        ),
        pytest.param(
            "ja4s",
            "t130200_1302_a56c5b993250",
            'host.services.tls.ja4s = "t130200_1302_a56c5b993250"',
            id="ja4s",
        ),
    ],
)
def test_fingerprint_matches(kind, value, match):
    # Given a fingerprint
    fingerprint = Fingerprint(kind=kind, value=value)

    # When/Then its CenQL match is exact
    assert FINGERPRINT_MATCHES[kind](fingerprint) == match


def test_process_message_maps_the_infrastructure(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given Censys hosts: a public one with a domain, a private one, one last scanned before the window
    requests_mock.post(
        SEARCH_URL,
        json=censys_answer(
            [
                censys_host("8.8.8.8", ["c2.update-cdn.net"]),
                censys_host("10.0.0.1", ["intranet.local"], cert=None),
                censys_host("9.9.9.9", cert=None, scan_time="2026-09-01T00:00:00Z"),
            ]
        ),
    )

    # When the hunt run is processed
    message = connector_factory().process_message(hunt_event)

    # Then the hosts of the window are hits, keyed by address, with one search sent
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "completed")
    assert kwargs["hits_count"] == 2
    assert kwargs["queries_count"] == 1
    assert "2 hit(s)" in message
    assert sorted(hit["host"] for hit in kwargs["hits_sample"]) == [
        "10.0.0.1",
        "8.8.8.8",
    ]
    evidence_fields = {item["field"] for item in kwargs["evidence_sample"]}
    assert "jarm" in evidence_fields and "certificates" not in evidence_fields
    assert requests_mock.last_request.qs == {"organization_id": ["org-1"]}

    # And the infrastructure grows with the public observables and their indicators
    sent = helper.stix2_create_bundle.call_args.args[0]
    assert Counter(obj["type"] for obj in sent) == {
        "infrastructure": 1,
        "ipv4-addr": 1,
        "domain-name": 1,
        "x509-certificate": 1,
        "indicator": 3,
        "relationship": 1 + 3 + 3 + 3,
        "observed-data": 3,
    }
    (infrastructure,) = [obj for obj in sent if obj["type"] == "infrastructure"]
    assert infrastructure["id"] == infrastructure_stix_id("hunt-1")
    assert "found on Censys Platform by hunt run run-1" in (
        infrastructure["description"]
    )
    (certificate,) = [obj for obj in sent if obj["type"] == "x509-certificate"]
    assert certificate["hashes"] == {"SHA-256": CERT_SHA256}
    helper.send_stix2_bundle.assert_called_once()


def test_certificates_can_be_left_out(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given certificates disabled
    requests_mock.post(SEARCH_URL, json=censys_answer([censys_host("8.8.8.8")]))
    connector = connector_factory({"censys_hunt": {"create_certificates": False}})

    # When the run is processed
    connector.process_message(hunt_event)

    # Then no certificate is created
    sent = helper.stix2_create_bundle.call_args.args[0]
    assert "x509-certificate" not in {obj["type"] for obj in sent}


def test_a_raw_query_runs_as_written(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given a hunt holding a raw CenQL query only
    requests_mock.post(SEARCH_URL, json=censys_answer([]))
    hunt_event["hunt"]["native_query"][
        "query"
    ] = "queries:\n  censys: 'host.services.port = 50050'\n"

    # When it is processed
    connector_factory().process_message(hunt_event)

    # Then the raw query is sent and nothing is created
    assert requests_mock.last_request.json()["query"] == "host.services.port = 50050"
    assert helper.report_hunt_run.call_args.kwargs["hits_count"] == 0
    helper.send_stix2_bundle.assert_not_called()


def test_sigma_rules_are_rejected(connector_factory, helper, hunt_event):
    # Given a hunt with a Sigma rule only
    hunt_event["hunt"]["native_query"] = None
    hunt_event["hunt"]["sigma_rule"] = "title: x"

    # When/Then the run fails, asking for a fingerprint document
    with pytest.raises(HuntTranslationError, match="not translated for Censys"):
        connector_factory().process_message(hunt_event)
    assert helper.report_hunt_run.call_args.args == ("run-1", "failed")


def test_a_refused_token_names_the_setting(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given a token Censys refuses
    requests_mock.post(SEARCH_URL, status_code=401, json={"message": "Unauthorized"})

    # When/Then the run fails, naming the setting to fix
    with pytest.raises(HuntAccessDeniedError):
        connector_factory().process_message(hunt_event)
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "failed")
    assert "CENSYS_HUNT_TOKEN" in kwargs["error"]
    helper.send_stix2_bundle.assert_not_called()


def test_execute_needs_the_client():
    # Given a connector that was not started
    connector = CensysHuntConnector(make_settings())

    # When/Then a search fails
    with pytest.raises(RuntimeError):
        connector.execute(
            NativeQuery(language="fingerprint", query='["q"]'), WINDOW, HuntLimits()
        )


def test_start_registers_the_censys_platform_and_listens():
    # Given a pycti providing the hunt API
    connector = CensysHuntConnector(make_settings())
    with (
        patch(f"{SDK_CONNECTOR}.ensure_pycti_hunt_support"),
        patch(f"{SDK_CONNECTOR}.OpenCTIConnectorHelper") as helper_cls,
    ):
        # When the connector starts
        connector.start()

    # Then the platform is registered without a Security Platform and the hunt queue consumed
    helper = helper_cls.return_value
    kwargs = helper.register_hunt_platform.call_args.kwargs
    assert kwargs["platform"] == "censys"
    assert kwargs["languages"] == ["fingerprint"]
    assert kwargs["security_platform_name"] is None
    assert kwargs["max_concurrent_runs"] == 1
    assert kwargs["supports_indicators"] is False
    helper.listen_hunt.assert_called_once_with(
        message_callback=connector.process_message
    )
