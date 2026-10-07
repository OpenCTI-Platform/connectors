"""Deployment write-back of the Google SecOps SIEM connector."""

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests
from connectors_sdk import (
    DeploymentAssurance,
    DeploymentReconciler,
    HitCollection,
    IndicatorDeployment,
)
from google.auth.exceptions import RefreshError
from pycti import OpenCTIConnectorHelper
from secops_siem_connector import ConnectorSettings, SecOpsSIEMConnector
from secops_siem_connector.deployment import (
    MAX_HIT_MATCHES,
    SecOpsDeploymentAdapter,
    SecOpsDeploymentError,
    build_deployment_assurance,
)
from secops_siem_services import SecOpsApiError, SecOpsEntitiesClient
from secops_siem_services.api_client import (
    REQUEST_TIMEOUT,
    describe_response,
    format_timestamp,
)

OPENCTI_EXTENSION_ID = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
PLATFORM_ID = "6c3b0f4e-2d41-4a77-8f0d-3e1c9b5a7d21"
INDICATOR_ID = "0d8b4f0e-6a43-4f11-8f6c-1d2f5e6a7b8c"
OTHER_ID = "1e9c5f1f-7b54-4a22-9e7d-2e3f6a7b8c9d"
STIX_ID = "indicator--5d4f2a3b-8c9d-4e1f-a2b3-c4d5e6f7a8b9"
SHA256 = "37c09c95f77e5677332de338b7e972cff67347ed2c807c15b415c41b0d4a9ac4"
NOW = datetime(2026, 10, 3, 12, 0, tzinfo=UTC)


def make_settings(**namespaces: dict[str, Any]) -> ConnectorSettings:
    """Build connector settings from a valid configuration and overrides."""
    config = {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "connector": {"live_stream_id": "live"},
        "secops_siem": {
            "project_id": "test-project-id",
            "project_instance": "test-instance",
            "private_key_id": "test-key-id",
            "private_key": "test-private-key",
            "client_email": "test@project.iam.gserviceaccount.com",
            "client_id": "123456789",
            "client_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/test",
        },
    }
    for namespace, values in namespaces.items():
        config[namespace] = {**config.get(namespace, {}), **values}

    class StubConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(config)

    return StubConnectorSettings()


def make_indicator(indicator_id=INDICATOR_ID, value="198.51.100.7", stix_id=STIX_ID):
    return {
        "id": stix_id,
        "type": "indicator",
        "spec_version": "2.1",
        "name": value,
        "pattern": f"[ipv4-addr:value = '{value}']",
        "pattern_type": "stix",
        "valid_from": "2026-10-01T00:00:00.000Z",
        "valid_until": "2027-10-01T00:00:00.000Z",
        "extensions": {
            OPENCTI_EXTENSION_ID: {
                "id": indicator_id,
                "type": "Indicator",
                "score": 80,
                "observable_values": [{"type": "IPv4-Addr", "value": value}],
            }
        },
    }


def make_message(event, data):
    return SimpleNamespace(event=event, data=json.dumps({"data": data}), id="1-0")


def make_helper(spec: list[str] | None = None) -> MagicMock:
    helper = MagicMock(spec=spec) if spec is not None else MagicMock()
    helper.get_attribute_in_extension = (
        OpenCTIConnectorHelper.get_attribute_in_extension
    )
    helper.opencti_url = "http://localhost:8080"
    return helper


def build_connector(settings=None, helper=None, assurance=None):
    with patch.object(SecOpsEntitiesClient, "init_session", return_value=MagicMock()):
        connector = SecOpsSIEMConnector(
            config=settings or make_settings(), helper=helper or make_helper()
        )
    connector.assurance = assurance
    return connector


def make_deployment(indicator_id=INDICATOR_ID, value="198.51.100.7", **fields):
    return IndicatorDeployment(
        relationship_id=f"relationship-{indicator_id}",
        status=fields.pop("status", "deployed"),
        indicator_id=indicator_id,
        pattern=fields.pop("pattern", f"[ipv4-addr:value = '{value}']"),
        pattern_type="stix",
        **fields,
    )


def mock_response(json_data=None, status_code=200, text=None):
    response = MagicMock(spec=requests.Response)
    response.status_code = status_code
    response.ok = 200 <= status_code < 400
    if isinstance(json_data, Exception):
        response.json.side_effect = json_data
    else:
        response.json.return_value = json_data
    response.text = text if text is not None else json.dumps(json_data)
    return response


def ioc_match(last_seen: datetime | str | None, **artifact: str) -> dict[str, Any]:
    match: dict[str, Any] = {"artifactIndicator": artifact, "sources": ["OPENCTI"]}
    if last_seen is not None:
        match["lastSeenTimestamp"] = (
            format_timestamp(last_seen)
            if isinstance(last_seen, datetime)
            else last_seen
        )
    return match


@pytest.fixture(name="connector")
def fixture_connector():
    connector = build_connector(assurance=MagicMock(spec=DeploymentAssurance))
    connector.api_client = MagicMock(spec=SecOpsEntitiesClient)
    return connector


@pytest.fixture(name="no_atexit")
def fixture_no_atexit(monkeypatch):
    """Do not register the exit flush of the deployment reporter during tests."""
    monkeypatch.setattr(
        "connectors_sdk.connectors.stream.deployment.reporter.atexit.register",
        lambda _handler: None,
    )


@pytest.fixture(name="secops_client")
def fixture_secops_client():
    with patch.object(SecOpsEntitiesClient, "init_session", return_value=MagicMock()):
        return SecOpsEntitiesClient(make_helper(), make_settings().secops_siem)


# Stream path


@pytest.mark.parametrize("event", ["create", "update"])
def test_ingested_indicator_is_reported_deployed(connector, event):
    indicator = make_indicator()

    connector.process_message(make_message(event, indicator))

    (entities,) = connector.api_client.ingest.call_args.args
    assert entities[0]["entity"] == {"ip": "198.51.100.7"}
    assert entities[0]["metadata"]["product_entity_id"] == STIX_ID
    connector.assurance.report_pushed.assert_called_once_with(
        indicator, external_id=STIX_ID
    )
    connector.assurance.report_push_failed.assert_not_called()


def test_rejected_indicator_is_reported_failed_and_the_stream_continues(connector):
    error = SecOpsApiError(
        "Entities import rejected: HTTP 400 - invalid entity", status_code=400
    )
    connector.api_client.ingest.side_effect = error
    indicator = make_indicator()

    connector.process_message(make_message("create", indicator))

    connector.assurance.report_push_failed.assert_called_once_with(
        indicator, "Google SecOps refused the entity ingestion: invalid request"
    )
    connector.assurance.report_pushed.assert_not_called()
    connector.helper.connector_logger.warning.assert_called_once_with(
        "[API] Error while ingesting indicator",
        meta={"indicator_id": STIX_ID, "error": str(error)},
    )
    connector.helper.connector_logger.error.assert_not_called()


def test_indicator_without_supported_observable_is_not_reported(connector):
    indicator = make_indicator()
    indicator["extensions"][OPENCTI_EXTENSION_ID]["observable_values"] = [
        {"type": "Mutex", "value": "evil"}
    ]

    connector.process_message(make_message("create", indicator))

    connector.api_client.ingest.assert_not_called()
    connector.assurance.report_pushed.assert_not_called()
    connector.assurance.report_push_failed.assert_not_called()


def test_delete_events_are_not_reported(connector):
    connector.process_message(make_message("delete", make_indicator()))

    connector.api_client.ingest.assert_not_called()
    connector.assurance.report_removed.assert_not_called()


def test_connector_works_without_write_back():
    connector = build_connector()
    connector.api_client = MagicMock(spec=SecOpsEntitiesClient)

    connector.process_message(make_message("create", make_indicator()))
    connector.api_client.ingest.side_effect = SecOpsApiError("rejected")
    connector.process_message(make_message("update", make_indicator()))

    assert connector.api_client.ingest.call_count == 2


def test_run_starts_the_write_back_before_listening(connector):
    order = []
    connector.assurance.start.side_effect = lambda: order.append("assurance")
    connector.helper.listen_stream.side_effect = lambda **_: order.append("stream")

    connector.run()

    assert order == ["assurance", "stream"]


def test_push_indicator_returns_the_stix_id(connector):
    assert connector.push_indicator(make_indicator()) == STIX_ID
    connector.api_client.ingest.assert_called_once()


def test_push_indicator_without_supported_observable_raises(connector):
    indicator = make_indicator()
    indicator["extensions"][OPENCTI_EXTENSION_ID]["observable_values"] = []

    with pytest.raises(ValueError, match="No observable"):
        connector.push_indicator(indicator)
    connector.api_client.ingest.assert_not_called()


# Settings and wiring


def test_write_back_settings_defaults():
    settings = make_settings()

    assert settings.deployment.reporting_enabled is True
    assert settings.deployment.reconciliation_interval == 60
    assert settings.hits.reporting_enabled is True
    assert settings.security_platform.name == "Google SecOps SIEM"
    assert settings.security_platform.type == "SIEM"
    assert settings.security_platform.id is None


def test_build_deployment_assurance_wires_re_push_and_hits():
    connector = build_connector()

    assurance = build_deployment_assurance(connector)

    assert isinstance(assurance.reconciler, DeploymentReconciler)
    assert isinstance(assurance.reconciler._adapter, SecOpsDeploymentAdapter)
    assert assurance.enabled is True


def test_disabled_write_back_is_a_no_op():
    connector = build_connector(
        settings=make_settings(deployment={"reporting_enabled": False})
    )

    assurance = build_deployment_assurance(connector)

    assert assurance.enabled is False
    assert assurance.start() is False
    assert assurance.report_pushed(make_indicator()) is False


# API client


def test_ingest_returns_true_when_the_entities_are_accepted(secops_client):
    secops_client.chronicle_http_session.request.return_value = mock_response({})

    assert secops_client.ingest([{"entity": {"ip": "198.51.100.7"}}]) is True

    kwargs = secops_client.chronicle_http_session.request.call_args.kwargs
    assert kwargs["method"] == "POST"
    assert kwargs["timeout"] == REQUEST_TIMEOUT
    assert kwargs["url"].endswith("/instances/test-instance/entities:import")
    assert kwargs["json"]["inline_source"]["log_type"] == "OPENCTI"


def test_ingest_retries_throttled_requests(secops_client, monkeypatch):
    monkeypatch.setattr("secops_siem_services.api_client.time.sleep", lambda _: None)
    secops_client.chronicle_http_session.request.side_effect = [
        mock_response({}, status_code=429),
        mock_response({}),
    ]

    assert secops_client.ingest([{}]) is True
    assert secops_client.chronicle_http_session.request.call_count == 2


def test_ingest_raises_when_the_request_stays_throttled(secops_client, monkeypatch):
    monkeypatch.setattr("secops_siem_services.api_client.time.sleep", lambda _: None)
    secops_client.chronicle_http_session.request.return_value = mock_response(
        status_code=429, text="quota exceeded"
    )

    with pytest.raises(SecOpsApiError, match="HTTP 429 - quota exceeded"):
        secops_client.ingest([{}])
    assert secops_client.chronicle_http_session.request.call_count == 4


def test_ingest_raises_a_readable_error_when_rejected(secops_client):
    secops_client.chronicle_http_session.request.return_value = mock_response(
        status_code=400, text=' {"error": "invalid entity"} '
    )

    with pytest.raises(SecOpsApiError) as error:
        secops_client.ingest([{}])

    assert str(error.value) == (
        'Entities import rejected: HTTP 400 - {"error": "invalid entity"}'
    )
    assert error.value.status_code == 400


def test_ingest_raises_when_google_secops_cannot_be_reached(secops_client):
    secops_client.chronicle_http_session.request.side_effect = (
        requests.exceptions.ConnectionError("connection refused")
    )

    with pytest.raises(SecOpsApiError, match="connection refused") as error:
        secops_client.ingest([{}])
    assert error.value.status_code is None


def test_ingest_reads_refused_credentials_as_an_authentication_failure(
    secops_client,
):
    secops_client.chronicle_http_session.request.side_effect = RefreshError(
        "invalid_grant"
    )

    with pytest.raises(SecOpsApiError, match="invalid_grant") as error:
        secops_client.ingest([{}])
    assert error.value.status_code == 401


def test_ingest_raises_without_response(secops_client, monkeypatch):
    monkeypatch.setattr(secops_client, "_send_request", lambda **_: None)

    with pytest.raises(SecOpsApiError, match="no response"):
        secops_client.ingest([{}])


def test_list_ioc_matches_sends_the_time_range(secops_client):
    payload = {"matches": [{"id": "1"}], "moreDataAvailable": True}
    secops_client.chronicle_http_session.request.return_value = mock_response(payload)

    matches, more_available = secops_client.list_ioc_matches(
        NOW - timedelta(hours=1), NOW, 100
    )

    assert matches == [{"id": "1"}]
    assert more_available is True
    kwargs = secops_client.chronicle_http_session.request.call_args.kwargs
    assert kwargs["method"] == "GET"
    assert kwargs["timeout"] == REQUEST_TIMEOUT
    assert kwargs["url"].endswith(
        "/instances/test-instance/legacy:legacySearchEnterpriseWideIoCs"
    )
    assert kwargs["params"] == {
        "timestampRange.startTime": "2026-10-03T11:00:00.000000Z",
        "timestampRange.endTime": "2026-10-03T12:00:00.000000Z",
        "maxMatchesToReturn": 100,
        "addMandiantAttributes": "false",
    }


def test_list_ioc_matches_without_match(secops_client):
    secops_client.chronicle_http_session.request.return_value = mock_response({})

    assert secops_client.list_ioc_matches(NOW, NOW, 10) == ([], False)


@pytest.mark.parametrize(
    "response, message",
    [
        (mock_response(status_code=403, text="denied"), "HTTP 403 - denied"),
        (mock_response(ValueError("no json"), text="<html>"), "not JSON"),
        (mock_response({"matches": "oops"}), "'matches' is not a list"),
        (mock_response(["unexpected"]), "'matches' is not a list"),
        (mock_response({"matches": [{"id": "1"}, "x"]}), "a match is not an object"),
        (
            mock_response({"matches": [], "moreDataAvailable": "false"}),
            "'moreDataAvailable' is not a boolean",
        ),
        (
            mock_response({"matches": [], "moreDataAvailable": None}),
            "'moreDataAvailable' is not a boolean",
        ),
    ],
)
def test_list_ioc_matches_errors(secops_client, response, message):
    secops_client.chronicle_http_session.request.return_value = response

    with pytest.raises(SecOpsApiError, match=message):
        secops_client.list_ioc_matches(NOW, NOW, 10)


def test_list_ioc_matches_raises_when_google_secops_cannot_be_reached(secops_client):
    secops_client.chronicle_http_session.request.side_effect = requests.Timeout(
        "timed out"
    )

    with pytest.raises(SecOpsApiError, match="timed out"):
        secops_client.list_ioc_matches(NOW, NOW, 10)


def test_describe_response_without_body():
    assert describe_response(mock_response(status_code=503, text="")) == "HTTP 503"


# Adapter


def test_adapter_push_uses_the_ingest_path(connector):
    adapter = SecOpsDeploymentAdapter(connector)

    assert adapter.push_indicator(make_indicator()) == STIX_ID
    connector.api_client.ingest.assert_called_once()


@pytest.mark.parametrize(
    "error, reason",
    [
        (
            SecOpsApiError("Entities import rejected: HTTP 403 - denied", 403),
            "Google SecOps refused the entity ingestion: permission denied",
        ),
        (
            SecOpsApiError("Cannot import the entities: timed out"),
            "Google SecOps could not be reached for the entity ingestion",
        ),
    ],
)
def test_adapter_push_raises_the_reason_and_logs_the_detail(connector, error, reason):
    connector.api_client.ingest.side_effect = error
    indicator = make_indicator()

    with pytest.raises(SecOpsDeploymentError) as raised:
        SecOpsDeploymentAdapter(connector).push_indicator(indicator)

    assert str(raised.value) == reason
    logged = connector.helper.connector_logger.warning.call_args
    message, meta = logged.args[0], logged.kwargs["meta"]
    assert message == (
        "[DEPLOYMENT] Google SecOps did not take an indicator pushed again."
    )
    assert meta == {"indicator_id": STIX_ID, "error": str(error)}


def test_adapter_collects_hits_from_ioc_matches(connector):
    since = datetime.now(UTC) - timedelta(hours=1)
    recent = datetime.now(UTC) - timedelta(minutes=5)
    connector.api_client.list_ioc_matches.return_value = (
        [
            ioc_match(recent, destinationIpAddress="198.51.100.7"),
            ioc_match(recent, domain="Evil.Example"),
            ioc_match(recent, hashSha256=SHA256.upper()),
            {
                "fieldAndValue": {"value": "198.51.100.7"},
                "lastSeenTimestamp": format_timestamp(recent),
            },
            ioc_match(since - timedelta(minutes=1), domain="evil.example"),
            ioc_match(recent, domain="unknown.example"),
            {"artifactIndicator": "oops", "lastSeenTimestamp": "2026-10-03T11:00:00Z"},
        ],
        False,
    )
    deployments = [
        make_deployment(),
        make_deployment(
            indicator_id=OTHER_ID, pattern="[domain-name:value = 'evil.example']"
        ),
        make_deployment(
            indicator_id="file-id", pattern=f"[file:hashes.'SHA-256' = '{SHA256}']"
        ),
    ]

    hits = list(SecOpsDeploymentAdapter(connector).collect_hits(deployments, since))

    assert [hit.indicator_id for hit in hits] == [
        INDICATOR_ID,
        OTHER_ID,
        "file-id",
        INDICATOR_ID,
    ]
    assert {hit.timestamp for hit in hits} == {recent}
    start, _end, limit = connector.api_client.list_ioc_matches.call_args.args
    assert start == since
    assert limit == MAX_HIT_MATCHES
    connector.helper.connector_logger.warning.assert_not_called()


@pytest.mark.parametrize("last_seen", [None, "not a date"])
def test_adapter_fails_the_hit_read_on_a_match_without_last_seen_time(
    connector, last_seen
):
    connector.api_client.list_ioc_matches.return_value = (
        [ioc_match(last_seen, domain="evil.example")],
        False,
    )

    with pytest.raises(SecOpsApiError, match="without last seen time"):
        SecOpsDeploymentAdapter(connector).collect_hits(
            [make_deployment()], datetime.now(UTC) - timedelta(hours=1)
        )


def test_adapter_credits_every_indicator_sharing_a_value(connector):
    recent = datetime.now(UTC) - timedelta(minutes=5)
    connector.api_client.list_ioc_matches.return_value = (
        [ioc_match(recent, destinationIpAddress="198.51.100.7")],
        False,
    )

    hits = SecOpsDeploymentAdapter(connector).collect_hits(
        [make_deployment(), make_deployment(indicator_id=OTHER_ID)],
        datetime.now(UTC) - timedelta(hours=1),
    )

    assert sorted(hit.indicator_id for hit in hits) == sorted([INDICATOR_ID, OTHER_ID])


def test_adapter_halves_truncated_windows_oldest_first(connector):
    since = NOW - timedelta(hours=1)
    middle = NOW - timedelta(minutes=30)
    shared = ioc_match(NOW - timedelta(minutes=1), destinationIpAddress="198.51.100.7")
    replies = {
        (since, NOW): ([], True),
        (since, middle): ([shared], False),
        (middle, NOW): ([shared, ioc_match(NOW, domain="evil.example")], False),
    }
    connector.api_client.list_ioc_matches.side_effect = (
        lambda start, end, limit: replies[(start, end)]
    )
    deployments = [
        make_deployment(),
        make_deployment(
            indicator_id=OTHER_ID, pattern="[domain-name:value = 'evil.example']"
        ),
    ]

    hits = SecOpsDeploymentAdapter(connector, clock=lambda: NOW).collect_hits(
        deployments, since
    )

    assert [hit.indicator_id for hit in hits] == [INDICATOR_ID, OTHER_ID]
    windows = [
        call.args[:2] for call in connector.api_client.list_ioc_matches.call_args_list
    ]
    assert windows == [(since, NOW), (since, middle), (middle, NOW)]


def test_adapter_resumes_after_the_read_budget(connector, monkeypatch):
    monkeypatch.setattr("secops_siem_connector.deployment.MAX_HIT_WINDOW_READS", 2)
    since = NOW - timedelta(hours=1)
    middle = NOW - timedelta(minutes=30)
    connector.api_client.list_ioc_matches.side_effect = [
        ([], True),
        (
            [
                ioc_match(
                    middle - timedelta(minutes=1), destinationIpAddress="198.51.100.7"
                )
            ],
            False,
        ),
    ]

    collected = SecOpsDeploymentAdapter(connector, clock=lambda: NOW).collect_hits(
        [make_deployment()], since
    )

    assert isinstance(collected, HitCollection)
    assert collected.complete_until == middle
    assert collected.resume is None
    assert [hit.indicator_id for hit in collected.hits] == [INDICATOR_ID]


def test_adapter_credits_hits_on_the_ingested_values_only(connector):
    since = NOW - timedelta(hours=1)
    recent = NOW - timedelta(minutes=5)
    connector.api_client.list_ioc_matches.return_value = (
        [
            ioc_match(recent, domain="evil.example"),
            ioc_match(recent, hashSha256=SHA256),
        ],
        False,
    )
    deployment = make_deployment(
        pattern=(
            f"[file:hashes.'SHA-256' = '{SHA256}' OR process:name = 'evil.example']"
        )
    )

    hits = list(
        SecOpsDeploymentAdapter(connector, clock=lambda: NOW).collect_hits(
            [deployment], since
        )
    )

    assert len(hits) == 1
    assert hits[0].indicator_id == deployment.indicator_id


def test_adapter_hands_the_unread_windows_to_the_next_run(connector, monkeypatch):
    """A budget spent before the window starting at `since` is read is resumed."""
    monkeypatch.setattr("secops_siem_connector.deployment.MAX_HIT_WINDOW_READS", 1)
    since = NOW - timedelta(hours=1)
    middle = NOW - timedelta(minutes=30)
    later = NOW + timedelta(minutes=10)
    match = ioc_match(
        middle + timedelta(minutes=1), destinationIpAddress="198.51.100.7"
    )
    replies = {
        (since, NOW): ([], True),
        (since, middle): ([], False),
        (middle, NOW): ([match], False),
        (NOW, later): ([], False),
    }
    connector.api_client.list_ioc_matches.side_effect = (
        lambda start, end, limit: replies[(start, end)]
    )

    first = SecOpsDeploymentAdapter(connector, clock=lambda: NOW).collect_hits(
        [make_deployment()], since
    )
    monkeypatch.setattr("secops_siem_connector.deployment.MAX_HIT_WINDOW_READS", 8)
    second = SecOpsDeploymentAdapter(connector, clock=lambda: later).collect_hits(
        [make_deployment()], since, resume=first.resume
    )

    assert (first.hits, first.complete_until) == ([], since)
    assert first.resume == (
        NOW.isoformat(),
        (
            (middle.isoformat(), NOW.isoformat()),
            (since.isoformat(), middle.isoformat()),
        ),
    )
    assert [hit.indicator_id for hit in second] == [INDICATOR_ID]
    windows = [
        call.args[:2] for call in connector.api_client.list_ioc_matches.call_args_list
    ]
    assert windows == [(since, NOW), (since, middle), (middle, NOW), (NOW, later)]


@pytest.mark.parametrize("resume", ["unexpected", ("not a date", ()), (None, [])])
def test_adapter_reads_from_the_start_on_a_malformed_continuation(connector, resume):
    since = NOW - timedelta(hours=1)
    connector.api_client.list_ioc_matches.return_value = ([], False)

    hits = SecOpsDeploymentAdapter(connector, clock=lambda: NOW).collect_hits(
        [make_deployment()], since, resume=resume
    )

    assert list(hits) == []
    connector.api_client.list_ioc_matches.assert_called_once_with(
        since, NOW, MAX_HIT_MATCHES
    )


def test_adapter_keeps_the_shortest_window_as_read(connector):
    since = NOW - timedelta(seconds=30)
    connector.api_client.list_ioc_matches.return_value = (
        [ioc_match(NOW, destinationIpAddress="198.51.100.7")],
        True,
    )

    hits = SecOpsDeploymentAdapter(connector, clock=lambda: NOW).collect_hits(
        [make_deployment()], since
    )

    assert [hit.indicator_id for hit in hits] == [INDICATOR_ID]
    connector.api_client.list_ioc_matches.assert_called_once()


def test_adapter_hits_without_values_read_no_match(connector):
    deployment = make_deployment(pattern=None)

    hits = SecOpsDeploymentAdapter(connector).collect_hits([deployment], NOW)

    assert list(hits) == []
    connector.api_client.list_ioc_matches.assert_not_called()


# End to end: stream processing and periodic run through GraphQL


class GraphQLRouter:
    """Fake `helper.api.query` dispatching on the GraphQL operation name."""

    def __init__(self, deployments=None):
        self.calls = []
        self.deployments = deployments or []

    def __call__(self, query, variables=None):
        self.calls.append((query, variables))
        if "DeploymentWriteBackFeatures" in query:
            return {"data": {"indicators": {"edges": []}}}
        if "DeploymentSecurityPlatformAdd" in query:
            return {"data": {"securityPlatformAdd": {"id": PLATFORM_ID}}}
        if "IndicatorReportDeployments(" in query:
            count = len(variables["reports"])
            return {
                "data": {
                    "indicatorReportDeployments": {
                        "processed": count,
                        "created": 0,
                        "updated": count,
                        "unchanged": 0,
                        "errors": [],
                    }
                }
            }
        if "IndicatorReportHits(" in query:
            return {"data": {"indicatorReportHits": {"id": "sighting-id"}}}
        if "IndicatorDeploymentsOfPlatform" in query:
            return {
                "data": {
                    "stixCoreRelationships": {
                        "edges": [{"node": node} for node in self.deployments],
                        "pageInfo": {"endCursor": None, "hasNextPage": False},
                    }
                }
            }
        raise AssertionError(f"Unexpected GraphQL document: {query}")

    def calls_of(self, marker):
        return [variables for query, variables in self.calls if marker in query]


def deployment_node(indicator_id, status, value):
    return {
        "id": f"relationship-{indicator_id}",
        "deployment_status": status,
        "external_id": None,
        "revoked": False,
        "last_sync_at": "2026-10-01T00:00:00.000Z",
        "last_hit_at": None,
        "hit_count": 0,
        "from": {
            "id": indicator_id,
            "standard_id": f"indicator--{indicator_id}",
            "name": value,
            "pattern": f"[ipv4-addr:value = '{value}']",
            "pattern_type": "stix",
            "revoked": False,
            "valid_until": None,
        },
    }


@pytest.fixture(name="router")
def fixture_router():
    return GraphQLRouter()


@pytest.fixture(name="e2e_connector")
def fixture_e2e_connector(no_atexit, router):
    """Connector with a helper without the pycti deployment helpers (GraphQL path)."""
    helper = make_helper(spec=["api", "connector_logger", "listen_stream"])
    helper.get_attribute_in_extension = (
        OpenCTIConnectorHelper.get_attribute_in_extension
    )
    helper.opencti_url = "http://localhost:8080"
    helper.api.query.side_effect = router
    connector = build_connector(helper=helper)
    connector.api_client = MagicMock(spec=SecOpsEntitiesClient)
    connector.assurance = DeploymentAssurance.from_settings(
        helper,
        connector.config,
        adapter=SecOpsDeploymentAdapter(connector),
        reporter_kwargs={"flush_interval": 3600.0},
    )
    return connector


def test_stream_outcomes_are_reported_in_one_batch(e2e_connector, router):
    e2e_connector.api_client.ingest.side_effect = [
        True,
        SecOpsApiError(
            "Entities import rejected: HTTP 400 - invalid entity", status_code=400
        ),
    ]

    e2e_connector.process_message(make_message("create", make_indicator()))
    e2e_connector.process_message(
        make_message("create", make_indicator(indicator_id=OTHER_ID))
    )
    result = e2e_connector.assurance.flush()

    assert result.processed == 2
    assert router.calls_of("DeploymentSecurityPlatformAdd") == [
        {
            "input": {
                "name": "Google SecOps SIEM",
                "update": True,
                "security_platform_type": "SIEM",
            }
        }
    ]
    (batch,) = router.calls_of("IndicatorReportDeployments(")
    deployed, failed = batch["reports"]
    assert deployed == {
        "indicatorId": INDICATOR_ID,
        "status": "deployed",
        "externalId": STIX_ID,
    }
    assert failed["indicatorId"] == OTHER_ID
    assert failed["status"] == "failed"
    assert failed["metadata"]["error_message"] == (
        "Google SecOps refused the entity ingestion: invalid request"
    )


def test_periodic_run_repushes_pending_deployments_and_reports_hits(
    e2e_connector, router
):
    router.deployments = [
        deployment_node(INDICATOR_ID, "deployed", "198.51.100.7"),
        deployment_node(OTHER_ID, "pending", "203.0.113.9"),
    ]
    e2e_connector.helper.api.stix2.get_stix_bundle_or_object_from_entity_id.return_value = {
        "type": "indicator",
        "id": "indicator--other",
        "pattern": "[ipv4-addr:value = '203.0.113.9']",
        "pattern_type": "stix",
        "valid_from": "2026-10-01T00:00:00.000Z",
        "valid_until": "2027-10-01T00:00:00.000Z",
        "x_opencti_score": 70,
    }
    last_seen = datetime.now(UTC) - timedelta(minutes=5)
    e2e_connector.api_client.list_ioc_matches.return_value = (
        [ioc_match(last_seen, destinationIpAddress="198.51.100.7")],
        False,
    )

    summary = e2e_connector.assurance.reconciler.run_once()

    assert summary.skipped is False
    assert summary.repushed == 1
    assert summary.confirmed_active == summary.marked_removed == 0
    assert summary.hits_reported == 1
    (entities,) = e2e_connector.api_client.ingest.call_args.args
    assert entities[0]["entity"] == {"ip": "203.0.113.9"}
    (batch,) = router.calls_of("IndicatorReportDeployments(")
    (report,) = batch["reports"]
    assert report["indicatorId"] == OTHER_ID
    assert report["status"] == "deployed"
    assert report["externalId"] == "indicator--other"
    (hits,) = router.calls_of("IndicatorReportHits(")
    assert hits["indicatorId"] == INDICATOR_ID
    assert hits["count"] == 1


def test_hit_collection_errors_do_not_stop_the_periodic_run(e2e_connector, router):
    router.deployments = [deployment_node(INDICATOR_ID, "active", "198.51.100.7")]
    e2e_connector.api_client.list_ioc_matches.side_effect = SecOpsApiError(
        "IoC matches listing rejected: HTTP 403 - denied"
    )

    summary = e2e_connector.assurance.reconciler.run_once()

    assert summary.skipped is False
    assert summary.hits_reported == 0
    assert router.calls_of("IndicatorReportHits(") == []
