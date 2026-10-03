"""Deployment write-back of the Microsoft Defender Intel connector."""

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
import requests
from connectors_sdk import DeploymentAssurance, IndicatorDeployment, VendorIndicator
from microsoft_defender_intel_connector import (
    ConnectorSettings,
    MicrosoftDefenderIntelConnector,
)
from microsoft_defender_intel_connector.api_handler import (
    APPLICATION_NAME,
    DefenderApiHandlerError,
)
from microsoft_defender_intel_connector.deployment import (
    DefenderDeploymentError,
    MicrosoftDefenderDeploymentAdapter,
    build_deployment_assurance,
    describe_error,
)
from pycti import OpenCTIConnectorHelper

OPENCTI_EXTENSION_ID = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
PLATFORM_ID = "6c3b0f4e-2d41-4a77-8f0d-3e1c9b5a7d21"
INDICATOR_ID = "0d8b4f0e-6a43-4f11-8f6c-1d2f5e6a7b8c"
OTHER_ID = "1e9c5f1f-7b54-4a22-9e7d-2e3f6a7b8c9d"
DEFENDER_ID = "6371"
INDICATORS_URL = "https://api.securitycenter.microsoft.com/api/indicators"
ALERTS_URL = "https://api.securitycenter.microsoft.com/api/alerts"


def make_settings(**namespaces: dict[str, Any]) -> ConnectorSettings:
    """Build connector settings from a valid configuration and overrides."""
    config = {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "connector": {"live_stream_id": "live"},
        "microsoft_defender_intel": {
            "tenant_id": "tenant",
            "client_id": "client",
            "client_secret": "secret",
        },
    }
    for namespace, values in namespaces.items():
        config[namespace] = {**config.get(namespace, {}), **values}

    class StubConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(config)

    return StubConnectorSettings()


def make_indicator(indicator_id=INDICATOR_ID, value="198.51.100.7"):
    return {
        "id": "indicator--5d4f2a3b-8c9d-4e1f-a2b3-c4d5e6f7a8b9",
        "type": "indicator",
        "spec_version": "2.1",
        "name": value,
        "pattern": f"[ipv4-addr:value = '{value}']",
        "pattern_type": "stix",
        "valid_from": "2026-10-01T00:00:00.000Z",
        "extensions": {
            OPENCTI_EXTENSION_ID: {
                "id": indicator_id,
                "type": "Indicator",
                "score": 80,
                "updated_at": "2026-10-01T00:00:00.000Z",
                "observable_values": [{"type": "IPv4-Addr", "value": value}],
            }
        },
    }


def make_message(event, data):
    return SimpleNamespace(event=event, data=json.dumps({"data": data}))


def http_error(status_code: int, text: str) -> DefenderApiHandlerError:
    """Build the error raised by the API handler for an HTTP error."""
    response = requests.Response()
    response.status_code = status_code
    response._content = text.encode()
    error = DefenderApiHandlerError(
        "[API] An error occurred during request", {"url_path": "POST /api"}
    )
    error.__cause__ = requests.HTTPError(
        f"{status_code} Client Error", response=response
    )
    return error


def make_deployment(indicator_id=INDICATOR_ID, value="198.51.100.7"):
    return IndicatorDeployment(
        relationship_id=f"relationship-{indicator_id}",
        status="deployed",
        indicator_id=indicator_id,
        pattern=f"[ipv4-addr:value = '{value}']",
        pattern_type="stix",
    )


def make_helper(spec: list[str] | None = None) -> MagicMock:
    helper = MagicMock(spec=spec) if spec is not None else MagicMock()
    helper.connect_live_stream_id = "live"
    helper.get_attribute_in_extension = (
        OpenCTIConnectorHelper.get_attribute_in_extension
    )
    return helper


def build_connector(settings=None, helper=None, assurance=None):
    connector = MicrosoftDefenderIntelConnector(
        config=settings or make_settings(),
        helper=helper or make_helper(),
        assurance=assurance,
    )
    connector.api._send_request = MagicMock()
    return connector


@pytest.fixture(name="connector")
def fixture_connector():
    return build_connector(assurance=MagicMock(spec=DeploymentAssurance))


@pytest.fixture(name="no_atexit")
def fixture_no_atexit(monkeypatch):
    """Do not register the exit flush of the deployment reporter during tests."""
    monkeypatch.setattr(
        "connectors_sdk.connectors.stream.deployment.reporter.atexit.register",
        lambda _handler: None,
    )


# Stream path


def test_created_indicator_is_reported_deployed(connector):
    connector.api._send_request.return_value = {"id": DEFENDER_ID}
    indicator = make_indicator()

    connector.process_message(make_message("create", indicator))

    connector.assurance.report_pushed.assert_called_once_with(
        indicator, external_id=DEFENDER_ID
    )
    body = connector.api._send_request.call_args.kwargs["json"]
    assert body["application"] == APPLICATION_NAME
    assert body["externalId"] == INDICATOR_ID
    assert body["indicatorValue"] == "198.51.100.7"


def test_rejected_indicator_is_reported_failed(connector):
    connector.api._send_request.side_effect = http_error(
        400, '{"error": {"message": "Invalid indicator value"}}'
    )
    indicator = make_indicator()

    connector.process_message(make_message("create", indicator))

    connector.assurance.report_push_failed.assert_called_once()
    reported, message = connector.assurance.report_push_failed.call_args.args
    assert reported == indicator
    assert message.startswith("[API] An error occurred during request: 400 Client")
    assert message.endswith('Invalid indicator value"}}')
    connector.assurance.report_pushed.assert_not_called()


def test_external_reference_errors_do_not_abort_the_dissemination(connector):
    connector.api._send_request.return_value = {"id": DEFENDER_ID}
    connector.helper.api.external_reference.create.side_effect = ValueError("boom")

    connector.process_message(make_message("create", make_indicator()))

    connector.assurance.report_pushed.assert_called_once()
    connector.helper.connector_logger.warning.assert_called_once_with(
        "[CREATE] Cannot add the Microsoft Defender external reference",
        {"defender_id": DEFENDER_ID, "error": "boom"},
    )


def test_indicator_without_observable_is_not_reported(connector):
    indicator = make_indicator()
    del indicator["extensions"][OPENCTI_EXTENSION_ID]["observable_values"]

    connector.process_message(make_message("create", indicator))

    connector.api._send_request.assert_not_called()
    connector.assurance.report_pushed.assert_not_called()
    connector.assurance.report_push_failed.assert_not_called()


def test_streamed_observables_are_not_reported(connector):
    connector.api._send_request.return_value = {"id": DEFENDER_ID}
    observable = {
        "id": "ipv4-addr--x",
        "type": "ipv4-addr",
        "value": "198.51.100.7",
        "extensions": {
            OPENCTI_EXTENSION_ID: {
                "id": OTHER_ID,
                "score": 50,
                "updated_at": "2026-10-01T00:00:00.000Z",
            }
        },
    }

    connector.process_message(make_message("create", observable))

    connector.api._send_request.assert_called_once()
    connector.assurance.report_pushed.assert_not_called()


def test_updated_indicator_is_reported_deployed(connector):
    connector.api._send_request.side_effect = [
        {"value": [{"id": DEFENDER_ID}]},
        {"id": DEFENDER_ID},
    ]
    indicator = make_indicator()

    connector.process_message(make_message("update", indicator))

    connector.assurance.report_pushed.assert_called_once_with(
        indicator, external_id=DEFENDER_ID
    )


def test_update_of_an_absent_indicator_is_not_reported(connector):
    connector.api._send_request.return_value = {"value": []}

    connector.process_message(make_message("update", make_indicator()))

    connector.assurance.report_pushed.assert_not_called()
    connector.assurance.report_push_failed.assert_not_called()


def test_failed_update_is_reported_failed(connector):
    connector.api._send_request.side_effect = [
        {"value": [{"id": DEFENDER_ID}]},
        http_error(403, "Forbidden"),
    ]

    connector.process_message(make_message("update", make_indicator()))

    message = connector.assurance.report_push_failed.call_args.args[1]
    assert message.endswith("403 Client Error - Forbidden")


def test_delete_is_reported_removed(connector):
    connector.api._send_request.side_effect = [
        {"value": [{"id": DEFENDER_ID}]},
        None,
    ]
    connector.helper.api.external_reference.read.return_value = {"id": "ref"}
    indicator = make_indicator()

    connector.process_message(make_message("delete", indicator))

    connector.assurance.report_removed.assert_called_once_with(
        indicator, external_id=DEFENDER_ID
    )
    connector.helper.api.external_reference.delete.assert_called_once_with("ref")


def test_delete_of_an_absent_indicator_is_reported_removed(connector):
    connector.api._send_request.return_value = {"value": []}
    indicator = make_indicator()

    connector.process_message(make_message("delete", indicator))

    connector.assurance.report_removed.assert_called_once_with(
        indicator, external_id=None
    )


def test_failed_delete_is_not_reported_removed(connector):
    connector.api._send_request.side_effect = [
        {"value": [{"id": DEFENDER_ID}]},
        http_error(500, "Internal error"),
    ]

    connector.process_message(make_message("delete", make_indicator()))

    connector.assurance.report_removed.assert_not_called()


def test_external_reference_cleanup_errors_are_logged(connector):
    connector.api._send_request.side_effect = [
        {"value": [{"id": DEFENDER_ID}]},
        None,
    ]
    connector.helper.api.external_reference.read.side_effect = ValueError("boom")

    connector.process_message(make_message("delete", make_indicator()))

    connector.assurance.report_removed.assert_called_once()
    connector.helper.connector_logger.warning.assert_called_once_with(
        "[DELETE] Cannot delete the Microsoft Defender external reference",
        {"defender_id": DEFENDER_ID, "error": "boom"},
    )


def test_connector_works_without_write_back():
    connector = build_connector()
    connector.api._send_request.return_value = {"id": DEFENDER_ID}

    connector.process_message(make_message("create", make_indicator()))

    connector.api._send_request.assert_called_once()


def test_run_starts_the_write_back(connector):
    connector.run()

    connector.assurance.start.assert_called_once_with()
    connector.helper.listen_stream.assert_called_once_with(
        message_callback=connector.process_message
    )


def test_describe_error():
    error = DefenderApiHandlerError("[API] Failed", {})

    assert describe_error(error) == "[API] Failed"
    error.__cause__ = requests.Timeout("read timeout")
    assert describe_error(error) == "[API] Failed: read timeout"
    assert describe_error(ValueError()) == "ValueError"


# Settings and factory


def test_write_back_settings_defaults():
    settings = make_settings()

    assert settings.deployment.reporting_enabled is True
    assert settings.deployment.reconciliation_interval == 60
    assert settings.hits.reporting_enabled is True
    assert settings.security_platform.name == "Microsoft Defender for Endpoint"
    assert settings.security_platform.type == "EDR"
    assert settings.security_platform.id is None


def test_build_deployment_assurance_wires_reconciliation_and_hits():
    connector = build_connector()

    assurance = build_deployment_assurance(connector)

    assert assurance.enabled is True
    assert assurance.reporter.hits_enabled is True
    assert isinstance(assurance.reconciler._adapter, MicrosoftDefenderDeploymentAdapter)


def test_disabled_write_back_is_a_no_op():
    connector = build_connector(
        settings=make_settings(deployment={"reporting_enabled": False})
    )

    assurance = build_deployment_assurance(connector)

    assert assurance.enabled is False
    assert assurance.start() is False
    assert assurance.report_pushed(make_indicator()) is False
    assert assurance.reconciler.start() is False
    connector.helper.api.query.assert_not_called()


# API handler


def test_iter_application_indicators_pages_with_top_and_skip():
    connector = build_connector()
    connector.api._send_request.side_effect = [
        {"value": [{"id": "1"}, {"id": "2"}]},
        {"value": [{"id": "3"}, "ignored"]},
    ]

    indicators = list(connector.api.iter_application_indicators(page_size=2))

    assert [indicator["id"] for indicator in indicators] == ["1", "2", "3"]
    first, second = connector.api._send_request.call_args_list
    assert first.args == ("get", INDICATORS_URL)
    assert first.kwargs["params"] == (
        "$filter=application%20eq%20%27OpenCTI%20Microsoft%20Defender%20Intel%27"
        "&$top=2&$skip=0"
    )
    assert second.kwargs["params"].endswith("&$top=2&$skip=2")


def test_iter_application_indicators_never_returns_a_partial_listing():
    connector = build_connector()
    connector.api._send_request.return_value = {"value": [{"id": "1"}]}

    with pytest.raises(DefenderApiHandlerError) as error:
        list(connector.api.iter_application_indicators(page_size=1, max_pages=3))

    assert error.value.metadata == {"max_pages": 3, "page_size": 1}

    connector.api._send_request.return_value = None
    with pytest.raises(DefenderApiHandlerError) as error:
        list(connector.api.iter_application_indicators())
    assert error.value.msg.startswith("[API] Unexpected response format")


def test_list_alerts_expands_the_evidence_and_is_bounded(monkeypatch):
    monkeypatch.setattr(
        "microsoft_defender_intel_connector.api_handler.MAX_PAGE_SIZE", 2
    )
    connector = build_connector()
    connector.api._send_request.side_effect = [
        {"value": [{"id": "a1"}, {"id": "a2"}]},
        {"value": [{"id": "a3"}, {"id": "a4"}]},
    ]
    since = datetime(2026, 10, 3, 10, 0, tzinfo=UTC)

    alerts = connector.api.list_alerts(since, max_alerts=3)

    assert [alert["id"] for alert in alerts] == ["a1", "a2", "a3"]
    first, second = connector.api._send_request.call_args_list
    assert first.args == ("get", ALERTS_URL)
    assert first.kwargs["params"] == (
        "$filter=alertCreationTime%20ge%202026-10-03T10%3A00%3A00Z"
        "&$expand=evidence&$top=2&$skip=0"
    )
    assert second.kwargs["params"].endswith("&$top=1&$skip=2")


def test_list_alerts_stops_on_a_short_page():
    connector = build_connector()
    connector.api._send_request.return_value = {"value": [{"id": "a1"}]}

    alerts = connector.api.list_alerts(datetime.now(UTC), max_alerts=50)

    assert alerts == [{"id": "a1"}]
    connector.api._send_request.assert_called_once()


# Vendor adapter


def test_adapter_lists_the_live_indicators_of_the_connector():
    connector = build_connector()
    future = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    connector.api.iter_application_indicators = MagicMock(
        return_value=iter(
            [
                {
                    "id": 1,
                    "indicatorValue": "198.51.100.7",
                    "externalId": INDICATOR_ID,
                    "expirationTime": future,
                },
                {"id": 2, "indicatorValue": "203.0.113.9", "externalId": None},
                {"id": 3, "indicatorValue": "old.example", "expirationTime": past},
                {"indicatorValue": "no-id.example"},
            ]
        )
    )

    vendor_indicators = list(
        MicrosoftDefenderDeploymentAdapter(connector).list_vendor_indicators()
    )

    assert vendor_indicators == [
        VendorIndicator(
            indicator_id=INDICATOR_ID, external_id="1", value="198.51.100.7"
        ),
        VendorIndicator(indicator_id=None, external_id="2", value="203.0.113.9"),
    ]
    connector.api.iter_application_indicators.assert_called_once_with(APPLICATION_NAME)


def test_adapter_read_back_errors_are_readable():
    connector = build_connector()
    connector.api.iter_application_indicators = MagicMock(
        side_effect=http_error(401, "Unauthorized")
    )

    with pytest.raises(DefenderDeploymentError, match="401 Client Error"):
        list(MicrosoftDefenderDeploymentAdapter(connector).list_vendor_indicators())


def test_adapter_removal():
    connector = build_connector()
    adapter = MicrosoftDefenderDeploymentAdapter(connector)
    vendor_indicator = VendorIndicator(external_id=DEFENDER_ID, raw={"id": 6371})

    adapter.remove_vendor_indicator(vendor_indicator, make_deployment())
    connector.api._send_request.assert_called_once_with(
        "delete", f"{INDICATORS_URL}/6371"
    )

    connector.api._send_request.side_effect = http_error(404, "Not found")
    adapter.remove_vendor_indicator(vendor_indicator, make_deployment())

    connector.api._send_request.side_effect = http_error(403, "Forbidden")
    with pytest.raises(DefenderDeploymentError, match="Forbidden"):
        adapter.remove_vendor_indicator(vendor_indicator, make_deployment())


def test_adapter_push():
    connector = build_connector()
    adapter = MicrosoftDefenderDeploymentAdapter(connector)
    connector.api._send_request.return_value = {"id": DEFENDER_ID}

    assert adapter.push_indicator(make_indicator()) == DEFENDER_ID

    indicator = make_indicator()
    del indicator["extensions"][OPENCTI_EXTENSION_ID]["observable_values"]
    with pytest.raises(ValueError, match="No observable"):
        adapter.push_indicator(indicator)

    connector.api._send_request.side_effect = http_error(400, "Invalid value")
    with pytest.raises(DefenderDeploymentError, match="Invalid value"):
        adapter.push_indicator(make_indicator())


def test_adapter_collects_hits_from_alert_evidence():
    connector = build_connector()
    since = datetime(2026, 10, 3, 11, 0, tzinfo=UTC)
    sha256 = "37c09c95f77e5677332de338b7e972cff67347ed2c807c15b415c41b0d4a9ac4"
    connector.api.list_alerts = MagicMock(
        return_value=[
            {
                "alertCreationTime": "2026-10-03T11:10:00Z",
                "evidence": [{"entityType": "Ip", "ipAddress": "198.51.100.7"}],
            },
            {
                "alertCreationTime": "2026-10-03T11:20:00Z",
                "evidence": [
                    {"entityType": "Url", "url": "https://evil.example/payload"},
                    {"entityType": "File", "sha256": sha256.upper()},
                    "ignored",
                ],
            },
            {
                "alertCreationTime": "2026-10-03T11:30:00Z",
                "evidence": [{"entityType": "User", "domainName": "EVIL.EXAMPLE"}],
            },
            {
                "alertCreationTime": "2026-10-03T10:00:00Z",
                "evidence": [{"ipAddress": "198.51.100.7"}],
            },
            {"evidence": [{"ipAddress": "198.51.100.7"}]},
        ]
    )
    deployments = [
        make_deployment(),
        IndicatorDeployment(
            relationship_id="r2",
            status="active",
            indicator_id=OTHER_ID,
            pattern="[domain-name:value = 'evil.example']",
            pattern_type="stix",
        ),
        IndicatorDeployment(
            relationship_id="r3",
            status="active",
            indicator_id="hash-indicator",
            pattern=f"[file:hashes.'SHA-256' = '{sha256}']",
            pattern_type="stix",
        ),
    ]

    hits = list(
        MicrosoftDefenderDeploymentAdapter(connector).collect_hits(deployments, since)
    )

    assert [(hit.indicator_id, hit.timestamp.minute) for hit in hits] == [
        (INDICATOR_ID, 10),
        (OTHER_ID, 20),
        ("hash-indicator", 20),
    ]
    connector.api.list_alerts.assert_called_once_with(since, 10_000)


def test_adapter_hits_without_values_read_no_alert():
    connector = build_connector()
    connector.api.list_alerts = MagicMock()
    deployment = IndicatorDeployment(
        relationship_id="r", status="deployed", indicator_id=INDICATOR_ID
    )

    adapter = MicrosoftDefenderDeploymentAdapter(connector)
    assert adapter.collect_hits([deployment], datetime.now(UTC)) == []
    connector.api.list_alerts.assert_not_called()


# End to end: stream processing and reconciliation through GraphQL


class GraphQLRouter:
    """Fake `helper.api.query` dispatching on the GraphQL operation name."""

    def __init__(self, deployments=None):
        self.calls = []
        self.deployments = deployments or []

    def __call__(self, query, variables=None):
        self.calls.append((query, variables))
        if "DeploymentWriteBackFeatures" in query:
            fields = [
                {"name": "indicatorReportDeployment"},
                {"name": "indicatorReportDeployments"},
                {"name": "indicatorReportHits"},
            ]
            return {"data": {"__type": {"fields": fields}}}
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
    helper = make_helper(
        spec=[
            "api",
            "connector_logger",
            "listen_stream",
            "connect_live_stream_id",
            "get_attribute_in_extension",
        ]
    )
    helper.api.query.side_effect = router
    connector = build_connector(helper=helper)
    connector.assurance = DeploymentAssurance.from_settings(
        helper,
        connector.config,
        adapter=MicrosoftDefenderDeploymentAdapter(connector),
        reporter_kwargs={"flush_interval": 3600.0},
    )
    return connector


def test_stream_outcomes_are_reported_in_one_batch(e2e_connector, router):
    e2e_connector.api._send_request.side_effect = [
        {"id": DEFENDER_ID},
        http_error(400, "Invalid value"),
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
                "name": "Microsoft Defender for Endpoint",
                "update": True,
                "security_platform_type": "EDR",
            }
        }
    ]
    (batch,) = router.calls_of("IndicatorReportDeployments(")
    deployed, failed = batch["reports"]
    assert deployed == {
        "indicatorId": INDICATOR_ID,
        "status": "deployed",
        "externalId": DEFENDER_ID,
    }
    assert failed["indicatorId"] == OTHER_ID
    assert failed["status"] == "failed"
    assert failed["metadata"]["error_message"].endswith("Invalid value")


def test_reconciliation_and_hits_are_reported(e2e_connector, router):
    router.deployments = [
        deployment_node(INDICATOR_ID, "deployed", "198.51.100.7"),
        deployment_node(OTHER_ID, "active", "203.0.113.9"),
    ]
    alert_time = (datetime.now(UTC) - timedelta(minutes=5)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    e2e_connector.api._send_request.side_effect = [
        {
            "value": [
                {
                    "id": 6371,
                    "indicatorValue": "198.51.100.7",
                    "externalId": INDICATOR_ID,
                }
            ]
        },
        {
            "value": [
                {
                    "alertCreationTime": alert_time,
                    "evidence": [{"ipAddress": "198.51.100.7"}],
                }
            ]
        },
    ]

    summary = e2e_connector.assurance.reconciler.run_once()

    assert summary.skipped is False
    assert summary.confirmed_active == 1
    assert summary.marked_removed == 1
    assert summary.hits_reported == 1
    (batch,) = router.calls_of("IndicatorReportDeployments(")
    reports = {report["indicatorId"]: report for report in batch["reports"]}
    assert reports[INDICATOR_ID]["status"] == "active"
    assert reports[INDICATOR_ID]["externalId"] == "6371"
    assert reports[OTHER_ID]["status"] == "removed"
    (hits,) = router.calls_of("IndicatorReportHits(")
    assert hits["indicatorId"] == INDICATOR_ID
    assert hits["count"] == 1


def test_read_back_failure_skips_the_reconciliation(e2e_connector, router):
    router.deployments = [deployment_node(INDICATOR_ID, "active", "198.51.100.7")]
    e2e_connector.api._send_request.side_effect = http_error(503, "Unavailable")

    summary = e2e_connector.assurance.reconciler.run_once()

    assert summary.skipped is True
    assert "Unavailable" in summary.reason
    assert router.calls_of("IndicatorReportDeployments(") == []
