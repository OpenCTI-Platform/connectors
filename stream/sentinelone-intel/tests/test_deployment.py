"""Deployment write-back of the SentinelOne Intel connector."""

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
import requests
from connectors_sdk import (
    DeploymentAssurance,
    DeploymentReconciler,
    IndicatorDeployment,
)
from connectors_sdk.connectors.stream.deployment import VendorIndicator
from pycti import OpenCTIConnectorHelper
from sentinelone_connector import SentinelOneIntelConnector
from sentinelone_connector.deployment import (
    SentinelOneDeploymentAdapter,
    SentinelOneDeploymentError,
    build_deployment_assurance,
)
from sentinelone_connector.settings import ConnectorSettings
from sentinelone_services import SentinelOneApiError
from sentinelone_services.client import IOCS_ENDPOINT_URL, describe_response

OPENCTI_EXTENSION_ID = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
PLATFORM_ID = "6c3b0f4e-2d41-4a77-8f0d-3e1c9b5a7d21"
INDICATOR_ID = "0d8b4f0e-6a43-4f11-8f6c-1d2f5e6a7b8c"
OTHER_ID = "1e9c5f1f-7b54-4a22-9e7d-2e3f6a7b8c9d"
STIX_ID = "indicator--5d4f2a3b-8c9d-4e1f-a2b3-c4d5e6f7a8b9"
OTHER_STIX_ID = "indicator--6e5a3b4c-9d0e-4f2a-b3c4-d5e6f7a8b9c0"
API_URL = "https://tenant.sentinelone.net"


def make_settings(**namespaces: dict[str, Any]) -> ConnectorSettings:
    """Build connector settings from a valid configuration and overrides."""
    config = {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "connector": {"id": "connector-id", "live_stream_id": "live"},
        "sentinelone_intel": {
            "api_url": API_URL,
            "api_key": "secret",
            "account_id": "1234",
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
        "extensions": {
            OPENCTI_EXTENSION_ID: {"id": indicator_id, "type": "Indicator", "score": 80}
        },
    }


def make_message(event, data):
    return SimpleNamespace(event=event, data=json.dumps({"data": data}), id="1-0")


def make_helper(spec: list[str] | None = None) -> MagicMock:
    helper = MagicMock(spec=spec) if spec is not None else MagicMock()
    helper.get_attribute_in_extension = (
        OpenCTIConnectorHelper.get_attribute_in_extension
    )
    return helper


def mock_response(json_data=None, status_code=200, text=None):
    response = MagicMock(spec=requests.Response)
    response.status_code = status_code
    if isinstance(json_data, Exception):
        response.json.side_effect = json_data
    else:
        response.json.return_value = json_data
    response.text = text if text is not None else json.dumps(json_data)
    response.content = response.text.encode() if json_data is not None or text else b""
    return response


def build_connector(settings=None, helper=None, assurance=None):
    connector = SentinelOneIntelConnector(
        config=settings or make_settings(), helper=helper or make_helper()
    )
    connector.client.session = MagicMock()
    connector.assurance = assurance
    return connector


def make_deployment(indicator_id=INDICATOR_ID, value="198.51.100.7", **fields):
    return IndicatorDeployment(
        relationship_id=f"relationship-{indicator_id}",
        status=fields.pop("status", "deployed"),
        indicator_id=indicator_id,
        indicator_standard_id=fields.pop("indicator_standard_id", STIX_ID),
        pattern=fields.pop("pattern", f"[ipv4-addr:value = '{value}']"),
        pattern_type="stix",
        **fields,
    )


def calls_of(session, method):
    return [call for call in session.request.call_args_list if call.args[0] == method]


@pytest.fixture(name="connector")
def fixture_connector(monkeypatch):
    monkeypatch.setattr("sentinelone_services.client.time.sleep", lambda _: None)
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
    connector.client.session.request.return_value = mock_response(
        {"data": [{"uuid": "uuid-1"}, {"uuid": "uuid-2"}]}
    )
    indicator = make_indicator()

    connector.process_message(make_message("create", indicator))

    method, url = connector.client.session.request.call_args.args
    assert method == "POST"
    assert url == f"{API_URL}/web/api/v2.1/threat-intelligence/iocs/stix"
    assert connector.client.session.request.call_args.kwargs["json"] == {
        "bundle": {"objects": [indicator]},
        "filter": {"tenant": "false", "accountIds": [1234]},
    }
    connector.assurance.report_pushed.assert_called_once_with(
        indicator, external_id="uuid-1"
    )


@pytest.mark.parametrize("payload", [{}, {"data": {"affected": 1}}, None])
def test_created_indicator_without_returned_uuid(connector, payload):
    connector.client.session.request.return_value = mock_response(payload)
    indicator = make_indicator()

    connector.process_message(make_message("create", indicator))

    connector.assurance.report_pushed.assert_called_once_with(
        indicator, external_id=None
    )


def test_rejected_indicator_is_reported_failed(connector):
    connector.client.session.request.return_value = mock_response(
        status_code=400, text='{"errors": [{"title": "Validation Error"}]}'
    )
    indicator = make_indicator()

    connector.process_message(make_message("create", indicator))

    (reported, error), _ = connector.assurance.report_push_failed.call_args
    assert reported == indicator
    assert str(error) == (
        'SentinelOne request rejected: HTTP 400 - {"errors": [{"title": "Validation Error"}]}'
    )
    connector.assurance.report_pushed.assert_not_called()


def test_unsupported_pattern_is_not_pushed_nor_reported(connector):
    indicator = make_indicator()
    indicator["pattern"] = "[process:name = 'evil.exe']"

    connector.process_message(make_message("create", indicator))

    connector.client.session.request.assert_not_called()
    connector.assurance.report_pushed.assert_not_called()
    connector.assurance.report_push_failed.assert_not_called()


def test_update_and_foreign_events_are_ignored(connector):
    connector.process_message(make_message("update", make_indicator()))
    connector.process_message(
        make_message("create", {"type": "malware", "pattern_type": None})
    )

    connector.client.session.request.assert_not_called()


def test_invalid_message_raises(connector):
    with pytest.raises(ValueError, match="Cannot process the message"):
        connector.process_message(SimpleNamespace(event="create", data="not json"))


def test_delete_removes_the_iocs_created_from_the_indicator(connector):
    connector.client.session.request.side_effect = [
        mock_response(
            {
                "data": [
                    {"uuid": "uuid-1", "externalId": STIX_ID},
                    {"uuid": "uuid-2", "externalId": "other-source"},
                    {"externalId": STIX_ID},
                ],
                "pagination": {"nextCursor": None},
            }
        ),
        mock_response({"data": {"affected": 1}}),
    ]
    indicator = make_indicator()

    connector.process_message(make_message("delete", indicator))

    (listing,) = calls_of(connector.client.session, "GET")
    assert listing.args[1] == f"{API_URL}{IOCS_ENDPOINT_URL}"
    assert listing.kwargs["params"] == {
        "accountIds": "1234",
        "externalId": STIX_ID,
        "limit": "1000",
    }
    (deletion,) = calls_of(connector.client.session, "DELETE")
    assert deletion.kwargs["json"] == {
        "filter": {"uuids": ["uuid-1"], "accountIds": [1234]}
    }
    connector.assurance.report_removed.assert_called_once_with(indicator)


def test_delete_without_ioc_of_the_indicator_is_not_reported(connector):
    connector.client.session.request.return_value = mock_response(
        {"data": [{"uuid": "uuid-2", "externalId": "other-source"}]}
    )

    connector.process_message(make_message("delete", make_indicator()))

    assert calls_of(connector.client.session, "DELETE") == []
    connector.assurance.report_removed.assert_not_called()


def test_delete_of_an_indicator_without_stix_id_reads_nothing(connector):
    assert connector.delete_indicator(make_indicator(stix_id="not-a-stix-id")) is False
    connector.client.session.request.assert_not_called()


def test_failed_delete_is_not_reported(connector):
    connector.client.session.request.return_value = mock_response(
        status_code=500, text="boom"
    )

    connector.process_message(make_message("delete", make_indicator()))

    connector.assurance.report_removed.assert_not_called()
    connector.helper.connector_logger.warning.assert_called()


def test_connector_works_without_write_back(monkeypatch):
    monkeypatch.setattr("sentinelone_services.client.time.sleep", lambda _: None)
    connector = build_connector()
    connector.client.session.request.side_effect = [
        mock_response({"data": [{"uuid": "uuid-1"}]}),
        mock_response(status_code=400, text="rejected"),
        mock_response({"data": [{"uuid": "uuid-1", "externalId": STIX_ID}]}),
        mock_response({}),
    ]

    connector.process_message(make_message("create", make_indicator()))
    connector.process_message(make_message("create", make_indicator()))
    connector.process_message(make_message("delete", make_indicator()))

    assert connector.client.session.request.call_count == 4


def test_run_starts_the_write_back_before_listening(connector):
    order = []
    connector.assurance.start.side_effect = lambda: order.append("assurance")
    connector.helper.listen_stream.side_effect = lambda **_: order.append("stream")

    connector.run()

    assert order == ["assurance", "stream"]


def test_push_indicator(connector):
    connector.client.session.request.side_effect = [
        mock_response({"data": [{"uuid": "uuid-9"}]}),
        mock_response({}),
    ]

    assert connector.push_indicator(make_indicator()) == "uuid-9"
    assert connector.push_indicator(make_indicator()) is None

    unsupported = make_indicator()
    unsupported["pattern"] = "[process:name = 'evil.exe']"
    with pytest.raises(ValueError, match="not supported"):
        connector.push_indicator(unsupported)


# Settings and wiring


def test_write_back_settings_defaults():
    settings = make_settings()

    assert settings.deployment.reporting_enabled is True
    assert settings.deployment.reconciliation_interval == 60
    assert settings.security_platform.name == "SentinelOne"
    assert settings.security_platform.type == "EDR"
    assert settings.security_platform.id is None


def test_build_deployment_assurance_wires_the_reconciliation_without_hits():
    connector = build_connector()

    assurance = build_deployment_assurance(connector)

    assert isinstance(assurance.reconciler, DeploymentReconciler)
    assert isinstance(assurance.reconciler._adapter, SentinelOneDeploymentAdapter)
    assert assurance.reporter.hits_enabled is False


def test_disabled_write_back_is_a_no_op():
    connector = build_connector(
        settings=make_settings(deployment={"reporting_enabled": False})
    )

    assurance = build_deployment_assurance(connector)

    assert assurance.enabled is False
    assert assurance.start() is False


# API client


def test_iter_iocs_pages_with_the_cursor(connector):
    connector.client.session.request.side_effect = [
        mock_response({"data": [{"uuid": "1"}], "pagination": {"nextCursor": "c1"}}),
        mock_response({"data": [{"uuid": "2"}, "junk"], "pagination": {}}),
    ]

    assert [ioc["uuid"] for ioc in connector.client.iter_iocs()] == ["1", "2"]

    first, second = connector.client.session.request.call_args_list
    assert first.kwargs["params"] == {"accountIds": "1234", "limit": "1000"}
    assert second.kwargs["params"] == {
        "accountIds": "1234",
        "limit": "1000",
        "cursor": "c1",
    }


def test_iter_iocs_scope_with_group_and_site():
    connector = build_connector(
        settings=make_settings(
            sentinelone_intel={"account_id": None, "group_id": "5", "site_id": "6"}
        )
    )
    connector.client.session.request.return_value = mock_response({"data": []})

    assert list(connector.client.iter_iocs()) == []
    assert connector.client.session.request.call_args.kwargs["params"] == {
        "groupIds": "5",
        "siteIds": "6",
        "limit": "1000",
    }


def test_iter_iocs_detects_an_ignored_pagination(connector):
    page = {"data": [{"uuid": "1"}], "pagination": {"nextCursor": "same"}}
    connector.client.session.request.side_effect = [
        mock_response(page),
        mock_response(page),
    ]

    with pytest.raises(SentinelOneApiError, match="same IOC cursor twice"):
        list(connector.client.iter_iocs())


def test_iter_iocs_stops_at_the_page_limit(connector):
    connector.client.session.request.side_effect = [
        mock_response({"data": [], "pagination": {"nextCursor": f"c{page}"}})
        for page in range(2)
    ]

    with pytest.raises(SentinelOneApiError, match="stopped after 2 pages"):
        list(connector.client.iter_iocs(max_pages=2))


@pytest.mark.parametrize(
    "response, message",
    [
        (mock_response({"errors": []}), "'data' is not a list"),
        (mock_response(["unexpected"]), "'data' is not a list"),
        (mock_response(ValueError("no json"), text="<html>"), "not JSON"),
        (mock_response(status_code=403, text="Forbidden"), "HTTP 403 - Forbidden"),
    ],
)
def test_iter_iocs_errors(connector, response, message):
    connector.client.session.request.return_value = response

    with pytest.raises(SentinelOneApiError, match=message):
        list(connector.client.iter_iocs())


def test_requests_are_retried_when_throttled(connector):
    connector.client.session.request.side_effect = [
        mock_response(status_code=429, text="slow down"),
        mock_response({"data": []}),
    ]

    assert connector.client.find_iocs_by_external_id(STIX_ID) == []
    assert connector.client.session.request.call_count == 2


def test_requests_fail_when_throttling_persists(connector):
    connector.client.session.request.return_value = mock_response(
        status_code=429, text="slow down"
    )

    with pytest.raises(SentinelOneApiError, match="HTTP 429 - slow down"):
        connector.client.delete_iocs(["uuid-1"])
    assert connector.client.session.request.call_count == 3
    connector.helper.connector_logger.warning.assert_called_once_with(
        "[API] Rate limited - exhausted all retry attempts"
    )


def test_requests_fail_on_transport_errors(connector):
    connector.client.session.request.side_effect = requests.ConnectionError("down")

    with pytest.raises(SentinelOneApiError, match="down"):
        connector.client.delete_iocs(["uuid-1"])


def test_describe_response_without_body():
    assert describe_response(mock_response(status_code=502, text="")) == "HTTP 502"


# Adapter


def test_adapter_lists_the_valid_iocs(connector):
    future = (datetime.now(UTC) + timedelta(days=30)).isoformat()
    past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    connector.client.session.request.return_value = mock_response(
        {
            "data": [
                {"uuid": "1", "value": "198.51.100.7", "externalId": STIX_ID},
                {
                    "uuid": "2",
                    "value": "evil.example",
                    "externalId": "feed-42",
                    "validUntil": future,
                },
                {"uuid": "3", "value": "old.example", "validUntil": past},
                {"uuid": "4", "value": ""},
                {"value": "no-uuid.example"},
            ]
        }
    )

    indicators = list(SentinelOneDeploymentAdapter(connector).list_vendor_indicators())

    assert indicators == [
        VendorIndicator(indicator_id=STIX_ID, external_id="1", value="198.51.100.7"),
        VendorIndicator(indicator_id=None, external_id="2", value="evil.example"),
    ]
    assert indicators[1].raw == {"uuid": "2", "externalId": "feed-42"}


def test_adapter_removes_only_the_iocs_of_the_indicator(connector):
    connector.client.session.request.return_value = mock_response({})
    adapter = SentinelOneDeploymentAdapter(connector)

    adapter.remove_vendor_indicator(
        VendorIndicator(
            indicator_id=STIX_ID,
            external_id="1",
            raw={"uuid": "1", "externalId": STIX_ID.upper()},
        ),
        make_deployment(),
    )
    (deletion,) = calls_of(connector.client.session, "DELETE")
    assert deletion.kwargs["json"]["filter"]["uuids"] == ["1"]

    with pytest.raises(SentinelOneDeploymentError, match="left in place"):
        adapter.remove_vendor_indicator(
            VendorIndicator(external_id="2", value="198.51.100.7", raw={"uuid": "2"}),
            make_deployment(),
        )
    assert len(calls_of(connector.client.session, "DELETE")) == 1


def test_adapter_push(connector):
    connector.client.session.request.return_value = mock_response(
        {"data": [{"uuid": "uuid-3"}]}
    )

    assert SentinelOneDeploymentAdapter(connector).push_indicator(make_indicator()) == (
        "uuid-3"
    )


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


def deployment_node(indicator_id, status, value, stix_id, revoked=False):
    return {
        "id": f"relationship-{indicator_id}",
        "deployment_status": status,
        "external_id": None,
        "revoked": revoked,
        "last_sync_at": "2026-10-01T00:00:00.000Z",
        "last_hit_at": None,
        "hit_count": 0,
        "from": {
            "id": indicator_id,
            "standard_id": stix_id,
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
def fixture_e2e_connector(no_atexit, router, monkeypatch):
    """Connector with a helper without the pycti deployment helpers (GraphQL path)."""
    monkeypatch.setattr("sentinelone_services.client.time.sleep", lambda _: None)
    helper = make_helper(spec=["api", "connector_logger", "listen_stream"])
    helper.get_attribute_in_extension = (
        OpenCTIConnectorHelper.get_attribute_in_extension
    )
    helper.api.query.side_effect = router
    connector = build_connector(helper=helper)
    connector.assurance = DeploymentAssurance.from_settings(
        helper,
        connector.config,
        adapter=SentinelOneDeploymentAdapter(connector),
        reporter_kwargs={"flush_interval": 3600.0},
    )
    return connector


def test_stream_outcomes_are_reported_in_one_batch(e2e_connector, router):
    e2e_connector.client.session.request.side_effect = [
        mock_response({"data": [{"uuid": "uuid-1"}]}),
        mock_response(status_code=400, text="Validation Error"),
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
                "name": "SentinelOne",
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
        "externalId": "uuid-1",
    }
    assert failed["indicatorId"] == OTHER_ID
    assert failed["status"] == "failed"
    assert failed["metadata"]["error_message"].endswith("HTTP 400 - Validation Error")


def test_reconciliation_confirms_removes_and_withdraws(e2e_connector, router):
    router.deployments = [
        deployment_node(INDICATOR_ID, "deployed", "198.51.100.7", STIX_ID),
        deployment_node(OTHER_ID, "active", "203.0.113.9", OTHER_STIX_ID),
        deployment_node(
            "withdrawn-id",
            "active",
            "192.0.2.1",
            "indicator--7f6b4c5d-0e1f-4a3b-c4d5-e6f7a8b9c0d1",
            revoked=True,
        ),
    ]

    def request(method, url, params=None, json=None, timeout=None):
        if method == "GET":
            return mock_response(
                {
                    "data": [
                        {"uuid": "u-1", "value": "198.51.100.7", "externalId": STIX_ID},
                        {
                            "uuid": "u-3",
                            "value": "192.0.2.1",
                            "externalId": "indicator--7f6b4c5d-0e1f-4a3b-c4d5-e6f7a8b9c0d1",
                        },
                    ],
                    "pagination": {"nextCursor": None},
                }
            )
        return mock_response({"data": {"affected": 1}})

    e2e_connector.client.session.request.side_effect = request

    summary = e2e_connector.assurance.reconciler.run_once()

    assert summary.skipped is False
    assert summary.confirmed_active == 1
    assert summary.marked_removed == 1
    assert summary.withdrawn == 1
    assert summary.hits_reported == 0
    (deletion,) = calls_of(e2e_connector.client.session, "DELETE")
    assert deletion.kwargs["json"]["filter"]["uuids"] == ["u-3"]
    (batch,) = router.calls_of("IndicatorReportDeployments(")
    reports = {report["indicatorId"]: report for report in batch["reports"]}
    assert reports[INDICATOR_ID]["status"] == "active"
    assert reports[INDICATOR_ID]["externalId"] == "u-1"
    assert reports[OTHER_ID]["status"] == "removed"
    assert reports["withdrawn-id"]["status"] == "removed"


def test_read_back_failure_skips_the_reconciliation(e2e_connector, router):
    router.deployments = [
        deployment_node(INDICATOR_ID, "active", "198.51.100.7", STIX_ID)
    ]
    e2e_connector.client.session.request.return_value = mock_response(
        status_code=503, text="Unavailable"
    )

    summary = e2e_connector.assurance.reconciler.run_once()

    assert summary.skipped is True
    assert "Unavailable" in summary.reason
    assert router.calls_of("IndicatorReportDeployments(") == []
