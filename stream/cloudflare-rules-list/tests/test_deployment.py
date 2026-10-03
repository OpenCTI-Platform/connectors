"""Deployment write-back of the Cloudflare Rules List connector."""

import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from cloudflare_rules_list import Connector, ConnectorSettings
from cloudflare_rules_list.client import CloudflareAPIError, CloudflareRulesListClient
from cloudflare_rules_list.deployment import (
    CloudflareDeploymentAdapter,
    CloudflareDeploymentError,
    build_deployment_assurance,
    comment_id,
)
from connectors_sdk import (
    DeploymentAssurance,
    DeploymentReconciler,
    IndicatorDeployment,
)
from connectors_sdk.connectors.stream.deployment import VendorIndicator

OPENCTI_EXTENSION_ID = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
PLATFORM_ID = "6c3b0f4e-2d41-4a77-8f0d-3e1c9b5a7d21"
INDICATOR_ID = "0d8b4f0e-6a43-4f11-8f6c-1d2f5e6a7b8c"
OTHER_ID = "1e9c5f1f-7b54-4a22-9e7d-2e3f6a7b8c9d"
STIX_ID = "indicator--5d4f2a3b-8c9d-4e1f-a2b3-c4d5e6f7a8b9"
OTHER_STIX_ID = "indicator--6e5a3b4c-9d0e-4f2a-b3c4-d5e6f7a8b9c0"


def make_settings(**namespaces: dict[str, Any]) -> ConnectorSettings:
    """Build connector settings from a valid configuration and overrides."""
    config = {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "connector": {"live_stream_id": "live"},
        "cloudflare": {
            "account_id": "account",
            "api_token": "token",
            "list_id": "list-123",
        },
    }
    for namespace, values in namespaces.items():
        config[namespace] = {**config.get(namespace, {}), **values}

    class StubConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(config)

    return StubConnectorSettings()


def make_indicator(stix_id=STIX_ID, indicator_id=INDICATOR_ID, ip="198.51.100.7"):
    return {
        "id": stix_id,
        "type": "indicator",
        "pattern": f"[ipv4-addr:value = '{ip}']",
        "pattern_type": "stix",
        "extensions": {OPENCTI_EXTENSION_ID: {"id": indicator_id, "type": "Indicator"}},
    }


def make_message(event, data):
    return SimpleNamespace(event=event, data=json.dumps({"data": data}), id="1-0")


def build_connector(helper=None, client=None, assurance=None, settings=None):
    connector = Connector(
        helper=helper or MagicMock(),
        config=settings or make_settings(),
        client=client or MagicMock(spec=CloudflareRulesListClient),
    )
    connector.sync_interval = 0
    connector.client.replace_list_items.return_value = {}
    connector.client.delete_list_items.return_value = {}
    connector.assurance = assurance
    return connector


def make_deployment(indicator_id=INDICATOR_ID, standard_id=STIX_ID, **fields):
    return IndicatorDeployment(
        relationship_id=f"relationship-{indicator_id}",
        status=fields.pop("status", "active"),
        indicator_id=indicator_id,
        indicator_standard_id=standard_id,
        pattern="[ipv4-addr:value = '198.51.100.7']",
        pattern_type="stix",
        **fields,
    )


def enqueued(assurance):
    """Return the queued reports, by indicator id."""
    return {
        call.args[0].indicator_id: call.args[0]
        for call in assurance.reporter.enqueue.call_args_list
    }


@pytest.fixture(name="assurance")
def fixture_assurance():
    assurance = MagicMock(spec=DeploymentAssurance)
    assurance.reporter = MagicMock()
    return assurance


@pytest.fixture(name="connector")
def fixture_connector(assurance):
    return build_connector(assurance=assurance)


@pytest.fixture(name="no_atexit")
def fixture_no_atexit(monkeypatch):
    """Do not register the exit flush of the deployment reporter during tests."""
    monkeypatch.setattr(
        "connectors_sdk.connectors.stream.deployment.reporter.atexit.register",
        lambda _handler: None,
    )


# Stream path: reports follow the snapshot uploads


def test_uploaded_indicators_are_reported_deployed(connector, assurance):
    connector.process_message(make_message("create", make_indicator()))

    report = enqueued(assurance)[STIX_ID]
    assert report.status == "deployed"
    connector.client.replace_list_items.assert_called_once_with(
        "list-123", [{"ip": "198.51.100.7", "comment": f"OpenCTI: {STIX_ID}"}]
    )


def test_unchanged_indicators_are_not_reported_again(connector, assurance):
    connector.process_message(make_message("create", make_indicator()))
    connector.process_message(make_message("update", make_indicator()))
    connector.process_message(make_message("update", make_indicator(ip="203.0.113.9")))

    statuses = [
        call.args[0].status for call in assurance.reporter.enqueue.call_args_list
    ]
    assert statuses == ["deployed", "deployed"]


def test_observables_are_pushed_but_not_reported(connector, assurance):
    connector.process_message(
        make_message(
            "create", {"id": "ipv4-addr--1", "type": "ipv4-addr", "value": "192.0.2.1"}
        )
    )

    connector.client.replace_list_items.assert_called_once()
    assurance.reporter.enqueue.assert_not_called()


def test_dropped_indicators_are_reported_removed(connector, assurance):
    connector.process_message(make_message("create", make_indicator()))
    connector.process_message(
        make_message("create", make_indicator(stix_id=OTHER_STIX_ID, ip="203.0.113.9"))
    )
    assurance.reporter.enqueue.reset_mock()

    connector.process_message(make_message("delete", make_indicator()))

    reports = enqueued(assurance)
    assert set(reports) == {STIX_ID}
    assert reports[STIX_ID].status == "removed"


def test_failed_upload_reports_the_new_indicators_failed(connector, assurance):
    connector.process_message(make_message("create", make_indicator()))
    assurance.reporter.enqueue.reset_mock()
    connector.client.replace_list_items.side_effect = CloudflareAPIError(
        "API request failed: [{'code': 10000, 'message': 'Authentication error'}]"
    )

    connector.process_message(
        make_message("create", make_indicator(stix_id=OTHER_STIX_ID, ip="203.0.113.9"))
    )

    reports = enqueued(assurance)
    assert set(reports) == {OTHER_STIX_ID}
    assert reports[OTHER_STIX_ID].status == "failed"
    assert "Authentication error" in reports[OTHER_STIX_ID].error_message
    connector.logger.error.assert_called_once()

    connector.client.replace_list_items.side_effect = None
    assurance.reporter.enqueue.reset_mock()
    connector.process_message(make_message("update", make_indicator()))
    assert set(enqueued(assurance)) == {OTHER_STIX_ID}


def test_failed_upload_without_message_uses_the_error_type(connector, assurance):
    connector.client.replace_list_items.side_effect = CloudflareAPIError()

    connector.process_message(make_message("create", make_indicator()))

    assert enqueued(assurance)[STIX_ID].error_message == "CloudflareAPIError"


def test_full_sync_reports_the_indicators_only(connector, assurance):
    connector.helper.api.indicator.list.return_value = [
        {
            "id": INDICATOR_ID,
            "entity_type": "Indicator",
            "pattern": "[ipv4-addr:value = '198.51.100.7']",
        }
    ]
    connector.helper.api.stix_cyber_observable.list.return_value = [
        {"id": "observable-id", "entity_type": "IPv4-Addr", "value": "192.0.2.1"}
    ]

    connector._full_sync()

    reports = enqueued(assurance)
    assert set(reports) == {INDICATOR_ID}
    assert connector._indicator_keys == {INDICATOR_ID}


def test_connector_works_without_write_back():
    connector = build_connector()

    connector.process_message(make_message("create", make_indicator()))
    connector.process_message(make_message("delete", make_indicator()))

    connector.client.replace_list_items.assert_called_once()


def test_run_starts_the_write_back_before_the_full_sync(connector, assurance):
    order = []
    assurance.start.side_effect = lambda: order.append("assurance")
    connector.helper.api.indicator.list.side_effect = lambda **_: (
        order.append("full sync") or []
    )
    connector.helper.listen_stream.side_effect = lambda **_: order.append("stream")

    connector.run()

    assert order == ["assurance", "full sync", "stream"]


def test_push_indicator_uploads_the_snapshot(connector, assurance):
    connector.push_indicator(make_indicator())

    connector.client.replace_list_items.assert_called_once_with(
        "list-123", [{"ip": "198.51.100.7", "comment": f"OpenCTI: {INDICATOR_ID}"}]
    )
    assert enqueued(assurance)[INDICATOR_ID].status == "deployed"


def test_push_indicator_errors(connector):
    with pytest.raises(ValueError, match="no IPv4 pattern"):
        connector.push_indicator(
            {"type": "indicator", "pattern": "[domain-name:value = 'evil.example']"}
        )
    connector.client.replace_list_items.side_effect = CloudflareAPIError("refused")
    with pytest.raises(CloudflareAPIError, match="refused"):
        connector.push_indicator(make_indicator())


def test_withdraw_item_deletes_the_item_and_drops_the_indicator(connector):
    connector.process_message(make_message("create", make_indicator()))
    connector.process_message(
        make_message("create", make_indicator(stix_id=OTHER_STIX_ID, ip="203.0.113.9"))
    )
    connector.client.delete_list_items.return_value = {"operation_id": "op-1"}

    connector.withdraw_item("item-1", {STIX_ID, INDICATOR_ID})

    connector.client.delete_list_items.assert_called_once_with("list-123", ["item-1"])
    connector.client.wait_for_operation.assert_called_once_with("op-1")
    assert connector._indicator_cache == {OTHER_STIX_ID: "203.0.113.9"}
    assert connector._indicator_keys == {OTHER_STIX_ID}
    assert set(connector._synced) == {OTHER_STIX_ID}


# Client


def test_iter_list_items_follows_the_cursors():
    client = CloudflareRulesListClient("account", "token")
    client.get_list_items = MagicMock(
        side_effect=[
            {
                "result": [{"id": "1"}, "junk"],
                "result_info": {"cursors": {"after": "c1"}},
            },
            {"result": [{"id": "2"}], "result_info": {}},
        ]
    )

    assert [item["id"] for item in client.iter_list_items("list-123")] == ["1", "2"]
    assert client.get_list_items.call_args_list[1].args == ("list-123", "c1")


@pytest.mark.parametrize(
    "pages, message",
    [
        ([{"errors": []}], "'result' is not a list"),
        (
            [{"result": [], "result_info": {"cursors": {"after": "same"}}}] * 2,
            "same list items cursor twice",
        ),
    ],
)
def test_iter_list_items_never_returns_a_partial_listing(pages, message):
    client = CloudflareRulesListClient("account", "token")
    client.get_list_items = MagicMock(side_effect=pages)

    with pytest.raises(CloudflareAPIError, match=message):
        list(client.iter_list_items("list-123"))


def test_iter_list_items_stops_at_the_page_limit():
    client = CloudflareRulesListClient("account", "token")
    client.get_list_items = MagicMock(
        side_effect=[
            {"result": [], "result_info": {"cursors": {"after": f"c{page}"}}}
            for page in range(2)
        ]
    )

    with pytest.raises(CloudflareAPIError, match="stopped after 2 pages"):
        list(client.iter_list_items("list-123", max_pages=2))


def test_delete_list_items_sends_the_item_ids():
    client = CloudflareRulesListClient("account", "token")
    client._make_request = MagicMock(return_value={"result": {"operation_id": "op"}})

    assert client.delete_list_items("list-123", ["a", "b"]) == {"operation_id": "op"}
    client._make_request.assert_called_once_with(
        "DELETE",
        "/rules/lists/list-123/items",
        data={"items": [{"id": "a"}, {"id": "b"}]},
    )


# Adapter


def test_comment_id():
    assert comment_id({"comment": f"OpenCTI: {STIX_ID}"}) == STIX_ID
    assert comment_id({"comment": "OpenCTI: "}) is None
    assert comment_id({"comment": "manual entry"}) is None
    assert comment_id({}) is None


def test_adapter_lists_the_items(connector):
    connector.client.iter_list_items.return_value = iter(
        [
            {"id": "1", "ip": "198.51.100.7", "comment": f"OpenCTI: {STIX_ID}"},
            {"id": "2", "ip": "203.0.113.9", "comment": f"OpenCTI: {INDICATOR_ID}"},
            {"id": "3", "ip": "192.0.2.1"},
            {"id": "4", "ip": ""},
            {"ip": "192.0.2.2"},
        ]
    )

    indicators = list(CloudflareDeploymentAdapter(connector).list_vendor_indicators())

    assert indicators == [
        VendorIndicator(indicator_id=STIX_ID, external_id="1", value="198.51.100.7"),
        VendorIndicator(indicator_id=None, external_id="2", value="203.0.113.9"),
        VendorIndicator(indicator_id=None, external_id="3", value="192.0.2.1"),
    ]
    assert indicators[1].raw == {"item_id": "2", "opencti_id": INDICATOR_ID}
    connector.client.iter_list_items.assert_called_once_with("list-123")


def test_adapter_removes_only_the_items_of_the_indicator(connector):
    adapter = CloudflareDeploymentAdapter(connector)

    adapter.remove_vendor_indicator(
        VendorIndicator(
            external_id="2", raw={"item_id": "2", "opencti_id": INDICATOR_ID}
        ),
        make_deployment(),
    )
    connector.client.delete_list_items.assert_called_once_with("list-123", ["2"])

    with pytest.raises(CloudflareDeploymentError, match="left in place"):
        adapter.remove_vendor_indicator(
            VendorIndicator(external_id="3", raw={"item_id": "3", "opencti_id": None}),
            make_deployment(),
        )
    connector.client.delete_list_items.assert_called_once()


def test_adapter_push(connector):
    assert (
        CloudflareDeploymentAdapter(connector).push_indicator(make_indicator()) is None
    )
    connector.client.replace_list_items.assert_called_once()


# Settings and wiring


def test_write_back_settings_defaults():
    settings = make_settings()

    assert settings.deployment.reporting_enabled is True
    assert settings.deployment.reconciliation_interval == 60
    assert settings.security_platform.name == "Cloudflare"
    assert settings.security_platform.type is None


def test_build_deployment_assurance_wires_the_reconciliation_without_hits():
    assurance = build_deployment_assurance(build_connector())

    assert isinstance(assurance.reconciler, DeploymentReconciler)
    assert isinstance(assurance.reconciler._adapter, CloudflareDeploymentAdapter)
    assert assurance.reporter.hits_enabled is False


def test_disabled_write_back_is_a_no_op():
    connector = build_connector(
        settings=make_settings(deployment={"reporting_enabled": False})
    )
    connector.assurance = build_deployment_assurance(connector)

    assert connector.assurance.start() is False
    connector.process_message(make_message("create", make_indicator()))
    connector.client.replace_list_items.assert_called_once()


# End to end: snapshot uploads and reconciliation through GraphQL


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


def deployment_node(indicator_id, status, ip, standard_id, revoked=False):
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
            "standard_id": standard_id,
            "name": ip,
            "pattern": f"[ipv4-addr:value = '{ip}']",
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
    helper = MagicMock(spec=["api", "connector_logger", "listen_stream"])
    helper.api.query.side_effect = router
    connector = build_connector(helper=helper)
    connector.assurance = DeploymentAssurance.from_settings(
        helper,
        connector.config,
        adapter=CloudflareDeploymentAdapter(connector),
        reporter_kwargs={"flush_interval": 3600.0},
    )
    return connector


def test_snapshot_outcomes_are_reported_in_one_batch(e2e_connector, router):
    e2e_connector.process_message(make_message("create", make_indicator()))
    e2e_connector.client.replace_list_items.side_effect = CloudflareAPIError(
        "API request failed: quota exceeded"
    )
    e2e_connector.process_message(
        make_message("create", make_indicator(stix_id=OTHER_STIX_ID, ip="203.0.113.9"))
    )
    result = e2e_connector.assurance.flush()

    assert result.processed == 2
    assert router.calls_of("DeploymentSecurityPlatformAdd") == [
        {"input": {"name": "Cloudflare", "update": True}}
    ]
    (batch,) = router.calls_of("IndicatorReportDeployments(")
    deployed, failed = batch["reports"]
    assert deployed == {"indicatorId": STIX_ID, "status": "deployed"}
    assert failed["indicatorId"] == OTHER_STIX_ID
    assert failed["status"] == "failed"
    assert failed["metadata"]["error_message"].endswith("quota exceeded")


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
    e2e_connector.client.iter_list_items.return_value = iter(
        [
            {"id": "i-1", "ip": "198.51.100.7", "comment": f"OpenCTI: {STIX_ID}"},
            {"id": "i-3", "ip": "192.0.2.1", "comment": "OpenCTI: withdrawn-id"},
        ]
    )

    summary = e2e_connector.assurance.reconciler.run_once()

    assert summary.skipped is False
    assert summary.confirmed_active == 1
    assert summary.marked_removed == 1
    assert summary.withdrawn == 1
    e2e_connector.client.delete_list_items.assert_called_once_with("list-123", ["i-3"])
    (batch,) = router.calls_of("IndicatorReportDeployments(")
    reports = {report["indicatorId"]: report for report in batch["reports"]}
    assert reports[INDICATOR_ID]["status"] == "active"
    assert reports[INDICATOR_ID]["externalId"] == "i-1"
    assert reports[OTHER_ID]["status"] == "removed"
    assert reports["withdrawn-id"]["status"] == "removed"


def test_read_back_failure_skips_the_reconciliation(e2e_connector, router):
    router.deployments = [
        deployment_node(INDICATOR_ID, "active", "198.51.100.7", STIX_ID)
    ]
    e2e_connector.client.iter_list_items.side_effect = CloudflareAPIError(
        "API request failed: 503 Service Unavailable"
    )

    summary = e2e_connector.assurance.reconciler.run_once()

    assert summary.skipped is True
    assert "503" in summary.reason
    assert router.calls_of("IndicatorReportDeployments(") == []
