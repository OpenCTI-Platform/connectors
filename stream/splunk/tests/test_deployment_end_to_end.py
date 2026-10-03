"""End-to-end write-back: stream processing and reconciliation through GraphQL."""

from datetime import UTC, datetime, timedelta
from queue import Queue
from unittest.mock import MagicMock

import pytest
import requests
from connectors_sdk import DeploymentAssurance
from settings import ConnectorSettings
from splunk import KVStore, SplunkConnector
from splunk_deployment import SplunkKVStoreDeploymentAdapter
from splunk_test_support import (
    DATA_URL,
    INDICATOR_ID,
    PLATFORM_ID,
    SEARCH_URL,
    SPLUNK_URL,
    GraphQLRouter,
    deployment_node,
    make_indicator,
    make_message,
)

REMOVED_ID = "1e9c5f1f-7b54-4a22-9e7d-2e3f6a7b8c9d"
PENDING_ID = "2fad6a2a-8c65-4b33-af8e-3f4a7b8c9dae"
DISCOVERED_ID = "3abe7b3b-9d76-4c44-b09f-4a5b8c9daebf"


@pytest.fixture
def router():
    return GraphQLRouter()


@pytest.fixture
def opencti_helper(router):
    """Helper without the pycti deployment helpers: the SDK sends GraphQL documents."""
    helper = MagicMock(
        spec=[
            "api",
            "connector_logger",
            "log_info",
            "log_warning",
            "log_error",
            "get_stream_collection",
        ]
    )
    helper.api.query.side_effect = router
    helper.get_stream_collection.return_value = {"name": "Splunk stream"}
    return helper


@pytest.fixture
def connector(splunk_environment, no_atexit, opencti_helper):
    settings = ConnectorSettings()
    kvstore = KVStore(
        SPLUNK_URL, "splunk-token", "Bearer", "search", "nobody", "opencti", True
    )
    connector = SplunkConnector(opencti_helper, kvstore, Queue(), [], 1)
    connector.assurance = DeploymentAssurance.from_settings(
        opencti_helper,
        settings,
        adapter=SplunkKVStoreDeploymentAdapter(
            kvstore,
            push_indicator=connector.push_indicator,
            hits_saved_search="OpenCTI indicator matches",
        ),
        reporter_kwargs={"flush_interval": 3600.0},
    )
    return connector


def test_stream_outcomes_are_reported_in_one_batch(connector, router, requests_mock):
    rejected = make_indicator(indicator_id=REMOVED_ID)
    requests_mock.post(
        DATA_URL,
        [
            {"json": {"_key": INDICATOR_ID}, "status_code": 201},
            {"text": "Document too large", "status_code": 400},
        ],
    )

    connector.process_message(make_message("create", make_indicator()))
    with pytest.raises(requests.HTTPError):
        connector.process_message(make_message("create", rejected))
    result = connector.assurance.flush()

    assert result.processed == 2
    assert router.calls_of("DeploymentSecurityPlatformAdd") == [
        {
            "input": {
                "name": "Splunk",
                "update": True,
                "security_platform_type": "SIEM",
            }
        }
    ]
    (batch,) = router.calls_of("IndicatorReportDeployments(")
    assert batch["platformId"] == PLATFORM_ID
    deployed, failed = batch["reports"]
    assert deployed == {
        "indicatorId": INDICATOR_ID,
        "status": "deployed",
        "externalId": INDICATOR_ID,
    }
    assert failed["indicatorId"] == REMOVED_ID
    assert failed["status"] == "failed"
    assert failed["metadata"]["error_message"].startswith("400 Client Error")
    assert failed["metadata"]["error_message"].endswith("Document too large")


def test_reconciliation_and_hits_are_reported(
    connector, router, opencti_helper, requests_mock
):
    router.deployments = [
        deployment_node(indicator_id=INDICATOR_ID, status="deployed"),
        deployment_node(indicator_id=REMOVED_ID, status="active"),
        deployment_node(indicator_id=PENDING_ID, status="pending"),
    ]
    requests_mock.get(
        DATA_URL,
        json=[
            {"_key": INDICATOR_ID, "type": "indicator", "values": ["198.51.100.7"]},
            {"_key": DISCOVERED_ID, "type": "indicator", "values": ["evil.example"]},
        ],
    )
    requests_mock.post(DATA_URL, json={"_key": PENDING_ID}, status_code=201)
    hit_time = datetime.now(UTC) - timedelta(minutes=5)
    requests_mock.post(
        SEARCH_URL,
        json={
            "results": [
                {
                    "opencti_id": INDICATOR_ID,
                    "_time": hit_time.isoformat(),
                    "count": "2",
                }
            ]
        },
    )
    exported = {
        "type": "indicator",
        "id": "indicator--6c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
        "spec_version": "2.1",
        "name": "pending.example",
        "pattern": "[domain-name:value = 'pending.example']",
        "pattern_type": "stix",
        "valid_from": "2026-10-01T00:00:00.000Z",
        "x_opencti_score": 50,
        "x_opencti_main_observable_type": "Domain-Name",
    }
    get_object = opencti_helper.api.stix2.get_stix_bundle_or_object_from_entity_id
    get_object.return_value = exported

    summary = connector.assurance.reconciler.run_once()

    assert summary.skipped is False
    assert summary.vendor_indicators == 2
    assert summary.confirmed_active == 1
    assert summary.marked_removed == 1
    assert summary.repushed == 1
    assert summary.discovered == 1
    assert summary.hits_reported == 1
    get_object.assert_called_once_with(
        entity_type="Indicator", entity_id=PENDING_ID, only_entity=True
    )
    repushed = [
        request
        for request in requests_mock.request_history
        if request.method == "POST" and request.url.startswith(DATA_URL)
    ]
    assert repushed[0].json()["_key"] == PENDING_ID
    assert repushed[0].json()["pattern"] == exported["pattern"]

    (batch,) = router.calls_of("IndicatorReportDeployments(")
    reports = {report["indicatorId"]: report for report in batch["reports"]}
    assert reports[INDICATOR_ID]["status"] == "active"
    assert reports[INDICATOR_ID]["externalId"] == INDICATOR_ID
    assert reports[REMOVED_ID]["status"] == "removed"
    assert reports[PENDING_ID]["status"] == "deployed"
    assert reports[PENDING_ID]["externalId"] == PENDING_ID
    assert reports[DISCOVERED_ID]["status"] == "active"

    (hits,) = router.calls_of("IndicatorReportHits(")
    assert hits["indicatorId"] == INDICATOR_ID
    assert hits["platformId"] == PLATFORM_ID
    assert hits["count"] == 2

    search = next(
        request
        for request in requests_mock.request_history
        if request.url.startswith(SEARCH_URL)
    )
    assert "exec_mode=oneshot" in search.text


def test_read_back_failure_skips_the_reconciliation(connector, router, requests_mock):
    router.deployments = [deployment_node(status="deployed")]
    requests_mock.get(DATA_URL, status_code=503, text="KV Store is initializing")

    summary = connector.assurance.reconciler.run_once()

    assert summary.skipped is True
    assert router.calls_of("IndicatorReportDeployments(") == []
