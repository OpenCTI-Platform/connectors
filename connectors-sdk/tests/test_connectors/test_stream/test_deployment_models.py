# pragma: no cover  # do not compute coverage on test files
# type: ignore
"""Tests of the deployment write-back models."""

from datetime import UTC, datetime, timedelta

import pytest
from connectors_sdk.connectors.stream.deployment.models import (
    LIVE_STATUSES,
    RECONCILED_STATUSES,
    REPORTABLE_STATUSES,
    DeploymentBatchResult,
    DeploymentReport,
    DeploymentReportError,
    DeploymentStatus,
    IndicatorDeployment,
    ReconciliationSummary,
    VendorHit,
    VendorIndicator,
)


def test_statuses_follow_the_contract():
    """Status values and groups follow the write-back contract."""
    assert [status.value for status in DeploymentStatus] == [
        "pending",
        "deployed",
        "active",
        "failed",
        "removed",
        "expired",
    ]
    assert DeploymentStatus.EXPIRED not in REPORTABLE_STATUSES
    assert set(RECONCILED_STATUSES) == {"pending", "deployed", "active", "failed"}
    assert LIVE_STATUSES == {"deployed", "active"}


def test_deployment_report_normalizes_the_status():
    """String statuses are converted into ``DeploymentStatus``."""
    report = DeploymentReport(indicator_id="internal-id", status="active")
    assert report.status is DeploymentStatus.ACTIVE


@pytest.mark.parametrize("indicator_id", ["", "   ", None])
def test_deployment_report_requires_an_indicator_id(indicator_id):
    """A report without an indicator id is rejected."""
    with pytest.raises(ValueError, match="indicator id"):
        DeploymentReport(indicator_id=indicator_id, status="deployed")


def test_deployment_report_rejects_unknown_statuses():
    """Unknown statuses are rejected."""
    with pytest.raises(ValueError):
        DeploymentReport(indicator_id="internal-id", status="live")


def test_deployment_report_rejects_the_expired_status():
    """Connectors never report ``expired``."""
    with pytest.raises(ValueError, match="set by OpenCTI only"):
        DeploymentReport(indicator_id="internal-id", status=DeploymentStatus.EXPIRED)


def test_deployment_report_from_mapping():
    """Reports are built from the pycti helper dictionary shape."""
    report = DeploymentReport.from_mapping(
        {
            "indicator_id": "internal-id",
            "status": "failed",
            "external_id": "vendor-id",
            "error_message": "rejected",
            "deployed_at": "2026-10-01T00:00:00Z",
            "synced_at": "2026-10-02T00:00:00Z",
            "removed_at": None,
        }
    )
    assert report == DeploymentReport(
        indicator_id="internal-id",
        status=DeploymentStatus.FAILED,
        external_id="vendor-id",
        error_message="rejected",
        deployed_at="2026-10-01T00:00:00Z",
        synced_at="2026-10-02T00:00:00Z",
    )


def test_deployment_report_graphql_input_without_optional_fields():
    """Only the mandatory fields are sent when nothing else is known."""
    report = DeploymentReport(indicator_id="internal-id", status="removed")
    assert report.metadata_input() is None
    assert report.to_graphql_input() == {
        "indicatorId": "internal-id",
        "status": "removed",
    }


def test_deployment_report_graphql_input_with_every_field():
    """Optional fields are mapped to the GraphQL input."""
    now = datetime(2026, 10, 3, 10, 0, tzinfo=UTC)
    report = DeploymentReport(
        indicator_id="internal-id",
        status="failed",
        external_id="vendor-id",
        error_message="rejected",
        deployed_at=now,
        synced_at="2026-10-03T10:00:00Z",
        removed_at=now,
    )
    assert report.to_graphql_input() == {
        "indicatorId": "internal-id",
        "status": "failed",
        "externalId": "vendor-id",
        "metadata": {
            "deployed_at": "2026-10-03T10:00:00.000Z",
            "last_sync_at": "2026-10-03T10:00:00.000Z",
            "removed_at": "2026-10-03T10:00:00.000Z",
            "error_message": "rejected",
        },
    }
    assert report.to_helper_kwargs() == {
        "indicator_id": "internal-id",
        "status": "failed",
        "external_id": "vendor-id",
        "error_message": "rejected",
        "deployed_at": "2026-10-03T10:00:00.000Z",
        "synced_at": "2026-10-03T10:00:00.000Z",
        "removed_at": "2026-10-03T10:00:00.000Z",
    }


def test_batch_result_from_graphql():
    """Batch results are parsed from the GraphQL payload."""
    result = DeploymentBatchResult.from_graphql(
        {
            "processed": 3,
            "created": 1,
            "updated": 1,
            "unchanged": 1,
            "errors": [
                {"indicatorId": "a", "message": "not found"},
                {"indicator_id": "b", "message": "invalid"},
            ],
        }
    )
    assert result == DeploymentBatchResult(
        processed=3,
        created=1,
        updated=1,
        unchanged=1,
        errors=(
            DeploymentReportError(indicator_id="a", message="not found"),
            DeploymentReportError(indicator_id="b", message="invalid"),
        ),
    )


@pytest.mark.parametrize("data", [None, {}])
def test_batch_result_from_empty_graphql_payload(data):
    """Empty payloads give an empty result."""
    assert DeploymentBatchResult.from_graphql(data) == DeploymentBatchResult()


def test_batch_result_failure_and_merge():
    """Failures list every report and results add up."""
    reports = [
        DeploymentReport(indicator_id="a", status="deployed"),
        DeploymentReport(indicator_id="b", status="deployed"),
    ]
    failure = DeploymentBatchResult.failure(reports, "boom")
    merged = DeploymentBatchResult(processed=2, created=2).merge(failure)
    assert merged.processed == 2
    assert merged.created == 2
    assert [error.indicator_id for error in merged.errors] == ["a", "b"]
    assert {error.message for error in merged.errors} == {"boom"}


def test_indicator_deployment_from_node(node_factory, ids):
    """Deployments are parsed from relationship nodes."""
    node = node_factory(
        status="active",
        external_id="vendor-id",
        revoked=True,
        indicator_revoked=True,
        valid_until="2026-01-01T00:00:00Z",
        last_hit_at="2026-09-30T00:00:00Z",
    )
    node["hit_count"] = 4

    deployment = IndicatorDeployment.from_node(node)

    assert deployment.relationship_id == f"relationship-{ids.indicator}"
    assert deployment.status == "active"
    assert deployment.indicator_id == ids.indicator
    assert deployment.indicator_standard_id == ids.indicator_stix
    assert deployment.external_id == "vendor-id"
    assert deployment.revoked is True
    assert deployment.indicator_revoked is True
    assert deployment.last_sync_at == datetime(2026, 10, 1, tzinfo=UTC)
    assert deployment.last_hit_at == datetime(2026, 9, 30, tzinfo=UTC)
    assert deployment.hit_count == 4
    assert deployment.valid_until == datetime(2026, 1, 1, tzinfo=UTC)
    assert deployment.main_observable_type == "IPv4-Addr"
    assert deployment.pattern_type == "stix"
    assert deployment.indicator_name == "indicator name"


def test_indicator_deployment_from_node_defaults_to_pending():
    """A node without status is ``pending``."""
    deployment = IndicatorDeployment.from_node(
        {"id": "relationship-id", "from": {"id": "indicator-id"}}
    )
    assert deployment.status == "pending"
    assert deployment.hit_count == 0
    assert deployment.revoked is False


@pytest.mark.parametrize(
    "node", [{"id": "relationship-id"}, {"from": None}, {"from": {"name": "no id"}}]
)
def test_indicator_deployment_from_node_without_indicator(node):
    """Nodes without a readable indicator are ignored."""
    assert IndicatorDeployment.from_node(node) is None


def test_indicator_deployment_lifecycle_helpers():
    """Live, expiry and removal helpers follow the contract."""
    now = datetime(2026, 10, 3, tzinfo=UTC)
    live = IndicatorDeployment("r", "deployed", "i")
    assert live.is_live
    assert not live.is_expired(now)
    assert not live.requires_removal(now)
    assert not IndicatorDeployment("r", "failed", "i").is_live

    expired = IndicatorDeployment(
        "r", "active", "i", valid_until=datetime(2026, 1, 1, tzinfo=UTC)
    )
    assert expired.is_expired(now)
    assert expired.requires_removal(now)
    at_boundary = IndicatorDeployment("r", "active", "i", valid_until=now)
    assert at_boundary.is_expired(now)
    assert not at_boundary.is_expired(now - timedelta(seconds=1))
    assert IndicatorDeployment("r", "active", "i", revoked=True).requires_removal(now)
    assert IndicatorDeployment(
        "r", "active", "i", indicator_revoked=True
    ).requires_removal(now)


def test_indicator_deployment_identifiers_and_values():
    """Identifiers and pattern values are normalized for matching."""
    deployment = IndicatorDeployment(
        "r",
        "deployed",
        "Internal-ID",
        indicator_standard_id="Indicator--1",
        pattern="[domain-name:value = 'Evil.Example' OR url:value = '']",
        pattern_type="stix",
    )
    assert deployment.identifiers == {"internal-id", "indicator--1"}
    assert deployment.values == {"evil.example"}
    assert IndicatorDeployment("r", "deployed", "i").values == frozenset()
    assert (
        IndicatorDeployment(
            "r", "deployed", "i", pattern="rule x {}", pattern_type="yara"
        ).values
        == frozenset()
    )


def test_vendor_models_defaults():
    """Vendor models only require what the vendor knows."""
    assert VendorIndicator(value="198.51.100.7").raw == {}
    assert VendorIndicator(external_id="1", raw={"a": 1}) == VendorIndicator(
        external_id="1"
    )
    hit = VendorHit(timestamp=datetime(2026, 10, 3, tzinfo=UTC), value="198.51.100.7")
    assert hit.count == 1


def test_reconciliation_summary_log_meta():
    """The summary exposes every counter for logging."""
    summary = ReconciliationSummary(confirmed_active=2, marked_removed=1)
    meta = summary.as_log_meta()
    assert meta["confirmed_active"] == 2
    assert meta["marked_removed"] == 1
    assert set(meta) == {
        "skipped",
        "reason",
        "vendor_indicators",
        "vendor_listing_truncated",
        "deployments",
        "confirmed_active",
        "discovered",
        "marked_removed",
        "deferred",
        "repushed",
        "repush_failed",
        "withdrawn",
        "withdrawal_failed",
        "hits_reported",
        "report_errors",
        "incomplete",
        "absence_unconfirmed",
    }
