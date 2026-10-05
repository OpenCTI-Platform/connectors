# pragma: no cover  # do not compute coverage on test files
# type: ignore
"""Tests of the deployment reconciliation."""

import threading
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from connectors_sdk.connectors.stream.deployment import reconciler as reconciler_module
from connectors_sdk.connectors.stream.deployment.models import (
    DeploymentReport,
    DeploymentStatus,
    HitCollection,
    IndicatorDeployment,
    VendorHit,
    VendorIndicator,
)
from connectors_sdk.connectors.stream.deployment.reconciler import (
    CAPPED_INSTANT_STEP,
    LISTED_STATUSES,
    DeploymentReconciler,
    DeploymentVendorAdapter,
)

NOW = datetime(2026, 10, 3, 12, 0, tzinfo=UTC)


class FakeAdapter(DeploymentVendorAdapter):
    """In-memory vendor."""

    def __init__(
        self,
        vendor=(),
        hits=(),
        push_result="vendor-new",
        push_error=None,
        remove_error=None,
        list_error=None,
        hits_error=None,
    ):
        self.vendor = list(vendor)
        self.hits = list(hits)
        self.push_result = push_result
        self.push_error = push_error
        self.remove_error = remove_error
        self.list_error = list_error
        self.hits_error = hits_error
        self.removed = []
        self.pushed = []
        self.hits_calls = []
        self.listed = threading.Event()

    def list_vendor_indicators(self):
        self.listed.set()
        if self.list_error:
            raise self.list_error
        yield from self.vendor

    def remove_vendor_indicator(self, vendor_indicator, deployment):
        if self.remove_error:
            raise self.remove_error
        self.removed.append((vendor_indicator, deployment))

    def push_indicator(self, stix_indicator):
        if self.push_error:
            raise self.push_error
        self.pushed.append(stix_indicator)
        return self.push_result

    def collect_hits(self, deployments, since):
        self.hits_calls.append((list(deployments), since))
        if self.hits_error:
            raise self.hits_error
        return self.hits


class ReadOnlyAdapter(DeploymentVendorAdapter):
    """Adapter without hits support (default ``collect_hits``)."""

    def __init__(self, vendor=()):
        self.vendor = list(vendor)

    def list_vendor_indicators(self):
        return self.vendor

    def remove_vendor_indicator(self, vendor_indicator, deployment):
        return None

    def push_indicator(self, stix_indicator):
        return None


@pytest.fixture
def list_nodes(router):
    """Serve the given relationship nodes as the deployments of the platform."""

    def _serve(*nodes):
        router.handlers["IndicatorDeploymentsOfPlatform"] = {
            "data": {
                "stixCoreRelationships": {
                    "edges": [{"node": node} for node in nodes],
                    "pageInfo": {"endCursor": None, "hasNextPage": False},
                }
            }
        }

    return _serve


@pytest.fixture
def reported(router):
    """Return the reports sent with ``indicatorReportDeployments``, by indicator id."""

    def _reports():
        return {
            report["indicatorId"]: report
            for call in router.calls_of("IndicatorReportDeployments(")
            for report in call["reports"]
        }

    return _reports


def make_reconciler(reporter, adapter, **kwargs):
    kwargs.setdefault("clock", lambda: NOW)
    kwargs.setdefault("initial_delay", 0.0)
    return DeploymentReconciler(reporter, adapter, **kwargs)


# --- skipped runs ---------------------------------------------------------------------


def test_reconciliation_is_skipped_when_disabled(
    graphql_helper, make_reporter, options
):
    """A disabled write-back skips the reconciliation."""
    reporter = make_reporter(graphql_helper, replace(options, reporting_enabled=False))
    summary = make_reconciler(reporter, FakeAdapter()).run_once()
    assert summary.skipped
    assert summary.reason == "Write-back disabled"
    graphql_helper.connector_logger.debug.assert_called()


def test_reconciliation_is_skipped_on_unsupported_platforms(
    graphql_helper, make_reporter, router, router_factory
):
    """Older platforms skip the reconciliation."""
    router.handlers.update(router_factory(mutations=()).handlers)
    summary = make_reconciler(make_reporter(graphql_helper), FakeAdapter()).run_once()
    assert summary.skipped
    assert "not supported" in summary.reason


def test_reconciliation_is_skipped_without_security_platform(
    graphql_helper, make_reporter, router
):
    """An unresolved security platform skips the reconciliation."""
    router.handlers["DeploymentSecurityPlatformAdd"] = {"data": None}
    summary = make_reconciler(make_reporter(graphql_helper), FakeAdapter()).run_once()
    assert summary.skipped
    assert summary.reason == "Security platform not resolved"


def test_reconciliation_is_skipped_when_the_vendor_read_back_fails(
    graphql_helper, make_reporter, router
):
    """A vendor error never leads to removals."""
    adapter = FakeAdapter(list_error=ConnectionError("vendor down"))
    summary = make_reconciler(make_reporter(graphql_helper), adapter).run_once()
    assert summary.skipped
    assert "vendor down" in summary.reason
    assert router.calls_of("IndicatorReportDeployments(") == []
    graphql_helper.connector_logger.warning.assert_called_once()


def test_reconciliation_is_skipped_while_queued_stream_reports_are_undelivered(
    graphql_helper, make_reporter, router
):
    """Sent again after the snapshot reports, older stream outcomes would overwrite
    them: the snapshot is not taken until they are delivered."""
    reporter = make_reporter(graphql_helper)
    reporter.enqueue(DeploymentReport(indicator_id="a", status=DeploymentStatus.FAILED))
    router.handlers["IndicatorReportDeployments("] = ConnectionError("unreachable")

    summary = make_reconciler(reporter, FakeAdapter()).run_once()

    assert summary.skipped
    assert summary.reason == "Queued stream reports not delivered"
    assert router.calls_of("IndicatorDeploymentsOfPlatform") == []
    assert list(reporter._buffer) == ["a"]


def test_reconciliation_is_skipped_when_the_deployments_cannot_be_listed(
    graphql_helper, make_reporter, router
):
    """An OpenCTI listing error skips the reconciliation."""
    router.handlers["IndicatorDeploymentsOfPlatform"] = ConnectionError("opencti down")
    summary = make_reconciler(make_reporter(graphql_helper), FakeAdapter()).run_once()
    assert summary.skipped
    assert "opencti down" in summary.reason


def test_unexpected_errors_never_raise(
    graphql_helper, make_reporter, monkeypatch, list_nodes
):
    """Unexpected errors are logged and the run is reported skipped."""
    list_nodes()
    reporter = make_reporter(graphql_helper)
    monkeypatch.setattr(
        reporter,
        "report_indicator_deployments",
        MagicMock(side_effect=RuntimeError("bug")),
    )
    summary = make_reconciler(reporter, FakeAdapter()).run_once()
    assert summary.skipped
    assert summary.reason == "bug"


def test_concurrent_runs_are_skipped(graphql_helper, make_reporter):
    """Only one reconciliation runs at a time."""
    reconciler = make_reconciler(make_reporter(graphql_helper), FakeAdapter())
    reconciler._run_lock.acquire()
    try:
        summary = reconciler.run_once()
    finally:
        reconciler._run_lock.release()
    assert summary.skipped
    assert summary.reason == "A reconciliation is already running"


# --- reconciliation algorithm --------------------------------------------------------


def test_reconciliation_applies_the_contract_algorithm(
    graphql_helper, make_reporter, router, list_nodes, node_factory, reported
):
    """Every step of the reconciliation algorithm is applied in one batch."""
    list_nodes(
        node_factory(
            indicator_id="present-by-id", status="deployed", standard_id="indicator--a"
        ),
        node_factory(
            indicator_id="absent-active", status="active", standard_id="indicator--b"
        ),
        node_factory(
            indicator_id="pending-absent", status="pending", standard_id="indicator--c"
        ),
        node_factory(
            indicator_id="failed-present-by-external-id",
            status="failed",
            external_id="ext-d",
            standard_id="indicator--d",
        ),
        node_factory(
            indicator_id="withdrawn-present-by-value",
            status="deployed",
            revoked=True,
            pattern="[domain-name:value = 'Withdrawn.Example']",
            standard_id="indicator--e",
        ),
        node_factory(
            indicator_id="expired-absent",
            status="active",
            valid_until="2026-01-01T00:00:00Z",
            pattern="[domain-name:value = 'gone.example']",
            standard_id="indicator--f",
        ),
        node_factory(
            indicator_id="opencti-expired-present",
            status="expired",
            standard_id="indicator--g",
        ),
        node_factory(
            indicator_id="failed-absent",
            status="failed",
            pattern="[domain-name:value = 'never.example']",
            standard_id="indicator--h",
        ),
    )
    graphql_helper.api.stix2.get_stix_bundle_or_object_from_entity_id.return_value = {
        "type": "indicator",
        "id": "indicator--c",
        "pattern": "[domain-name:value = 'retry.example']",
        "x_opencti_score": 70,
    }
    adapter = FakeAdapter(
        vendor=[
            VendorIndicator(indicator_id="INDICATOR--A", external_id="ext-a"),
            VendorIndicator(external_id="ext-d", value="unrelated.example"),
            VendorIndicator(value="withdrawn.example", external_id="ext-e"),
            VendorIndicator(
                indicator_id="opencti-expired-present", external_id="ext-g"
            ),
            VendorIndicator(indicator_id="indicator--unknown", external_id="ext-x"),
            VendorIndicator(indicator_id="indicator--unknown", external_id="ext-y"),
            VendorIndicator(value="orphan.example"),
        ]
    )
    reporter = make_reporter(graphql_helper)

    summary = make_reconciler(reporter, adapter).run_once()

    assert not summary.skipped
    assert summary.vendor_indicators == 7
    assert summary.deployments == 8
    assert summary.confirmed_active == 2
    assert summary.marked_removed == 2
    assert summary.repushed == 1
    assert summary.withdrawn == 2
    assert summary.discovered == 1
    assert summary.report_errors == 0

    reports = reported()
    assert reports["present-by-id"]["status"] == "active"
    assert reports["present-by-id"]["externalId"] == "ext-a"
    assert reports["absent-active"]["status"] == "removed"
    assert reports["pending-absent"] == {
        "indicatorId": "pending-absent",
        "status": "deployed",
        "externalId": "vendor-new",
        "metadata": {
            "deployed_at": "2026-10-03T12:00:00.000Z",
            "last_sync_at": "2026-10-03T12:00:00.000Z",
        },
    }
    assert reports["failed-present-by-external-id"]["status"] == "active"
    assert reports["failed-present-by-external-id"]["externalId"] == "ext-d"
    assert reports["withdrawn-present-by-value"]["status"] == "removed"
    assert reports["withdrawn-present-by-value"]["externalId"] == "ext-e"
    assert reports["expired-absent"]["status"] == "removed"
    assert reports["opencti-expired-present"]["status"] == "removed"
    assert reports["indicator--unknown"] == {
        "indicatorId": "indicator--unknown",
        "status": "active",
        "externalId": "ext-x",
        "metadata": {"last_sync_at": "2026-10-03T12:00:00.000Z"},
    }
    assert "failed-absent" not in reports
    assert len(reports) == 8

    assert [deployment.indicator_id for _vendor, deployment in adapter.removed] == [
        "withdrawn-present-by-value",
        "opencti-expired-present",
    ]
    pushed = adapter.pushed[0]
    assert (
        pushed["extensions"][
            "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
        ]["score"]
        == 70
    )
    graphql_helper.api.stix2.get_stix_bundle_or_object_from_entity_id.assert_called_once_with(
        entity_type="Indicator", entity_id="pending-absent", only_entity=True
    )
    statuses = router.calls_of("IndicatorDeploymentsOfPlatform")[0]["filters"][
        "filters"
    ][0]
    assert statuses["values"] == [status.value for status in LISTED_STATUSES]


def test_withdrawal_failures_are_not_reported(
    graphql_helper, make_reporter, list_nodes, node_factory, reported
):
    """A refused removal keeps the deployment unchanged (OpenCTI flags it expired)."""
    list_nodes(node_factory(indicator_id="a", status="active", revoked=True))
    adapter = FakeAdapter(
        vendor=[VendorIndicator(indicator_id="a")],
        remove_error=PermissionError("denied"),
    )

    summary = make_reconciler(make_reporter(graphql_helper), adapter).run_once()

    assert summary.withdrawal_failed == 1
    assert reported() == {}


def test_withdrawal_removes_every_vendor_item_of_the_indicator(
    graphql_helper, make_reporter, list_nodes, node_factory, reported
):
    """One indicator can be several vendor items (one per observable, duplicates):
    ``removed`` is only reported once every item matched by id is removed."""
    list_nodes(
        node_factory(
            indicator_id="a", status="active", revoked=True, standard_id="indicator--a"
        )
    )
    adapter = FakeAdapter(
        vendor=[
            VendorIndicator(indicator_id="a", external_id="ext-1"),
            VendorIndicator(indicator_id="indicator--a", external_id="ext-2"),
            VendorIndicator(indicator_id="a", external_id="ext-3"),
        ]
    )

    summary = make_reconciler(make_reporter(graphql_helper), adapter).run_once()

    assert [vendor.external_id for vendor, _deployment in adapter.removed] == [
        "ext-1",
        "ext-3",
        "ext-2",
    ]
    assert summary.withdrawn == 1
    assert summary.discovered == 0
    assert reported()["a"]["status"] == "removed"
    assert reported()["a"]["externalId"] == "ext-1"


def test_partial_withdrawal_is_not_reported(
    graphql_helper, make_reporter, list_nodes, node_factory, reported
):
    """When one item of the indicator cannot be removed, the next run retries."""

    class FailingOnSecondRemoval(FakeAdapter):
        def remove_vendor_indicator(self, vendor_indicator, deployment):
            if self.removed:
                raise PermissionError("denied")
            super().remove_vendor_indicator(vendor_indicator, deployment)

    list_nodes(node_factory(indicator_id="a", status="active", revoked=True))
    adapter = FailingOnSecondRemoval(
        vendor=[
            VendorIndicator(indicator_id="a", external_id="ext-1"),
            VendorIndicator(indicator_id="a", external_id="ext-2"),
        ]
    )

    summary = make_reconciler(make_reporter(graphql_helper), adapter).run_once()

    assert len(adapter.removed) == 1
    assert summary.withdrawal_failed == 1
    assert summary.withdrawn == 0
    assert reported() == {}


def test_value_matching_withdraws_a_single_vendor_item(
    graphql_helper, make_reporter, list_nodes, node_factory, reported
):
    """A value can be shared by unrelated indicators: only one item is removed."""
    list_nodes(
        node_factory(
            indicator_id="a",
            status="active",
            revoked=True,
            pattern="[domain-name:value = 'shared.example']",
        )
    )
    adapter = FakeAdapter(
        vendor=[
            VendorIndicator(value="shared.example", external_id="ext-1"),
            VendorIndicator(value="shared.example", external_id="ext-2"),
        ]
    )

    make_reconciler(make_reporter(graphql_helper), adapter).run_once()

    assert [vendor.external_id for vendor, _deployment in adapter.removed] == ["ext-1"]
    assert reported()["a"]["status"] == "removed"


@pytest.mark.parametrize(
    ("withdrawn", "matched_by"),
    [
        ({"revoked": True}, "external_id"),
        ({"status": "expired"}, "external_id"),
        ({"revoked": True}, "value"),
    ],
)
def test_a_vendor_item_shared_with_a_deployment_that_stays_is_not_removed(
    graphql_helper,
    make_reporter,
    list_nodes,
    node_factory,
    reported,
    withdrawn,
    matched_by,
):
    """Vendors de-duplicating by value hold one item for two indicators: withdrawing
    one of them leaves the item to the other one."""
    external_id = "ext-shared" if matched_by == "external_id" else None
    pattern = "[domain-name:value = 'shared.example']"
    list_nodes(
        node_factory(
            **{
                "indicator_id": "a",
                "status": "active",
                "pattern": pattern,
                "external_id": external_id,
                "standard_id": "indicator--a",
                **withdrawn,
            }
        ),
        node_factory(
            indicator_id="b",
            status="active",
            pattern=pattern,
            external_id=external_id,
            standard_id="indicator--b",
        ),
    )
    adapter = FakeAdapter(
        vendor=[VendorIndicator(value="shared.example", external_id="ext-shared")]
    )

    summary = make_reconciler(make_reporter(graphql_helper), adapter).run_once()

    assert adapter.removed == []
    assert summary.withdrawn == 1
    assert reported()["a"]["status"] == "removed"
    assert reported()["b"]["status"] == "active"


def test_a_vendor_item_of_withdrawn_deployments_only_is_removed(
    graphql_helper, make_reporter, list_nodes, node_factory, reported
):
    list_nodes(
        node_factory(
            indicator_id="a",
            status="active",
            revoked=True,
            external_id="ext-shared",
            standard_id="indicator--a",
        ),
        node_factory(
            indicator_id="b",
            status="expired",
            external_id="ext-shared",
            standard_id="indicator--b",
        ),
    )
    adapter = FakeAdapter(vendor=[VendorIndicator(external_id="ext-shared")])

    summary = make_reconciler(make_reporter(graphql_helper), adapter).run_once()

    assert [vendor.external_id for vendor, _deployment in adapter.removed] == [
        "ext-shared"
    ]
    assert summary.withdrawn == 2
    assert reported()["a"]["status"] == "removed"
    assert reported()["b"]["status"] == "removed"


def test_deployments_confirmed_during_the_read_back_are_deferred(
    graphql_helper, make_reporter, list_nodes, node_factory, reported
):
    """A deployment pushed by the stream after the read-back started is absent from
    the listing without being gone: no absence decision is taken this run."""
    during_run = "2026-10-03T12:00:05.000Z"
    list_nodes(
        node_factory(indicator_id="live", status="deployed", last_sync_at=during_run),
        node_factory(
            indicator_id="withdrawn",
            status="active",
            revoked=True,
            last_sync_at=during_run,
        ),
        node_factory(indicator_id="pending", status="pending", last_sync_at=during_run),
        node_factory(indicator_id="stale", status="active"),
    )
    adapter = FakeAdapter()

    summary = make_reconciler(make_reporter(graphql_helper), adapter).run_once()

    assert summary.deferred == 3
    assert summary.marked_removed == 1
    assert set(reported()) == {"stale"}
    assert adapter.pushed == []


def test_repush_failures_are_reported_failed(
    graphql_helper, make_reporter, list_nodes, node_factory, reported
):
    """A refused push, an unreadable or a non-indicator object give ``failed``."""
    list_nodes(
        node_factory(indicator_id="refused", status="pending", external_id="ext-1"),
        node_factory(
            indicator_id="unreadable", status="pending", standard_id="indicator--u"
        ),
        node_factory(
            indicator_id="not-indicator", status="pending", standard_id="indicator--n"
        ),
    )
    exports = {
        "refused": {
            "type": "indicator",
            "id": "indicator--r",
            "pattern": "[url:value = 'x']",
        },
        "unreadable": IndexError("list index out of range"),
        "not-indicator": {"type": "malware", "id": "malware--1"},
    }

    def export(entity_type, entity_id, only_entity):
        result = exports[entity_id]
        if isinstance(result, BaseException):
            raise result
        return result

    graphql_helper.api.stix2.get_stix_bundle_or_object_from_entity_id.side_effect = (
        export
    )
    adapter = FakeAdapter(push_error=ValueError(""))

    summary = make_reconciler(make_reporter(graphql_helper), adapter).run_once()

    assert summary.repush_failed == 3
    reports = reported()
    assert reports["refused"]["status"] == "failed"
    assert reports["refused"]["externalId"] == "ext-1"
    assert reports["refused"]["metadata"]["error_message"] == "ValueError"
    assert reports["unreadable"]["status"] == "failed"
    assert "cannot be read" in reports["unreadable"]["metadata"]["error_message"]
    assert reports["not-indicator"]["status"] == "failed"


class PartialAdapter(FakeAdapter):
    """Vendor holding only part of the observables of some indicators."""

    def __init__(self, incomplete, **kwargs):
        super().__init__(**kwargs)
        self.incomplete = set(incomplete)
        self.checked = {}

    def is_complete(self, deployment, vendor_matches):
        self.checked[deployment.indicator_id] = [
            match.external_id for match in vendor_matches
        ]
        return deployment.indicator_id not in self.incomplete


def test_deployments_only_partly_on_the_vendor_are_pushed_again(
    graphql_helper, make_reporter, list_nodes, node_factory, reported
):
    """An indicator with an observable missing on the vendor is pushed again instead
    of being confirmed active; a failed one stays failed until a new push is asked."""
    list_nodes(
        node_factory(indicator_id="partial", status="active"),
        node_factory(indicator_id="partial-failed", status="failed"),
        node_factory(indicator_id="complete", status="deployed"),
    )
    graphql_helper.api.stix2.get_stix_bundle_or_object_from_entity_id.return_value = {
        "type": "indicator",
        "id": "indicator--p",
        "pattern": "[url:value = 'x']",
    }
    adapter = PartialAdapter(
        incomplete={"partial", "partial-failed"},
        vendor=[
            VendorIndicator(indicator_id="partial", external_id="v-1"),
            VendorIndicator(indicator_id="partial-failed", external_id="v-2"),
            VendorIndicator(indicator_id="complete", external_id="v-3"),
        ],
    )

    summary = make_reconciler(make_reporter(graphql_helper), adapter).run_once()

    assert (summary.incomplete, summary.repushed, summary.confirmed_active) == (
        2,
        1,
        1,
    )
    assert adapter.checked == {
        "partial": ["v-1"],
        "partial-failed": ["v-2"],
        "complete": ["v-3"],
    }
    assert len(adapter.pushed) == 1
    reports = reported()
    assert reports["partial"]["status"] == "deployed"
    assert "partial-failed" not in reports
    assert reports["complete"]["status"] == "active"


def test_retained_inactive_vendor_objects_are_only_removed(
    graphql_helper, make_reporter, list_nodes, node_factory, reported
):
    """An expired or revoked object the vendor keeps is removed for a deployment that
    must be withdrawn, never confirms a live one and is never backfilled."""
    list_nodes(
        node_factory(indicator_id="withdrawn", status="active", revoked=True),
        node_factory(indicator_id="expired", status="expired"),
        node_factory(indicator_id="live", status="active"),
    )
    inactive = [
        VendorIndicator(indicator_id=identifier, external_id=f"v-{identifier}")
        for identifier in ("withdrawn", "expired", "live", "unknown")
    ]
    adapter = FakeAdapter(vendor=[replace(vendor, active=False) for vendor in inactive])

    summary = make_reconciler(make_reporter(graphql_helper), adapter).run_once()

    assert sorted(vendor.external_id for vendor, _ in adapter.removed) == [
        "v-expired",
        "v-withdrawn",
    ]
    assert (summary.withdrawn, summary.confirmed_active, summary.discovered) == (
        2,
        0,
        0,
    )
    reports = reported()
    assert {key: reports[key]["status"] for key in reports} == {
        "withdrawn": "removed",
        "expired": "removed",
        "live": "removed",
    }


def test_vendor_adapters_confirm_any_vendor_item_by_default():
    assert FakeAdapter().is_complete(None, [VendorIndicator(indicator_id="a")])


def test_truncated_read_back_skips_absence_decisions(
    graphql_helper, make_reporter, list_nodes, node_factory, reported
):
    """When the read-back limit is reached, absent deployments are left untouched."""
    list_nodes(
        node_factory(indicator_id="present", status="deployed"),
        node_factory(indicator_id="absent-live", status="active"),
        node_factory(indicator_id="absent-pending", status="pending"),
        node_factory(indicator_id="absent-revoked", status="active", revoked=True),
    )
    adapter = FakeAdapter(
        vendor=[VendorIndicator(indicator_id="present"), VendorIndicator(value="other")]
    )

    summary = make_reconciler(
        make_reporter(graphql_helper), adapter, max_vendor_indicators=1
    ).run_once()

    assert summary.vendor_listing_truncated
    assert summary.vendor_indicators == 1
    assert set(reported()) == {"present"}
    assert adapter.pushed == []


def test_reconciliation_without_any_report(
    graphql_helper, make_reporter, router, list_nodes
):
    """An empty platform sends nothing."""
    list_nodes()
    summary = make_reconciler(
        make_reporter(graphql_helper), ReadOnlyAdapter()
    ).run_once()
    assert not summary.skipped
    assert router.calls_of("IndicatorReportDeployments(") == []


# --- hits --------------------------------------------------------------------------------


def test_hits_are_aggregated_and_reported(
    graphql_helper, make_reporter, router, list_nodes, node_factory
):
    """New hits are matched, filtered on the last reported hit and aggregated."""
    list_nodes(
        node_factory(indicator_id="by-id", status="active", standard_id="indicator--1"),
        node_factory(
            indicator_id="by-external-id",
            status="deployed",
            external_id="ext-2",
            standard_id="indicator--2",
            pattern="[url:value = 'http://two.example']",
        ),
        node_factory(
            indicator_id="by-value",
            status="active",
            pattern="[domain-name:value = 'three.example']",
            last_hit_at="2026-10-03T11:00:00Z",
            standard_id="indicator--3",
        ),
        node_factory(
            indicator_id="not-live", status="failed", standard_id="indicator--4"
        ),
        node_factory(
            indicator_id="withdrawn",
            status="active",
            revoked=True,
            standard_id="indicator--5",
            pattern="[domain-name:value = 'five.example']",
        ),
    )
    adapter = FakeAdapter(
        vendor=[
            VendorIndicator(indicator_id="by-id"),
            VendorIndicator(external_id="ext-2"),
            VendorIndicator(value="three.example"),
            VendorIndicator(value="five.example"),
        ],
        hits=[
            VendorHit(
                timestamp=datetime(2026, 10, 3, 9, tzinfo=UTC),
                indicator_id="INDICATOR--1",
            ),
            VendorHit(
                timestamp=datetime(2026, 10, 3, 10, tzinfo=UTC),
                indicator_id="by-id",
                count=2,
            ),
            VendorHit(
                timestamp=datetime(2026, 10, 3, 8, tzinfo=UTC), external_id="ext-2"
            ),
            VendorHit(
                timestamp=datetime(2026, 10, 3, 10, tzinfo=UTC), value="Three.Example"
            ),
            VendorHit(
                timestamp=datetime(2026, 10, 3, 11, 30, tzinfo=UTC),
                value="three.example",
            ),
            VendorHit(
                timestamp=datetime(2026, 10, 3, 11, 0, tzinfo=UTC),
                value="unknown.example",
            ),
            VendorHit(
                timestamp=datetime(2026, 10, 3, 11, 0, tzinfo=UTC),
                indicator_id="by-id",
                count=0,
            ),
            VendorHit(timestamp="not a date", indicator_id="by-id"),
        ],
    )
    reporter = make_reporter(graphql_helper)
    reconciler = make_reconciler(reporter, adapter)

    summary = reconciler.run_once()

    assert summary.hits_reported == 3
    deployments, since = adapter.hits_calls[0]
    assert {deployment.indicator_id for deployment in deployments} == {
        "by-id",
        "by-external-id",
        "by-value",
    }
    assert since == NOW - timedelta(hours=1)
    hits = {
        call["indicatorId"]: call for call in router.calls_of("IndicatorReportHits(")
    }
    assert hits["by-id"]["count"] == 3
    assert hits["by-id"]["firstHit"] == "2026-10-03T09:00:00.000Z"
    assert hits["by-id"]["lastHit"] == "2026-10-03T10:00:00.000Z"
    assert hits["by-external-id"]["count"] == 1
    assert hits["by-value"]["count"] == 1
    assert hits["by-value"]["lastHit"] == "2026-10-03T11:30:00.000Z"

    reconciler.run_once()
    assert adapter.hits_calls[1][1] == NOW - timedelta(hours=1)


def test_hits_lookback_follows_the_interval(
    graphql_helper, make_reporter, options, list_nodes, node_factory
):
    """The hits window defaults to the reconciliation interval (at least one hour)."""
    list_nodes(node_factory(indicator_id="a", status="active"))
    adapter = FakeAdapter(vendor=[VendorIndicator(indicator_id="a")])
    reporter = make_reporter(
        graphql_helper, replace(options, reconciliation_interval=240)
    )

    make_reconciler(reporter, adapter).run_once()

    assert adapter.hits_calls[0][1] == NOW - timedelta(hours=4)


def test_capped_hit_collection_resumes_where_it_stopped(
    graphql_helper, make_reporter, router, list_nodes, node_factory
):
    """Only the hits before ``complete_until`` are reported, and the next run reads
    from there instead of skipping the capped detections."""
    list_nodes(node_factory(indicator_id="a", status="active"))
    complete_until = NOW - timedelta(minutes=30)
    adapter = FakeAdapter(vendor=[VendorIndicator(indicator_id="a")])
    adapter.hits = HitCollection(
        hits=[
            VendorHit(timestamp=NOW - timedelta(minutes=50), indicator_id="a"),
            VendorHit(timestamp=complete_until, indicator_id="a"),
            VendorHit(timestamp=NOW - timedelta(minutes=10), indicator_id="a"),
        ],
        complete_until=complete_until,
    )
    reconciler = make_reconciler(make_reporter(graphql_helper), adapter)

    assert reconciler.run_once().hits_reported == 1
    (hits,) = router.calls_of("IndicatorReportHits(")
    assert hits["count"] == 1
    assert hits["lastHit"] == "2026-10-03T11:10:00.000Z"
    assert reconciler._hits_since == complete_until

    adapter.hits = []
    reconciler.run_once()
    assert adapter.hits_calls[1][1] == complete_until


def test_hit_collection_capped_at_its_start_is_a_lower_bound(
    graphql_helper, make_reporter, router, list_nodes, node_factory
):
    """Without a continuation, the capped hits are reported as they are and the next
    run starts just after the capped instant, never at the end of the lookback."""
    list_nodes(node_factory(indicator_id="a", status="active"))
    adapter = FakeAdapter(vendor=[VendorIndicator(indicator_id="a")])
    since = NOW - timedelta(hours=1)
    adapter.hits = HitCollection(
        hits=[VendorHit(timestamp=NOW - timedelta(minutes=5), indicator_id="a")],
        complete_until=since,
    )
    reconciler = make_reconciler(make_reporter(graphql_helper), adapter)

    assert reconciler.run_once().hits_reported == 1
    assert adapter.hits_calls[0][1] == since
    assert reconciler._hits_since == since + CAPPED_INSTANT_STEP
    graphql_helper.connector_logger.warning.assert_called_once()


class ResumingAdapter(FakeAdapter):
    """Vendor whose reads are scripted, recording the continuation of each call."""

    def __init__(self, collections, **kwargs):
        super().__init__(**kwargs)
        self.collections = list(collections)
        self.resumes = []

    def collect_hits(self, deployments, since, *, resume=None):
        self.hits_calls.append((list(deployments), since))
        self.resumes.append(resume)
        collected = self.collections.pop(0)
        if self.hits_error:
            raise self.hits_error
        return collected


def test_capped_instant_is_read_further_with_the_continuation(
    graphql_helper, make_reporter, router, list_nodes, node_factory
):
    """The detections of an instant capped by the vendor read are held until the
    instant is read completely, then reported together."""
    list_nodes(node_factory(indicator_id="a", status="active"))
    since = NOW - timedelta(hours=1)
    later = NOW - timedelta(minutes=10)
    adapter = ResumingAdapter(
        [
            HitCollection(
                hits=[VendorHit(timestamp=since, indicator_id="a")] * 2,
                complete_until=since,
                resume=2,
            ),
            HitCollection(
                hits=[VendorHit(timestamp=since, indicator_id="a")] * 2,
                complete_until=since,
                resume=4,
            ),
            HitCollection(
                hits=[
                    VendorHit(timestamp=since, indicator_id="a"),
                    VendorHit(timestamp=later, indicator_id="a"),
                ]
            ),
        ],
        vendor=[VendorIndicator(indicator_id="a")],
    )
    reconciler = make_reconciler(make_reporter(graphql_helper), adapter)

    assert reconciler.run_once().hits_reported == 0
    assert reconciler._hits_since == since
    assert reconciler.run_once().hits_reported == 0
    assert reconciler._hits_since == since
    assert router.calls_of("IndicatorReportHits(") == []

    assert reconciler.run_once().hits_reported == 1
    assert adapter.resumes == [None, 2, 4]
    assert [call[1] for call in adapter.hits_calls] == [since, since, since]
    (hits,) = router.calls_of("IndicatorReportHits(")
    assert hits["count"] == 6
    assert hits["lastHit"] == "2026-10-03T11:50:00.000Z"
    assert reconciler._hits_since == NOW - reconciler._hits_lookback
    assert reconciler._hits_resume is None
    assert reconciler._held_hits == []


def test_capped_instant_continued_until_a_later_complete_until(
    graphql_helper, make_reporter, router, list_nodes, node_factory
):
    list_nodes(node_factory(indicator_id="a", status="active"))
    since = NOW - timedelta(hours=1)
    complete_until = NOW - timedelta(minutes=30)
    adapter = ResumingAdapter(
        [
            HitCollection(
                hits=[VendorHit(timestamp=since, indicator_id="a")],
                complete_until=since,
                resume="page-2",
            ),
            HitCollection(
                hits=[
                    VendorHit(timestamp=since, indicator_id="a"),
                    VendorHit(timestamp=complete_until, indicator_id="a"),
                ],
                complete_until=complete_until,
            ),
        ],
        vendor=[VendorIndicator(indicator_id="a")],
    )
    reconciler = make_reconciler(make_reporter(graphql_helper), adapter)

    reconciler.run_once()
    assert reconciler.run_once().hits_reported == 1
    (hits,) = router.calls_of("IndicatorReportHits(")
    assert hits["count"] == 2
    assert reconciler._hits_since == complete_until


def test_capped_instant_without_progress_moves_past_it(
    graphql_helper, make_reporter, router, list_nodes, node_factory
):
    """A continuation returned twice (nothing more read) is not followed forever."""
    list_nodes(node_factory(indicator_id="a", status="active"))
    since = NOW - timedelta(hours=1)
    capped = HitCollection(
        hits=[VendorHit(timestamp=since, indicator_id="a")],
        complete_until=since,
        resume="same",
    )
    adapter = ResumingAdapter(
        [capped, capped], vendor=[VendorIndicator(indicator_id="a")]
    )
    reconciler = make_reconciler(make_reporter(graphql_helper), adapter)

    assert reconciler.run_once().hits_reported == 0
    assert reconciler.run_once().hits_reported == 1
    (hits,) = router.calls_of("IndicatorReportHits(")
    assert hits["count"] == 2
    assert reconciler._hits_since == since + CAPPED_INSTANT_STEP
    assert reconciler._hits_resume is None


def test_capped_instant_held_hits_are_bounded(
    graphql_helper, make_reporter, router, list_nodes, node_factory, monkeypatch
):
    monkeypatch.setattr(reconciler_module, "MAX_HELD_HITS", 3)
    list_nodes(node_factory(indicator_id="a", status="active"))
    since = NOW - timedelta(hours=1)
    adapter = ResumingAdapter(
        [
            HitCollection(
                hits=[VendorHit(timestamp=since, indicator_id="a")] * 2,
                complete_until=since,
                resume=2,
            ),
            HitCollection(
                hits=[VendorHit(timestamp=since, indicator_id="a")] * 2,
                complete_until=since,
                resume=4,
            ),
        ],
        vendor=[VendorIndicator(indicator_id="a")],
    )
    reconciler = make_reconciler(make_reporter(graphql_helper), adapter)

    reconciler.run_once()
    assert reconciler.run_once().hits_reported == 1
    (hits,) = router.calls_of("IndicatorReportHits(")
    assert hits["count"] == 4
    assert reconciler._hits_since == since + CAPPED_INSTANT_STEP


def test_capped_instant_read_again_from_its_start_after_a_vendor_error(
    graphql_helper, make_reporter, router, list_nodes, node_factory
):
    """A failed continued read (stale continuation) drops the held hits: the instant
    is read again from its start, so nothing is counted twice."""
    list_nodes(node_factory(indicator_id="a", status="active"))
    since = NOW - timedelta(hours=1)
    adapter = ResumingAdapter(
        [
            HitCollection(
                hits=[VendorHit(timestamp=since, indicator_id="a")],
                complete_until=since,
                resume="token",
            ),
            [],
            [VendorHit(timestamp=since, indicator_id="a")],
        ],
        vendor=[VendorIndicator(indicator_id="a")],
    )
    reconciler = make_reconciler(make_reporter(graphql_helper), adapter)

    reconciler.run_once()
    adapter.hits_error = RuntimeError("continuation expired")
    assert reconciler.run_once().hits_reported == 0
    assert reconciler._hits_resume is None
    assert reconciler._held_hits == []
    assert reconciler._hits_since == since

    adapter.hits_error = None
    assert reconciler.run_once().hits_reported == 1
    assert adapter.resumes == [None, "token", None]
    (hits,) = router.calls_of("IndicatorReportHits(")
    assert hits["count"] == 1


def test_complete_hit_collection_advances_the_window(
    graphql_helper, make_reporter, list_nodes, node_factory
):
    list_nodes(node_factory(indicator_id="a", status="active"))
    adapter = FakeAdapter(vendor=[VendorIndicator(indicator_id="a")])
    adapter.hits = HitCollection(
        hits=[VendorHit(timestamp=NOW - timedelta(minutes=5), indicator_id="a")]
    )
    reconciler = make_reconciler(make_reporter(graphql_helper), adapter)

    assert reconciler.run_once().hits_reported == 1
    assert reconciler._hits_since == NOW - reconciler._hits_lookback


def stateful_helper(router, state):
    """GraphQL helper keeping a connector state, as pycti does between restarts."""
    helper = MagicMock(spec=["api", "connector_logger", "get_state", "set_state"])
    helper.api.query.side_effect = router
    holder = {"state": state}
    helper.get_state.side_effect = lambda: (
        dict(holder["state"]) if holder["state"] is not None else None
    )
    helper.set_state.side_effect = lambda new_state: holder.update(state=new_state)
    helper.holder = holder
    return helper


def checkpoint_of(helper):
    return helper.holder["state"][reconciler_module.HITS_CHECKPOINT_STATE_KEY]


def test_hit_checkpoint_is_kept_in_the_connector_state(
    router, make_reporter, list_nodes, node_factory
):
    list_nodes(node_factory(indicator_id="a", status="active"))
    helper = stateful_helper(router, {"start_from": "1-0"})
    adapter = FakeAdapter(
        vendor=[VendorIndicator(indicator_id="a")],
        hits=[VendorHit(timestamp=NOW - timedelta(minutes=5), indicator_id="a")],
    )
    reconciler = make_reconciler(make_reporter(helper), adapter)

    assert reconciler.run_once().hits_reported == 1

    assert helper.holder["state"]["start_from"] == "1-0"
    assert checkpoint_of(helper) == "2026-10-03T11:00:00.000Z"


@pytest.mark.parametrize(
    "stopped_for, since",
    [
        (timedelta(days=3), NOW - timedelta(days=3)),
        (timedelta(days=30), NOW - reconciler_module.MAX_HITS_RECOVERY),
        (timedelta(minutes=10), NOW - timedelta(hours=1)),
    ],
)
def test_first_hit_read_after_a_start_resumes_at_the_checkpoint(
    router, make_reporter, list_nodes, node_factory, stopped_for, since
):
    """The detections of a stop longer than the lookback are read too, within the
    recovery window; a short stop keeps the lookback overlap."""
    list_nodes(node_factory(indicator_id="a", status="active"))
    state = {
        "start_from": "1-0",
        reconciler_module.HITS_CHECKPOINT_STATE_KEY: (NOW - stopped_for).isoformat(),
    }
    adapter = FakeAdapter(vendor=[VendorIndicator(indicator_id="a")])
    reconciler = make_reconciler(make_reporter(stateful_helper(router, state)), adapter)

    reconciler.run_once()

    assert adapter.hits_calls[0][1] == since


def test_hit_checkpoint_never_passes_an_undelivered_report(
    router, make_reporter, list_nodes, node_factory
):
    router.handlers["IndicatorReportHits("] = ValueError("unavailable")
    list_nodes(node_factory(indicator_id="a", status="active"))
    helper = stateful_helper(router, {"start_from": "1-0"})
    adapter = FakeAdapter(
        vendor=[VendorIndicator(indicator_id="a")],
        hits=[VendorHit(timestamp=NOW - timedelta(minutes=50), indicator_id="a")],
    )
    clock = [NOW]
    reconciler = make_reconciler(make_reporter(helper), adapter, clock=lambda: clock[0])
    reconciler.run_once()
    adapter.hits = []
    clock[0] = NOW + timedelta(hours=2)

    reconciler.run_once()

    assert reconciler._hits_since == clock[0] - reconciler._hits_lookback
    assert checkpoint_of(helper) == "2026-10-03T11:10:00.000Z"


def test_a_reset_connector_state_is_never_replaced(
    router, make_reporter, list_nodes, node_factory
):
    """pycti reads a state set to None as a reset and starts the stream over."""
    list_nodes(node_factory(indicator_id="a", status="active"))
    helper = stateful_helper(router, None)
    adapter = FakeAdapter(vendor=[VendorIndicator(indicator_id="a")])
    reconciler = make_reconciler(make_reporter(helper), adapter)

    reconciler.run_once()

    assert adapter.hits_calls[0][1] == NOW - reconciler._hits_lookback
    assert helper.holder["state"] is None


def run_with_a_hit(make_reporter, list_nodes, node_factory, helper):
    """Run once with a hit, so that the hit checkpoint is written in the state."""
    list_nodes(node_factory(indicator_id="a", status="active"))
    adapter = FakeAdapter(
        vendor=[VendorIndicator(indicator_id="a")],
        hits=[VendorHit(timestamp=NOW - timedelta(minutes=5), indicator_id="a")],
    )
    make_reconciler(make_reporter(helper), adapter).run_once()


def test_a_stream_position_written_from_an_older_state_keeps_the_hit_checkpoint(
    router, make_reporter, list_nodes, node_factory
):
    """The stream listener of pycti reads the state, handles an event and writes
    its position back: a checkpoint written meanwhile is never lost."""
    helper = stateful_helper(router, {"start_from": "1-0"})
    read_by_the_listener = helper.get_state()
    run_with_a_hit(make_reporter, list_nodes, node_factory, helper)
    read_by_the_listener["start_from"] = "2-0"

    helper.set_state(read_by_the_listener)

    assert helper.holder["state"]["start_from"] == "2-0"
    assert checkpoint_of(helper) == "2026-10-03T11:00:00.000Z"
    # A position written from a state read after the checkpoint is written as it is
    fresh = helper.get_state()
    fresh["start_from"] = "3-0"
    helper.set_state(fresh)
    assert helper.holder["state"]["start_from"] == "3-0"
    assert checkpoint_of(helper) == "2026-10-03T11:00:00.000Z"


def test_a_reset_of_the_connector_state_is_never_undone_by_the_checkpoint(
    router, make_reporter, list_nodes, node_factory
):
    """The ping of the platform writes a reset with the original writer: the
    checkpoint is not put back by the next writes of the stream listener."""
    helper = stateful_helper(router, {"start_from": "1-0"})
    original_write = helper.set_state
    run_with_a_hit(make_reporter, list_nodes, node_factory, helper)

    original_write({"start_from": "0-0"})
    helper.set_state({"start_from": "1-0"})
    assert helper.holder["state"] == {"start_from": "1-0"}
    helper.set_state(None)

    assert helper.holder["state"] is None
    helper.set_state({"start_from": "0-0"})
    assert helper.holder["state"] == {"start_from": "0-0"}


def test_a_listener_write_goes_on_when_the_state_cannot_be_read(
    router, make_reporter, list_nodes, node_factory
):
    helper = stateful_helper(router, {"start_from": "1-0"})
    run_with_a_hit(make_reporter, list_nodes, node_factory, helper)
    helper.get_state.side_effect = RuntimeError("state unavailable")

    helper.set_state({"start_from": "2-0"})

    assert helper.holder["state"] == {"start_from": "2-0"}


def test_concurrent_writers_never_roll_back_the_stream_position_or_the_checkpoint(
    router,
):
    """Both writers run at once: the last stream position and the last checkpoint
    are the ones kept."""
    helper = stateful_helper(router, {"start_from": "0-0"})
    guard = reconciler_module._ConnectorStateGuard.of(helper)
    rounds = 500

    def listener():
        for index in range(1, rounds + 1):
            state = helper.get_state()
            state["start_from"] = f"{index}-0"
            helper.set_state(state)

    def reconciler():
        for index in range(1, rounds + 1):
            guard.update(reconciler_module.HITS_CHECKPOINT_STATE_KEY, index)

    threads = [threading.Thread(target=listener), threading.Thread(target=reconciler)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert reconciler_module._ConnectorStateGuard.of(helper) is guard
    assert helper.holder["state"]["start_from"] == f"{rounds}-0"
    assert checkpoint_of(helper) == rounds


def test_connector_state_errors_never_stop_the_hits(
    router, make_reporter, list_nodes, node_factory
):
    list_nodes(node_factory(indicator_id="a", status="active"))
    helper = stateful_helper(router, {})
    helper.get_state.side_effect = RuntimeError("state unavailable")
    adapter = FakeAdapter(
        vendor=[VendorIndicator(indicator_id="a")],
        hits=[VendorHit(timestamp=NOW - timedelta(minutes=5), indicator_id="a")],
    )
    reconciler = make_reconciler(make_reporter(helper), adapter)

    assert reconciler.run_once().hits_reported == 1
    assert adapter.hits_calls[0][1] == NOW - reconciler._hits_lookback
    assert helper.holder["state"] == {}


def test_stream_reports_queued_during_the_snapshot_are_sent_after_it(
    graphql_helper, make_reporter, router, list_nodes, node_factory
):
    """A stream removal that happens while the vendor is read back is applied after
    the (stale) `active` report of the snapshot, never before."""
    list_nodes(node_factory(indicator_id="a", status="deployed"))
    reporter = make_reporter(graphql_helper)

    class StreamDuringSnapshot(FakeAdapter):
        def list_vendor_indicators(self):
            reporter.enqueue(
                DeploymentReport(indicator_id="a", status=DeploymentStatus.REMOVED)
            )
            yield from super().list_vendor_indicators()

    adapter = StreamDuringSnapshot(vendor=[VendorIndicator(indicator_id="a")])

    make_reconciler(reporter, adapter).run_once()

    batches = [
        [(report["indicatorId"], report["status"]) for report in call["reports"]]
        for call in router.calls_of("IndicatorReportDeployments(")
    ]
    assert batches == [[("a", "active")], [("a", "removed")]]


def test_queued_reports_are_held_without_blocking(
    graphql_helper, make_reporter, router
):
    reporter = make_reporter(graphql_helper)

    with reporter.holding_queued_reports():
        reporter.enqueue(
            DeploymentReport(indicator_id="a", status=DeploymentStatus.REMOVED)
        )
        assert reporter.flush(wait=False).processed == 0
        assert router.calls_of("IndicatorReportDeployments(") == []

    (batch,) = router.calls_of("IndicatorReportDeployments(")
    assert batch["reports"][0]["indicatorId"] == "a"


def test_undelivered_hit_reports_are_sent_with_the_next_run(
    graphql_helper, make_reporter, router, list_nodes, node_factory
):
    """An OpenCTI outage loses no detection: the window moves on, the undelivered
    report is sent again unchanged and the newer hits in their own report."""
    router.handlers["IndicatorReportHits("] = ValueError("unavailable")
    list_nodes(node_factory(indicator_id="a", status="active"))
    adapter = FakeAdapter(
        vendor=[VendorIndicator(indicator_id="a")],
        hits=[VendorHit(timestamp=NOW - timedelta(minutes=5), indicator_id="a")],
    )
    reconciler = make_reconciler(make_reporter(graphql_helper), adapter)

    assert reconciler.run_once().hits_reported == 0
    assert reconciler._hits_since == NOW - reconciler._hits_lookback
    assert list(reconciler._pending_hits) == ["a"]

    router.handlers["IndicatorReportHits("] = {
        "data": {"indicatorReportHits": {"id": "sighting"}}
    }
    adapter.hits = [VendorHit(timestamp=NOW - timedelta(minutes=1), indicator_id="a")]
    assert reconciler.run_once().hits_reported == 1
    undelivered, replayed, newer = router.calls_of("IndicatorReportHits(")[-3:]
    assert (replayed["count"], replayed["firstHit"], replayed["lastHit"]) == (
        1,
        "2026-10-03T11:55:00.000Z",
        "2026-10-03T11:55:00.000Z",
    )
    assert (newer["count"], newer["firstHit"], newer["lastHit"]) == (
        1,
        "2026-10-03T11:59:00.000Z",
        "2026-10-03T11:59:00.000Z",
    )
    # The report sent again keeps its id, so OpenCTI never counts it twice; the
    # newer hits are a distinct report
    assert replayed["reportId"] == undelivered["reportId"]
    assert newer["reportId"] not in (None, replayed["reportId"])
    assert reconciler._pending_hits == {}


def _hit_reports(router):
    return [
        (call["count"], call["lastHit"])
        for call in router.calls_of("IndicatorReportHits(")
    ]


def test_newer_hits_wait_behind_an_undelivered_report_without_changing_it(
    graphql_helper, make_reporter, router, list_nodes, node_factory
):
    """OpenCTI may have recorded a report whose call timed out, and only ignores a
    report that is not newer: the report is never merged with newer hits, and the
    newer hits are only sent once it is delivered."""
    router.handlers["IndicatorReportHits("] = ValueError("unavailable")
    list_nodes(node_factory(indicator_id="a", status="active"))
    adapter = FakeAdapter(
        vendor=[VendorIndicator(indicator_id="a")],
        hits=[
            VendorHit(timestamp=NOW - timedelta(minutes=9), indicator_id="a"),
            VendorHit(timestamp=NOW - timedelta(minutes=8), indicator_id="a"),
        ],
    )
    reconciler = make_reconciler(make_reporter(graphql_helper), adapter)
    reconciler.run_once()

    adapter.hits = [VendorHit(timestamp=NOW - timedelta(minutes=6), indicator_id="a")]
    reconciler.run_once()
    adapter.hits = [VendorHit(timestamp=NOW - timedelta(minutes=4), indicator_id="a")]
    reconciler.run_once()

    assert _hit_reports(router) == [(2, "2026-10-03T11:52:00.000Z")] * 3
    assert [
        (pending.count, pending.failing_since is None)
        for pending in reconciler._pending_hits["a"]
    ] == [(2, False), (2, True)]

    router.handlers["IndicatorReportHits("] = {
        "data": {"indicatorReportHits": {"id": "sighting"}}
    }
    adapter.hits = []
    assert reconciler.run_once().hits_reported == 1
    assert _hit_reports(router)[-2:] == [
        (2, "2026-10-03T11:52:00.000Z"),
        (2, "2026-10-03T11:56:00.000Z"),
    ]
    assert reconciler._pending_hits == {}


def test_newer_hits_are_sent_alone_once_an_undelivered_report_expires(
    graphql_helper, make_reporter, router, list_nodes, node_factory
):
    router.handlers["IndicatorReportHits("] = ValueError("unavailable")
    list_nodes(node_factory(indicator_id="a", status="active"))
    adapter = FakeAdapter(
        vendor=[VendorIndicator(indicator_id="a")],
        hits=[VendorHit(timestamp=NOW - timedelta(minutes=5), indicator_id="a")],
    )
    clock = {"now": NOW}
    reconciler = make_reconciler(
        make_reporter(graphql_helper), adapter, clock=lambda: clock["now"]
    )
    reconciler.run_once()

    clock["now"] = NOW + reconciler_module.MAX_PENDING_HITS_AGE + timedelta(minutes=1)
    adapter.hits = [
        VendorHit(timestamp=clock["now"] - timedelta(minutes=1), indicator_id="a")
    ]
    reconciler.run_once()

    assert [
        (pending.count, pending.failing_since)
        for pending in reconciler._pending_hits["a"]
    ] == [(1, clock["now"])]
    assert _hit_reports(router)[-2:] == [
        (1, "2026-10-03T11:55:00.000Z"),
        (1, "2026-10-04T12:00:00.000Z"),
    ]


def test_a_hit_held_in_an_undelivered_report_is_not_counted_again(
    graphql_helper, make_reporter, router, list_nodes, node_factory
):
    """The hit reads overlap: a hit already held in an undelivered report is not
    counted again when the next run reads it a second time."""
    router.handlers["IndicatorReportHits("] = ValueError("unavailable")
    list_nodes(node_factory(indicator_id="a", status="active"))
    first_hit = VendorHit(timestamp=NOW - timedelta(minutes=5), indicator_id="a")
    adapter = FakeAdapter(vendor=[VendorIndicator(indicator_id="a")], hits=[first_hit])
    reconciler = make_reconciler(make_reporter(graphql_helper), adapter)
    reconciler.run_once()

    router.handlers["IndicatorReportHits("] = {
        "data": {"indicatorReportHits": {"id": "sighting"}}
    }
    adapter.hits = [
        first_hit,
        VendorHit(timestamp=NOW - timedelta(minutes=1), indicator_id="a"),
    ]
    assert reconciler.run_once().hits_reported == 1
    assert _hit_reports(router)[-2:] == [
        (1, "2026-10-03T11:55:00.000Z"),
        (1, "2026-10-03T11:59:00.000Z"),
    ]


def test_a_newer_last_hit_recorded_by_opencti_stays_the_watermark(
    graphql_helper, make_reporter, router, list_nodes, node_factory
):
    router.handlers["IndicatorReportHits("] = ValueError("unavailable")
    list_nodes(node_factory(indicator_id="a", status="active"))
    adapter = FakeAdapter(
        vendor=[VendorIndicator(indicator_id="a")],
        hits=[VendorHit(timestamp=NOW - timedelta(minutes=10), indicator_id="a")],
    )
    reconciler = make_reconciler(make_reporter(graphql_helper), adapter)
    reconciler.run_once()

    router.handlers["IndicatorReportHits("] = {
        "data": {"indicatorReportHits": {"id": "sighting"}}
    }
    list_nodes(
        node_factory(
            indicator_id="a", status="active", last_hit_at="2026-10-03T11:55:00Z"
        )
    )
    adapter.hits = [
        VendorHit(timestamp=NOW - timedelta(minutes=7), indicator_id="a"),
        VendorHit(timestamp=NOW - timedelta(minutes=2), indicator_id="a"),
    ]
    assert reconciler.run_once().hits_reported == 1
    # The replay is not newer than the last hit OpenCTI recorded: OpenCTI ignores it.
    assert _hit_reports(router)[-2:] == [
        (1, "2026-10-03T11:50:00.000Z"),
        (1, "2026-10-03T11:58:00.000Z"),
    ]


def test_hit_reports_rejected_by_opencti_are_not_sent_again(
    graphql_helper, make_reporter, router, list_nodes, node_factory
):
    router.handlers["IndicatorReportHits("] = ValueError(
        {"name": "FUNCTIONAL_ERROR", "error_message": "Indicator not found"}
    )
    list_nodes(node_factory(indicator_id="a", status="active"))
    adapter = FakeAdapter(
        vendor=[VendorIndicator(indicator_id="a")],
        hits=[VendorHit(timestamp=NOW - timedelta(minutes=5), indicator_id="a")],
    )
    reconciler = make_reconciler(make_reporter(graphql_helper), adapter)

    assert reconciler.run_once().hits_reported == 0
    assert reconciler._pending_hits == {}


def test_undelivered_hit_reports_are_dropped_after_the_maximum_age(
    graphql_helper, make_reporter, router, list_nodes, node_factory
):
    router.handlers["IndicatorReportHits("] = ValueError("unavailable")
    list_nodes(node_factory(indicator_id="a", status="active"))
    adapter = FakeAdapter(
        vendor=[VendorIndicator(indicator_id="a")],
        hits=[VendorHit(timestamp=NOW - timedelta(minutes=5), indicator_id="a")],
    )
    clock = {"now": NOW}
    reconciler = make_reconciler(
        make_reporter(graphql_helper), adapter, clock=lambda: clock["now"]
    )

    reconciler.run_once()
    assert list(reconciler._pending_hits) == ["a"]
    adapter.hits = []
    clock["now"] = NOW + reconciler_module.MAX_PENDING_HITS_AGE + timedelta(minutes=1)
    reconciler.run_once()
    assert reconciler._pending_hits == {}


def test_undelivered_hit_reports_are_sent_when_the_vendor_cannot_be_read(
    graphql_helper, make_reporter, router, list_nodes, node_factory
):
    router.handlers["IndicatorReportHits("] = ValueError("unavailable")
    list_nodes(node_factory(indicator_id="a", status="active"))
    adapter = FakeAdapter(
        vendor=[VendorIndicator(indicator_id="a")],
        hits=[VendorHit(timestamp=NOW - timedelta(minutes=5), indicator_id="a")],
    )
    reconciler = make_reconciler(make_reporter(graphql_helper), adapter)
    reconciler.run_once()
    assert list(reconciler._pending_hits) == ["a"]

    router.handlers["IndicatorReportHits("] = {
        "data": {"indicatorReportHits": {"id": "sighting"}}
    }
    adapter.hits_error = RuntimeError("vendor unavailable")
    assert reconciler.run_once().hits_reported == 1
    assert router.calls_of("IndicatorReportHits(")[-1]["count"] == 1
    assert reconciler._pending_hits == {}


def test_undelivered_hit_reports_are_sent_when_no_deployment_is_live(
    graphql_helper, make_reporter, router, list_nodes, node_factory
):
    router.handlers["IndicatorReportHits("] = ValueError("unavailable")
    list_nodes(node_factory(indicator_id="a", status="active"))
    adapter = FakeAdapter(
        vendor=[VendorIndicator(indicator_id="a")],
        hits=[VendorHit(timestamp=NOW - timedelta(minutes=5), indicator_id="a")],
    )
    reconciler = make_reconciler(make_reporter(graphql_helper), adapter)
    reconciler.run_once()
    assert list(reconciler._pending_hits) == ["a"]

    router.handlers["IndicatorReportHits("] = {
        "data": {"indicatorReportHits": {"id": "sighting"}}
    }
    list_nodes()
    adapter.vendor = []
    adapter.hits = []
    assert reconciler.run_once().hits_reported == 1
    assert router.calls_of("IndicatorReportHits(")[-1]["count"] == 1
    assert reconciler._pending_hits == {}


def test_a_hit_matched_by_value_credits_every_indicator_carrying_it(
    graphql_helper, make_reporter, router, list_nodes, node_factory
):
    list_nodes(
        node_factory(indicator_id="a", status="active", standard_id="indicator--a"),
        node_factory(indicator_id="b", status="active", standard_id="indicator--b"),
    )
    adapter = FakeAdapter(
        vendor=[VendorIndicator(indicator_id="a"), VendorIndicator(indicator_id="b")],
        hits=[VendorHit(timestamp=NOW - timedelta(minutes=5), value="198.51.100.7")],
    )
    reconciler = make_reconciler(make_reporter(graphql_helper), adapter)

    assert reconciler.run_once().hits_reported == 2
    assert sorted(
        call["indicatorId"] for call in router.calls_of("IndicatorReportHits(")
    ) == ["a", "b"]


def test_a_deployment_removed_by_the_run_gets_no_hit_of_a_shared_value(
    graphql_helper, make_reporter, router, list_nodes, node_factory
):
    list_nodes(
        node_factory(indicator_id="a", status="active", standard_id="indicator--a"),
        node_factory(indicator_id="b", status="active", standard_id="indicator--b"),
    )
    adapter = FakeAdapter(
        vendor=[VendorIndicator(indicator_id="a")],
        hits=[VendorHit(timestamp=NOW - timedelta(minutes=5), value="198.51.100.7")],
    )
    reconciler = make_reconciler(make_reporter(graphql_helper), adapter)

    summary = reconciler.run_once()

    assert summary.marked_removed == 1
    assert summary.hits_reported == 1
    assert [
        call["indicatorId"] for call in router.calls_of("IndicatorReportHits(")
    ] == ["a"]


def test_hit_window_advances_past_a_single_rejected_indicator(
    graphql_helper, make_reporter, router, list_nodes, node_factory
):
    calls = []

    def report_hits(variables):
        calls.append(variables["indicatorId"])
        if variables["indicatorId"] == "gone":
            raise ValueError("Indicator not found or not accessible")
        return {"data": {"indicatorReportHits": {"id": "sighting"}}}

    router.handlers["IndicatorReportHits("] = report_hits
    list_nodes(
        node_factory(indicator_id="a", status="active", standard_id="indicator--a"),
        node_factory(indicator_id="gone", status="active", standard_id="indicator--g"),
    )
    adapter = FakeAdapter(
        vendor=[
            VendorIndicator(indicator_id="a"),
            VendorIndicator(indicator_id="gone"),
        ],
        hits=[
            VendorHit(timestamp=NOW - timedelta(minutes=5), indicator_id="a"),
            VendorHit(timestamp=NOW - timedelta(minutes=5), indicator_id="gone"),
        ],
    )
    reconciler = make_reconciler(make_reporter(graphql_helper), adapter)

    assert reconciler.run_once().hits_reported == 1
    assert sorted(calls) == ["a", "gone"]
    assert reconciler._hits_since == NOW - reconciler._hits_lookback


def test_failed_hit_reports_are_not_counted(
    graphql_helper, make_reporter, router, list_nodes, node_factory
):
    """Hits rejected by OpenCTI are not counted as reported."""
    router.handlers["IndicatorReportHits("] = ValueError("boom")
    list_nodes(node_factory(indicator_id="a", status="active"))
    adapter = FakeAdapter(
        vendor=[VendorIndicator(indicator_id="a")],
        hits=[VendorHit(timestamp=NOW, indicator_id="a")],
    )
    summary = make_reconciler(make_reporter(graphql_helper), adapter).run_once()
    assert summary.hits_reported == 0


def test_hits_collection_errors_never_raise(
    graphql_helper, make_reporter, list_nodes, node_factory
):
    """Vendor errors while reading detections are logged."""
    list_nodes(node_factory(indicator_id="a", status="active"))
    adapter = FakeAdapter(
        vendor=[VendorIndicator(indicator_id="a")], hits_error=TimeoutError("slow")
    )
    reconciler = make_reconciler(make_reporter(graphql_helper), adapter)

    summary = reconciler.run_once()

    assert summary.hits_reported == 0
    assert not summary.skipped
    graphql_helper.connector_logger.warning.assert_called_once()
    assert reconciler._hits_since is None


def test_hits_without_live_deployments(graphql_helper, make_reporter, list_nodes):
    """No live deployment means no detection query."""
    list_nodes()
    adapter = FakeAdapter()
    reconciler = make_reconciler(make_reporter(graphql_helper), adapter)
    assert reconciler.run_once().hits_reported == 0
    assert adapter.hits_calls == []
    assert reconciler._hits_since == NOW - reconciler._hits_lookback


def test_hits_disabled_by_configuration(
    graphql_helper, make_reporter, options, list_nodes, node_factory
):
    """``HITS_REPORTING_ENABLED=false`` skips the detection query."""
    list_nodes(node_factory(indicator_id="a", status="active"))
    adapter = FakeAdapter(vendor=[VendorIndicator(indicator_id="a")])
    reporter = make_reporter(
        graphql_helper, replace(options, hits_reporting_enabled=False)
    )
    make_reconciler(reporter, adapter).run_once()
    assert adapter.hits_calls == []


def test_default_adapter_reports_no_hit():
    """Adapters that cannot read detections report no hit."""
    assert (
        ReadOnlyAdapter().collect_hits([IndicatorDeployment("r", "active", "i")], NOW)
        == ()
    )


# --- scheduling --------------------------------------------------------------------------


def test_start_is_disabled_without_interval(graphql_helper, make_reporter, options):
    """``DEPLOYMENT_RECONCILIATION_INTERVAL=0`` disables the reconciliation."""
    reporter = make_reporter(
        graphql_helper, replace(options, reconciliation_interval=0)
    )
    reconciler = make_reconciler(reporter, FakeAdapter())
    assert reconciler.interval_seconds == 0
    assert reconciler.start() is False


def test_start_is_disabled_when_reporting_is_disabled(
    graphql_helper, make_reporter, options
):
    """A disabled write-back never starts the reconciliation."""
    reporter = make_reporter(graphql_helper, replace(options, reporting_enabled=False))
    assert make_reconciler(reporter, FakeAdapter()).start() is False


def test_periodic_reconciliation_runs_until_stopped(
    graphql_helper, make_reporter, list_nodes
):
    """The reconciliation runs in a daemon thread until stopped."""
    list_nodes()
    adapter = FakeAdapter()
    reconciler = make_reconciler(make_reporter(graphql_helper), adapter)

    assert reconciler.interval_seconds == 3600
    assert reconciler.start() is True
    assert reconciler.start() is True
    assert adapter.listed.wait(5)

    reconciler.stop(timeout=5)
    assert not reconciler._thread.is_alive()


def test_stop_during_the_initial_delay(graphql_helper, make_reporter):
    """Stopping before the first run exits without reconciling."""
    adapter = FakeAdapter()
    reconciler = make_reconciler(
        make_reporter(graphql_helper), adapter, initial_delay=60
    )
    reconciler.start()
    reconciler.stop(timeout=5)
    assert not reconciler._thread.is_alive()
    assert not adapter.listed.is_set()


def test_stop_without_start(graphql_helper, make_reporter):
    """Stopping a reconciler that never started is harmless."""
    make_reconciler(make_reporter(graphql_helper), FakeAdapter()).stop()


# --- absence confirmed by a direct lookup ---------------------------------------------


class ConfirmingAdapter(FakeAdapter):
    """Vendor whose listing may miss items: absences are looked up one by one."""

    confirms_absence = True

    def __init__(self, present=(), lookup_error=None, **kwargs):
        super().__init__(**kwargs)
        self.present = set(present)
        self.lookup_error = lookup_error
        self.looked_up = []

    def confirm_absent(self, deployment):
        self.looked_up.append(deployment.indicator_id)
        if self.lookup_error:
            raise self.lookup_error
        return deployment.indicator_id not in self.present


def test_an_absence_is_only_reported_once_the_adapter_confirms_it(
    graphql_helper, make_reporter, list_nodes, node_factory, reported
):
    """A live or withdrawn deployment missing from the listing but found by the lookup
    is left as it is; a confirmed absence is reported removed."""
    list_nodes(
        node_factory(indicator_id="gone", status="active"),
        node_factory(indicator_id="missed", status="active"),
        node_factory(indicator_id="withdrawn", status="active", revoked=True),
        node_factory(indicator_id="pending", status="pending", external_id="ext-p"),
    )
    adapter = ConfirmingAdapter(present={"missed", "withdrawn"})

    summary = make_reconciler(make_reporter(graphql_helper), adapter).run_once()

    assert sorted(adapter.looked_up) == ["gone", "missed", "withdrawn"]
    assert set(reported()) == {"gone", "pending"}
    assert reported()["gone"]["status"] == "removed"
    assert summary.marked_removed == 1
    assert summary.absence_unconfirmed == 2
    assert summary.as_log_meta()["absence_unconfirmed"] == 2


def test_absence_lookups_are_bounded_per_run(
    graphql_helper, make_reporter, list_nodes, node_factory, reported
):
    """Beyond the lookup budget of a run, absent deployments wait for the next run."""
    list_nodes(
        node_factory(indicator_id="first", status="active"),
        node_factory(indicator_id="second", status="deployed"),
    )
    adapter = ConfirmingAdapter()
    reconciler = make_reconciler(
        make_reporter(graphql_helper), adapter, max_absence_checks=1
    )

    summary = reconciler.run_once()

    assert len(adapter.looked_up) == 1
    assert len(reported()) == 1
    assert summary.marked_removed == 1
    assert summary.absence_unconfirmed == 1
    # The budget is per run: the next run looks a deployment up again
    reconciler.run_once()
    assert len(adapter.looked_up) == 2


def test_a_failed_absence_lookup_leaves_the_deployment_to_the_next_run(
    graphql_helper, make_reporter, list_nodes, node_factory, reported
):
    list_nodes(node_factory(indicator_id="unknown", status="active"))
    adapter = ConfirmingAdapter(lookup_error=ConnectionError("vendor down"))

    summary = make_reconciler(make_reporter(graphql_helper), adapter).run_once()

    assert reported() == {}
    assert summary.absence_unconfirmed == 1
    graphql_helper.connector_logger.warning.assert_called_once()


def test_adapters_trust_their_listing_by_default():
    """The default adapter confirms every absence without any lookup."""
    adapter = ReadOnlyAdapter()
    assert adapter.confirms_absence is False
    assert adapter.confirm_absent(MagicMock()) is True
