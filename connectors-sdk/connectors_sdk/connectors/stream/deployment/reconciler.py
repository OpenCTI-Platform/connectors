"""Reconciliation of deployment statuses with the security platform.

A stream connector able to read indicators back from its vendor implements a
``DeploymentVendorAdapter``; the ``DeploymentReconciler`` periodically compares the
vendor content with the ``deployed-on`` relationships of the platform in OpenCTI:

1. List the vendor indicators (bounded, paginated by the adapter).
2. List the deployments of the platform (``pending``, ``deployed``, ``active``,
   ``failed`` and ``expired``).
3. Present on the vendor -> report ``active`` (with the vendor id); only partly
   present (``DeploymentVendorAdapter.is_complete``) -> push again, unless ``failed``.
4. Absent and ``deployed`` / ``active`` -> report ``removed``.
5. ``pending`` (analyst retry) and absent -> push again, report the outcome.
6. Withdrawal requested (relationship revoked), indicator revoked or expired, and
   present -> remove from the vendor, report ``removed`` (absent -> ``removed``).
7. Vendor indicators carrying an OpenCTI id with no deployment -> report
   ``active`` (backfill of indicators pushed before the write-back existed).

All reports of a run are sent with ``indicatorReportDeployments`` (batch). When the
adapter can read detections, hits observed since the previous run are reported.
"""

import threading
import uuid
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from connectors_sdk.connectors.stream.deployment.models import (
    LIVE_STATUSES,
    RECONCILED_STATUSES,
    DeploymentReport,
    DeploymentStatus,
    HitCollection,
    IndicatorDeployment,
    ReconciliationSummary,
    VendorHit,
    VendorIndicator,
)
from connectors_sdk.connectors.stream.deployment.reporter import (
    REPORT_SENT,
    REPORT_UNSENT,
    DeploymentListingError,
    DeploymentReporter,
)
from connectors_sdk.connectors.stream.deployment.utils import (
    format_datetime,
    normalize_value,
    parse_datetime,
    to_stream_indicator,
)

LISTED_STATUSES = (*RECONCILED_STATUSES, DeploymentStatus.EXPIRED)
"""Statuses of the deployments listed by a reconciliation.

``expired`` deployments are listed too, so that indicators still present on the
vendor after their expiry are withdrawn and their removal confirmed.
"""

DEFAULT_MAX_VENDOR_INDICATORS = 1_000_000
"""Default read-back limit of a reconciliation run."""

DEFAULT_MAX_ABSENCE_CHECKS = 100
"""Default number of ``confirm_absent`` lookups of a reconciliation run."""

MAX_HELD_HITS = 100_000
"""Maximum detections held while an instant capped by the vendor read is read over several runs."""

CAPPED_INSTANT_STEP = timedelta(seconds=1)
"""Step past an instant capped by the vendor read when the adapter cannot continue reading it."""

MAX_PENDING_HITS_AGE = timedelta(hours=24)
"""How long a hit report that never reached OpenCTI is sent again with the following runs."""

HITS_CHECKPOINT_STATE_KEY = "deployment_hits_since"
"""Key of the connector state holding where the next hit read starts, kept across restarts."""

MAX_HITS_RECOVERY = timedelta(days=7)
"""How far back the first hit read after a start goes, however long the connector was stopped."""


class _ConnectorStateGuard:
    """Keep the keys the SDK writes in the connector state against the other writers.

    pycti keeps the connector state as one serialized document. Its stream listener
    rewrites it after each event from its own thread (read, change ``start_from``,
    write), without a lock. The guard wraps the ``set_state`` of the helper so that
    every write takes one lock: a key is written from the state read under that lock
    (``start_from`` is never rolled back), and a write made from a state read before
    the key changed gets the key back (the key is never lost). A state reset, written
    by the ping of the platform with the original ``set_state``, is never undone: a
    kept key the current state no longer holds is forgotten.
    """

    def __init__(self, helper: Any) -> None:
        self._helper = helper
        self._lock = threading.RLock()
        self._write = helper.set_state
        self._kept: dict[str, Any] = {}
        helper.set_state = self._guarded_write

    @classmethod
    def of(cls, helper: Any) -> "_ConnectorStateGuard":
        """Return the guard of a helper, installed on its first use."""
        guard = getattr(helper, "_deployment_state_guard", None)
        if not isinstance(guard, cls):
            guard = cls(helper)
            helper._deployment_state_guard = guard
        return guard

    def _current(self) -> dict[str, Any] | None:
        state = self._helper.get_state()
        return state if isinstance(state, dict) else None

    def _guarded_write(self, state: Any) -> None:
        with self._lock:
            if isinstance(state, dict) and self._kept:
                try:
                    current = self._current()
                except Exception:  # noqa: BLE001 - the write of the caller goes on
                    current = None
                restored: dict[str, Any] = {}
                for key, value in list(self._kept.items()):
                    if current is None or current.get(key) != value:
                        del self._kept[key]
                    elif state.get(key) != value:
                        restored[key] = value
                if restored:
                    state = {**state, **restored}
            self._write(state)

    def update(self, key: str, value: Any) -> None:
        """Write one key into the latest state, unless the state was reset.

        Args:
            key: The state key.
            value: Its new value.
        """
        with self._lock:
            state = self._current()
            if state is None:
                # pycti reads a state set to None as a reset and starts the stream over.
                return
            self._kept[key] = value
            if state.get(key) != value:
                state[key] = value
                self._write(state)


@dataclass(slots=True)
class _PendingHits:
    """A hit report of one indicator not delivered to OpenCTI yet.

    ``failing_since`` is ``None`` until the report is sent: only a report never
    sent can take newer hits, one that was sent may have been recorded.
    ``report_id`` is the same at every send of the report, so OpenCTI tells a report
    sent again from a distinct one ending at the same instant.
    """

    count: int
    first_hit: datetime
    last_hit: datetime
    failing_since: datetime | None
    report_id: str = field(default_factory=lambda: str(uuid.uuid4()))


_LOG_PREFIX = "[DEPLOYMENT]"


class DeploymentVendorAdapter(ABC):
    """Vendor operations needed by the reconciliation of a stream connector."""

    confirms_absence: bool = False
    """Whether ``confirm_absent`` looks indicators up on the vendor.

    An adapter whose listing cannot guarantee completeness (offset pages of a
    collection without a documented order) sets it: a live deployment missing from
    the listing is then only reported ``removed`` once a direct lookup confirms it.
    """

    @abstractmethod
    def list_vendor_indicators(self) -> Iterable[VendorIndicator]:
        """Read the indicators pushed by the connector back from the vendor.

        The adapter paginates the vendor API and only returns the indicators the
        connector manages (same source, list or tag). Objects the vendor retains
        but no longer enforces (expired, revoked, deactivated) are returned with
        ``active=False``, so that a withdrawal still removes them.

        Returns:
            The vendor indicators.

        Raises:
            Exception: On any vendor error. A partial listing must never be
                returned: absent indicators are reported ``removed``.
        """

    @abstractmethod
    def remove_vendor_indicator(
        self, vendor_indicator: VendorIndicator, deployment: IndicatorDeployment
    ) -> None:
        """Remove an indicator from the vendor (withdrawal, revocation or expiry).

        Args:
            vendor_indicator: The vendor indicator, as listed.
            deployment: The deployment requesting the removal.

        Raises:
            Exception: When the vendor refused the removal.
        """

    @abstractmethod
    def push_indicator(self, stix_indicator: dict[str, Any]) -> str | None:
        """Push an indicator to the vendor again (analyst retry).

        Args:
            stix_indicator: The indicator, in the stream event shape (OpenCTI
                extension included).

        Returns:
            The id of the indicator on the vendor side, if known.

        Raises:
            Exception: When the vendor rejected the push (reported ``failed``).
        """

    def is_complete(
        self,
        deployment: IndicatorDeployment,
        vendor_matches: Sequence[VendorIndicator],
    ) -> bool:
        """Tell whether the vendor items of a deployment cover the whole indicator.

        Adapters pushing one vendor item per observable override it, so that an
        indicator only partly on the vendor is pushed again instead of being
        confirmed ``active``. By default, any vendor item confirms the deployment.

        Args:
            deployment: The deployment.
            vendor_matches: Its vendor items (at least one).

        Returns:
            ``False`` when an observable of the indicator has no vendor item.
        """
        return True

    def confirm_absent(self, deployment: IndicatorDeployment) -> bool:
        """Confirm with a direct vendor lookup that an indicator is not on the vendor.

        Only called when ``confirms_absence`` is set, for the deployments missing from
        the listing that the run would report ``removed``, within the lookup budget of
        the run (``DeploymentReconciler(max_absence_checks=...)``).

        Args:
            deployment: The deployment missing from the listing.

        Returns:
            ``False`` when the vendor still holds the indicator: the run leaves the
            deployment as it is.

        Raises:
            Exception: On any vendor error (the deployment is left to the next run).
        """
        return True

    def collect_hits(
        self,
        deployments: Sequence[IndicatorDeployment],
        since: datetime,
        *,
        resume: Any = None,
    ) -> Iterable[VendorHit] | HitCollection:
        """Read the detections of deployed indicators observed since a date.

        Adapters able to read detections (alerts, incidents, matches) override it;
        the default implementation reports no hit.

        Args:
            deployments: The live deployments (``deployed`` or ``active``).
            since: Only return detections that happened after this date.
            resume: The ``HitCollection.resume`` returned by the previous call, only
                passed to adapters that return one.

        Returns:
            The hits, matched to deployments by indicator id, vendor id or value. A
            capped read returns a ``HitCollection`` telling how far it is complete.
            An adapter returning ``HitCollection.resume`` also accepts the keyword
            argument ``resume``: it is called again with it to continue a read capped
            at its very start.
        """
        return ()


class _Index:
    """Lookup of objects by OpenCTI id, vendor id and observable value."""

    def __init__(self) -> None:
        self.by_id: dict[str, list[Any]] = {}
        self.by_external_id: dict[str, list[Any]] = {}
        self.by_value: dict[str, list[Any]] = {}

    @staticmethod
    def _add(mapping: dict[str, list[Any]], key: str | None, item: Any) -> None:
        if key is not None:
            mapping.setdefault(key, []).append(item)

    @classmethod
    def of_vendor_indicators(
        cls, vendor_indicators: Iterable[VendorIndicator]
    ) -> "_Index":
        index = cls()
        for vendor_indicator in vendor_indicators:
            index._add(
                index.by_id,
                normalize_value(vendor_indicator.indicator_id),
                vendor_indicator,
            )
            index._add(
                index.by_external_id,
                normalize_value(vendor_indicator.external_id),
                vendor_indicator,
            )
            if vendor_indicator.indicator_id is None:
                # Value matching is a fallback for vendors that do not keep the id.
                index._add(
                    index.by_value,
                    normalize_value(vendor_indicator.value),
                    vendor_indicator,
                )
        return index

    @classmethod
    def of_deployments(cls, deployments: Iterable[IndicatorDeployment]) -> "_Index":
        index = cls()
        for deployment in deployments:
            for identifier in deployment.identifiers:
                index._add(index.by_id, identifier, deployment)
            index._add(
                index.by_external_id,
                normalize_value(deployment.external_id),
                deployment,
            )
            for value in deployment.values:
                index._add(index.by_value, value, deployment)
        return index

    def find_all(
        self, identifiers: Iterable[str], external_id: Any, values: Iterable[str]
    ) -> list[Any]:
        """Return every object matching the first criterion that matches.

        All the objects sharing an OpenCTI id or a vendor id are returned, since a
        vendor can hold several items for one indicator (one per observable, or
        duplicates). Value matching only returns the first object: a value can be
        shared by unrelated indicators.
        """
        matches: dict[int, Any] = {}
        for identifier in sorted(identifiers):
            for item in self.by_id.get(identifier, ()):
                matches.setdefault(id(item), item)
        if matches:
            return list(matches.values())
        normalized_external_id = normalize_value(external_id)
        if normalized_external_id and normalized_external_id in self.by_external_id:
            return list(self.by_external_id[normalized_external_id])
        for value in values:
            if value in self.by_value:
                return self.by_value[value][:1]
        return []


class DeploymentReconciler:
    """Reconcile deployment statuses with the security platform, periodically.

    Example:
        >>> reconciler = DeploymentReconciler(reporter, MyVendorAdapter(client))
        >>> reconciler.start()  # every DEPLOYMENT_RECONCILIATION_INTERVAL minutes
    """

    def __init__(
        self,
        reporter: DeploymentReporter,
        adapter: DeploymentVendorAdapter,
        *,
        max_vendor_indicators: int = DEFAULT_MAX_VENDOR_INDICATORS,
        max_absence_checks: int = DEFAULT_MAX_ABSENCE_CHECKS,
        hits_lookback: timedelta | None = None,
        initial_delay: float = 60.0,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Initialize the reconciler.

        Args:
            reporter: The deployment reporter of the connector.
            adapter: The vendor adapter.
            max_vendor_indicators: Read-back limit of a run. When reached, absence
                based decisions (``removed``, re-push) are skipped for that run.
            max_absence_checks: ``confirm_absent`` lookups of a run, for adapters
                that confirm absences; the next absent deployments wait for the
                next run.
            hits_lookback: How far back detections are read on each run (overlap
                with the previous run included). Defaults to the reconciliation
                interval, at least one hour.
            initial_delay: Seconds between ``start()`` and the first run.
            clock: Current time provider (injectable for tests).
        """
        self._reporter = reporter
        self._adapter = adapter
        self._logger = reporter.logger
        self._max_vendor_indicators = max_vendor_indicators
        self._max_absence_checks = max_absence_checks
        self._absence_checks = 0
        interval = timedelta(minutes=reporter.options.reconciliation_interval)
        self._hits_lookback = hits_lookback or max(interval, timedelta(hours=1))
        self._initial_delay = initial_delay
        self._clock = clock or (lambda: datetime.now(UTC))
        self._hits_since: datetime | None = None
        self._hits_resume: Any = None
        self._held_hits: list[VendorHit] = []
        self._pending_hits: dict[str, list[_PendingHits]] = {}
        self._run_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def interval_seconds(self) -> float:
        """Return the interval between two runs, in seconds (0 when disabled)."""
        return float(self._reporter.options.reconciliation_interval * 60)

    def start(self) -> bool:
        """Start the periodic reconciliation in a daemon thread.

        Returns:
            ``True`` when the reconciliation runs (disabled when the write-back is
            disabled or ``DEPLOYMENT_RECONCILIATION_INTERVAL`` is 0).
        """
        if not self._reporter.enabled or self.interval_seconds <= 0:
            self._logger.info(
                f"{_LOG_PREFIX} Deployment reconciliation disabled by configuration."
            )
            return False
        if self._thread is not None and self._thread.is_alive():
            return True
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_periodically,
            name="deployment-reconciliation",
            daemon=True,
        )
        self._thread.start()
        self._logger.info(
            f"{_LOG_PREFIX} Deployment reconciliation scheduled.",
            meta={"interval_minutes": self._reporter.options.reconciliation_interval},
        )
        return True

    def stop(self, timeout: float | None = None) -> None:
        """Stop the periodic reconciliation.

        Args:
            timeout: Seconds to wait for a running reconciliation to finish.
        """
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout)

    def run_once(self) -> ReconciliationSummary:
        """Run one reconciliation (and hit collection) now. Never raises.

        Returns:
            The counters of the run.
        """
        if not self._run_lock.acquire(blocking=False):
            return ReconciliationSummary(
                skipped=True, reason="A reconciliation is already running"
            )
        try:
            summary = self._reconcile()
        except Exception as err:
            self._logger.warning(
                f"{_LOG_PREFIX} Deployment reconciliation failed.",
                meta={"error": str(err)},
            )
            summary = ReconciliationSummary(skipped=True, reason=str(err))
        finally:
            self._run_lock.release()
        log = self._logger.debug if summary.skipped else self._logger.info
        log(
            f"{_LOG_PREFIX} Deployment reconciliation completed.",
            meta=summary.as_log_meta(),
        )
        return summary

    def _run_periodically(self) -> None:
        """Run reconciliations until ``stop()`` is called."""
        if self._stop_event.wait(self._initial_delay):
            return
        while True:
            self.run_once()
            if self._stop_event.wait(self.interval_seconds):
                return

    def _reconcile(self) -> ReconciliationSummary:
        """Run the reconciliation algorithm.

        Returns:
            The counters of the run.
        """
        reporter = self._reporter
        if not reporter.enabled:
            return ReconciliationSummary(skipped=True, reason="Write-back disabled")
        if not reporter.is_supported():
            return ReconciliationSummary(
                skipped=True, reason="Write-back not supported by the OpenCTI platform"
            )
        if reporter.security_platform_id is None:
            return ReconciliationSummary(
                skipped=True, reason="Security platform not resolved"
            )
        summary = ReconciliationSummary()
        self._absence_checks = 0
        # From the vendor snapshot to its reports, the stream outcomes are held and sent
        # right after: a removal pushed meanwhile always lands after a stale `active`.
        with reporter.holding_queued_reports() as delivered:
            if not delivered:
                self._logger.warning(
                    f"{_LOG_PREFIX} Stream reports not delivered yet, reconciliation "
                    "skipped (sent again later, they would overwrite its reports)."
                )
                return ReconciliationSummary(
                    skipped=True, reason="Queued stream reports not delivered"
                )
            now = self._clock()
            try:
                vendor_indicators = self._read_vendor_indicators(summary)
            except Exception as err:
                self._logger.warning(
                    f"{_LOG_PREFIX} Cannot read the indicators back from the vendor, "
                    "reconciliation skipped.",
                    meta={"error": str(err)},
                )
                return ReconciliationSummary(
                    skipped=True, reason=f"Vendor read-back failed: {err}"
                )
            try:
                deployments = list(reporter.list_indicator_deployments(LISTED_STATUSES))
            except DeploymentListingError as err:
                self._logger.warning(
                    f"{_LOG_PREFIX} Cannot list the deployments, reconciliation skipped.",
                    meta={"error": str(err)},
                )
                return ReconciliationSummary(skipped=True, reason=str(err))
            summary.deployments = len(deployments)

            vendor_index = _Index.of_vendor_indicators(vendor_indicators)
            deployment_matches = [
                (
                    deployment,
                    [
                        vendor
                        for vendor in vendor_index.find_all(
                            deployment.identifiers,
                            deployment.external_id,
                            deployment.values,
                        )
                        # A retained inactive object is only removed, never live.
                        if vendor.active or self._must_remove(deployment, now)
                    ],
                )
                for deployment in deployments
            ]
            # Vendors de-duplicating by value hold one item for several indicators:
            # an item still used by a deployment that stays is never removed.
            kept = {
                id(vendor)
                for deployment, vendor_matches in deployment_matches
                if not self._must_remove(deployment, now)
                for vendor in vendor_matches
            }
            removed: set[int] = set()
            matched: set[int] = set()
            reports: list[DeploymentReport] = []
            for deployment, vendor_matches in deployment_matches:
                matched.update(id(vendor) for vendor in vendor_matches)
                report = self._reconcile_deployment(
                    deployment, vendor_matches, now, summary, kept, removed
                )
                if report is not None:
                    reports.append(report)
            reports.extend(
                self._discover(vendor_indicators, deployments, matched, now, summary)
            )

            result = reporter.report_indicator_deployments(reports)
            summary.report_errors = len(result.errors)

        if reporter.hits_enabled:
            # A deployment this run reports as no longer live is not credited with
            # the hits of a value it shares with a live one.
            withdrawn = {
                report.indicator_id
                for report in reports
                if report.status not in LIVE_STATUSES
            }
            live = [
                deployment
                for deployment in deployments
                if deployment.is_live
                and not deployment.requires_removal(now)
                and deployment.indicator_id not in withdrawn
            ]
            summary.hits_reported = self._report_hits(live, now)
            self._save_hits_checkpoint()
        return summary

    def _read_vendor_indicators(
        self, summary: ReconciliationSummary
    ) -> list[VendorIndicator]:
        """Read the vendor indicators, up to the read-back limit.

        Args:
            summary: The run counters, updated.

        Returns:
            The vendor indicators.
        """
        vendor_indicators: list[VendorIndicator] = []
        for vendor_indicator in self._adapter.list_vendor_indicators():
            if len(vendor_indicators) >= self._max_vendor_indicators:
                summary.vendor_listing_truncated = True
                self._logger.warning(
                    f"{_LOG_PREFIX} Vendor read-back limit reached, absent indicators "
                    "are not reported removed during this run.",
                    meta={"limit": self._max_vendor_indicators},
                )
                break
            vendor_indicators.append(vendor_indicator)
        summary.vendor_indicators = len(vendor_indicators)
        return vendor_indicators

    @staticmethod
    def _must_remove(deployment: IndicatorDeployment, now: datetime) -> bool:
        """Tell whether a deployment must be withdrawn from the vendor.

        Args:
            deployment: The deployment.
            now: The start of the run.

        Returns:
            ``True`` when the indicator must be withdrawn or the deployment expired.
        """
        return (
            deployment.requires_removal(now)
            or deployment.status == DeploymentStatus.EXPIRED
        )

    def _reconcile_deployment(
        self,
        deployment: IndicatorDeployment,
        vendor_matches: Sequence[VendorIndicator],
        now: datetime,
        summary: ReconciliationSummary,
        kept: set[int],
        removed: set[int],
    ) -> DeploymentReport | None:
        """Decide the report of one deployment.

        Args:
            deployment: The deployment.
            vendor_matches: The vendor indicators of the deployment (several when
                the vendor holds one item per observable, or duplicates).
            now: The start of the run, taken before the vendor read-back.
            summary: The run counters, updated.
            kept: Python ids of the vendor indicators used by a deployment that stays.
            removed: Python ids of the vendor indicators removed by the run, updated.

        Returns:
            The report to send, if any.
        """
        must_remove = self._must_remove(deployment, now)
        if must_remove and vendor_matches:
            return self._withdraw(
                deployment, vendor_matches, now, summary, kept, removed
            )
        if not vendor_matches:
            if summary.vendor_listing_truncated:
                return None
            if deployment.last_sync_at is not None and deployment.last_sync_at >= now:
                # Pushed by the stream while the vendor was being read back.
                summary.deferred += 1
                return None
            if (must_remove or deployment.is_live) and not self._absence_confirmed(
                deployment, summary
            ):
                return None
        if must_remove:
            summary.marked_removed += 1
            return DeploymentReport(
                indicator_id=deployment.indicator_id,
                status=DeploymentStatus.REMOVED,
                external_id=deployment.external_id,
                synced_at=now,
                removed_at=now,
            )
        if vendor_matches:
            return self._confirm_present(deployment, vendor_matches, now, summary)
        if deployment.is_live:
            summary.marked_removed += 1
            return DeploymentReport(
                indicator_id=deployment.indicator_id,
                status=DeploymentStatus.REMOVED,
                external_id=deployment.external_id,
                synced_at=now,
                removed_at=now,
            )
        if deployment.status == DeploymentStatus.PENDING:
            return self._repush(deployment, now, summary)
        return None

    def _absence_confirmed(
        self, deployment: IndicatorDeployment, summary: ReconciliationSummary
    ) -> bool:
        """Tell whether a deployment missing from the listing is absent from the vendor.

        Adapters that do not confirm absences trust their listing. Otherwise the
        adapter looks the indicator up, within the lookup budget of the run.

        Args:
            deployment: The deployment missing from the listing.
            summary: The run counters, updated.

        Returns:
            ``False`` when the vendor still holds the indicator, or when it could not
            be looked up this run: no absence decision is taken.
        """
        if not self._adapter.confirms_absence:
            return True
        if self._absence_checks >= self._max_absence_checks:
            summary.absence_unconfirmed += 1
            return False
        self._absence_checks += 1
        try:
            absent = self._adapter.confirm_absent(deployment)
        except Exception as err:
            self._logger.warning(
                f"{_LOG_PREFIX} Cannot confirm that an indicator left the vendor, "
                "left to the next run.",
                meta={"indicator_id": deployment.indicator_id, "error": str(err)},
            )
            summary.absence_unconfirmed += 1
            return False
        if not absent:
            self._logger.info(
                f"{_LOG_PREFIX} Indicator missing from the listing found on the vendor, "
                "left as it is.",
                meta={"indicator_id": deployment.indicator_id},
            )
            summary.absence_unconfirmed += 1
        return absent

    def _confirm_present(
        self,
        deployment: IndicatorDeployment,
        vendor_matches: Sequence[VendorIndicator],
        now: datetime,
        summary: ReconciliationSummary,
    ) -> DeploymentReport | None:
        """Confirm a deployment found on the vendor, or push it again when partly there.

        Args:
            deployment: The deployment, not to be withdrawn.
            vendor_matches: Its vendor items (at least one).
            now: The start of the run.
            summary: The run counters, updated.

        Returns:
            An ``active`` report, the report of the new push, or ``None`` for a
            ``failed`` deployment only partly on the vendor.
        """
        if not self._adapter.is_complete(deployment, vendor_matches):
            summary.incomplete += 1
            if deployment.status == DeploymentStatus.FAILED:
                # Stays failed until an analyst requests a new push.
                return None
            return self._repush(deployment, now, summary)
        summary.confirmed_active += 1
        return DeploymentReport(
            indicator_id=deployment.indicator_id,
            status=DeploymentStatus.ACTIVE,
            external_id=vendor_matches[0].external_id or deployment.external_id,
            synced_at=now,
        )

    def _withdraw(
        self,
        deployment: IndicatorDeployment,
        vendor_matches: Sequence[VendorIndicator],
        now: datetime,
        summary: ReconciliationSummary,
        kept: set[int],
        removed: set[int],
    ) -> DeploymentReport | None:
        """Remove every vendor item of an indicator from the vendor.

        An item another deployment still uses (one vendor item for several
        indicators of the same value) stays on the vendor: the indicator is
        withdrawn without it. An item already removed by the run is not removed
        again.

        Args:
            deployment: The deployment to withdraw.
            vendor_matches: The vendor indicators of the deployment (at least one).
            now: The reference time.
            summary: The run counters, updated.
            kept: Python ids of the vendor indicators used by a deployment that stays.
            removed: Python ids of the vendor indicators removed by the run, updated.

        Returns:
            A ``removed`` report once every item is removed, or ``None`` when one
            removal failed (the next run retries the items still listed; OpenCTI
            flags the deployment ``expired`` if no removal is confirmed in time).
        """
        for vendor_indicator in vendor_matches:
            if id(vendor_indicator) in removed:
                continue
            if id(vendor_indicator) in kept:
                self._logger.info(
                    f"{_LOG_PREFIX} Vendor indicator kept, another deployment still "
                    "uses it.",
                    meta={
                        "indicator_id": deployment.indicator_id,
                        "external_id": vendor_indicator.external_id,
                    },
                )
                continue
            try:
                self._adapter.remove_vendor_indicator(vendor_indicator, deployment)
            except Exception as err:
                summary.withdrawal_failed += 1
                self._logger.warning(
                    f"{_LOG_PREFIX} Cannot remove an indicator from the vendor.",
                    meta={
                        "indicator_id": deployment.indicator_id,
                        "external_id": vendor_indicator.external_id,
                        "error": str(err),
                    },
                )
                return None
            removed.add(id(vendor_indicator))
        summary.withdrawn += 1
        return DeploymentReport(
            indicator_id=deployment.indicator_id,
            status=DeploymentStatus.REMOVED,
            external_id=vendor_matches[0].external_id or deployment.external_id,
            synced_at=now,
            removed_at=now,
        )

    def _repush(
        self,
        deployment: IndicatorDeployment,
        now: datetime,
        summary: ReconciliationSummary,
    ) -> DeploymentReport:
        """Push a ``pending`` indicator, or one only partly on the vendor, again.

        Args:
            deployment: The pending or incomplete deployment.
            now: The reference time.
            summary: The run counters, updated.

        Returns:
            A ``deployed`` or ``failed`` report.
        """
        stix_indicator = self._fetch_indicator(deployment)
        if stix_indicator is None:
            summary.repush_failed += 1
            return DeploymentReport(
                indicator_id=deployment.indicator_id,
                status=DeploymentStatus.FAILED,
                error_message="The indicator cannot be read from OpenCTI for a new push",
                synced_at=now,
            )
        try:
            external_id = self._adapter.push_indicator(stix_indicator)
        except Exception as err:
            summary.repush_failed += 1
            return DeploymentReport(
                indicator_id=deployment.indicator_id,
                status=DeploymentStatus.FAILED,
                external_id=deployment.external_id,
                error_message=str(err) or type(err).__name__,
                synced_at=now,
            )
        summary.repushed += 1
        return DeploymentReport(
            indicator_id=deployment.indicator_id,
            status=DeploymentStatus.DEPLOYED,
            external_id=external_id or deployment.external_id,
            deployed_at=now,
            synced_at=now,
        )

    def _fetch_indicator(
        self, deployment: IndicatorDeployment
    ) -> dict[str, Any] | None:
        """Read an indicator from OpenCTI in the stream event shape.

        Args:
            deployment: The deployment of the indicator.

        Returns:
            The indicator, or ``None`` when it cannot be read.
        """
        try:
            exported = self._reporter.helper.api.stix2.get_stix_bundle_or_object_from_entity_id(
                entity_type="Indicator",
                entity_id=deployment.indicator_id,
                only_entity=True,
            )
        except Exception as err:
            self._logger.warning(
                f"{_LOG_PREFIX} Cannot read an indicator to push it again.",
                meta={"indicator_id": deployment.indicator_id, "error": str(err)},
            )
            return None
        if not isinstance(exported, Mapping) or exported.get("type") != "indicator":
            return None
        return to_stream_indicator(exported, deployment.indicator_id)

    def _discover(
        self,
        vendor_indicators: Sequence[VendorIndicator],
        deployments: Sequence[IndicatorDeployment],
        matched: set[int],
        now: datetime,
        summary: ReconciliationSummary,
    ) -> list[DeploymentReport]:
        """Report active vendor indicators carrying an OpenCTI id but no deployment.

        Args:
            vendor_indicators: The vendor indicators.
            deployments: The listed deployments.
            matched: Python ids of the vendor indicators matched to a deployment.
            now: The reference time.
            summary: The run counters, updated.

        Returns:
            ``active`` reports, which create the missing relationships.
        """
        known: set[str] = set()
        for deployment in deployments:
            known.update(deployment.identifiers)
        reports: list[DeploymentReport] = []
        reported: set[str] = set()
        for vendor_indicator in vendor_indicators:
            identifier = normalize_value(vendor_indicator.indicator_id)
            if (
                not vendor_indicator.active
                or vendor_indicator.indicator_id is None
                or identifier is None
                or id(vendor_indicator) in matched
                or identifier in known
                or identifier in reported
            ):
                continue
            reported.add(identifier)
            summary.discovered += 1
            reports.append(
                DeploymentReport(
                    indicator_id=vendor_indicator.indicator_id,
                    status=DeploymentStatus.ACTIVE,
                    external_id=vendor_indicator.external_id,
                    synced_at=now,
                )
            )
        return reports

    def _read_hits(
        self,
        deployments: list[IndicatorDeployment],
        since: datetime,
        next_since: datetime,
    ) -> tuple[list[VendorHit], datetime] | None:
        """Read the detections from the vendor and decide where the next run starts.

        Args:
            deployments: The live deployments.
            since: Start of the read.
            next_since: Start of the next read when this one is complete.

        Returns:
            The hits to report and the start of the next read, or ``None`` when the
            vendor could not be read.
        """
        resume = self._hits_resume
        try:
            if resume is None:
                collected = self._adapter.collect_hits(deployments, since)
            else:
                collected = self._adapter.collect_hits(
                    deployments, since, resume=resume
                )
            if not isinstance(collected, HitCollection):
                return self._release_held_hits(list(collected)), next_since
            hits = list(collected.hits)
        except Exception as err:
            self._logger.warning(
                f"{_LOG_PREFIX} Cannot read the detections from the vendor.",
                meta={"error": str(err)},
            )
            # The continuation may be stale: the capped instant is read again from its start.
            self._hits_resume = None
            self._held_hits = []
            return None
        complete_until = collected.complete_until
        if complete_until is None:
            return self._release_held_hits(hits), next_since
        if complete_until <= since:
            return self._continue_capped_instant(since, hits, collected.resume)
        self._logger.warning(
            f"{_LOG_PREFIX} Detection read capped by the vendor, the next run "
            "resumes where this one stopped.",
            meta={
                "since": since.isoformat(),
                "complete_until": complete_until.isoformat(),
            },
        )
        return [
            hit
            for hit in self._release_held_hits(hits)
            if (timestamp := parse_datetime(hit.timestamp)) is not None
            and timestamp < complete_until
        ], complete_until

    def _continue_capped_instant(
        self, since: datetime, hits: list[VendorHit], resume: Any
    ) -> tuple[list[VendorHit], datetime]:
        """Handle a read capped at its very start: more detections share ``since`` than the read limit.

        With a continuation that progresses, the hits are held (reporting them would
        move the ``last_hit_at`` watermark to that instant and hide the detections
        still to read there) and the next run reads the same instant further. Without
        one, the instant cannot be read further: the next run starts just after it
        and the hits of that instant are a lower bound.

        Args:
            since: Start of the read, the capped instant.
            hits: The detections read by this run.
            resume: The continuation returned by the adapter.

        Returns:
            The hits to report and the start of the next read.
        """
        progressed = resume is not None and resume != self._hits_resume
        if progressed and len(self._held_hits) + len(hits) <= MAX_HELD_HITS:
            self._logger.info(
                f"{_LOG_PREFIX} Detection read capped at the start of its window, the "
                "next run continues reading the same instant.",
                meta={
                    "since": since.isoformat(),
                    "held": len(self._held_hits) + len(hits),
                },
            )
            self._hits_resume = resume
            self._held_hits.extend(hits)
            return [], since
        self._logger.warning(
            f"{_LOG_PREFIX} Detection read capped at the start of its window and not "
            "continued, the detections of that instant are a lower bound.",
            meta={
                "since": since.isoformat(),
                "next_since": (since + CAPPED_INSTANT_STEP).isoformat(),
            },
        )
        return self._release_held_hits(hits), since + CAPPED_INSTANT_STEP

    def _release_held_hits(self, hits: list[VendorHit]) -> list[VendorHit]:
        """End the reading of a capped instant: return its held hits with the new ones.

        Args:
            hits: The detections read by this run.

        Returns:
            The held detections followed by ``hits``.
        """
        held = self._held_hits
        self._hits_resume = None
        self._held_hits = []
        return held + hits

    def _report_hits(
        self, deployments: list[IndicatorDeployment], now: datetime
    ) -> int:
        """Collect and report the hits of live deployments.

        Args:
            deployments: The live deployments.
            now: The reference time.

        Returns:
            The number of indicators with new hits reported.
        """
        next_since = now - self._hits_lookback
        if not deployments:
            self._hits_since = next_since
            self._release_held_hits([])
            return self._send_hit_reports({}, now)
        since = (
            self._hits_since
            if self._hits_since is not None
            else self._restored_hits_since(now, next_since)
        )
        collected = self._read_hits(deployments, since, next_since)
        if collected is None:
            return self._send_hit_reports({}, now)
        hits, next_since = collected
        index = _Index.of_deployments(deployments)
        aggregated: dict[str, list[Any]] = {}
        for hit in hits:
            timestamp = parse_datetime(hit.timestamp)
            if timestamp is None or hit.count < 1:
                continue
            identifier = normalize_value(hit.indicator_id)
            value = normalize_value(hit.value)
            matched = index.find_all(
                [identifier] if identifier else [], hit.external_id, []
            )
            if not matched and value:
                # A matched value is a hit of every indicator carrying it.
                matched = index.by_value.get(value, [])
            for deployment in matched:
                watermark = self._hit_watermark(deployment)
                if watermark is not None and timestamp <= watermark:
                    continue
                entry = aggregated.setdefault(
                    deployment.indicator_id, [0, timestamp, timestamp]
                )
                entry[0] += hit.count
                entry[1] = min(entry[1], timestamp)
                entry[2] = max(entry[2], timestamp)
        self._hits_since = next_since
        return self._send_hit_reports(aggregated, now)

    def _hits_checkpoint(self) -> datetime | None:
        """Return where a hit read loses no detection: the start of the next read,
        or the first hit of a report not delivered yet when it is older.

        Returns:
            The checkpoint, or ``None`` before the first hit read.
        """
        checkpoint = self._hits_since
        for queue in self._pending_hits.values():
            for pending in queue:
                if checkpoint is None or pending.first_hit < checkpoint:
                    checkpoint = pending.first_hit
        return checkpoint

    def _connector_state(self) -> dict[str, Any] | None:
        """Return the state of the connector, or ``None`` when it has none.

        A ``None`` state is never replaced: pycti reads it as a state reset from the
        platform and starts the stream over.
        """
        get_state = getattr(self._reporter.helper, "get_state", None)
        if not callable(get_state):
            return None
        state = get_state()
        return state if isinstance(state, dict) else None

    def _restored_hits_since(self, now: datetime, next_since: datetime) -> datetime:
        """Return where the first hit read after a start begins.

        The read resumes at the checkpoint saved before the stop, so the detections
        of a stop longer than the lookback are read too, within ``MAX_HITS_RECOVERY``.

        Args:
            now: The reference time.
            next_since: The start of a read without checkpoint (the lookback).

        Returns:
            The earlier of the saved checkpoint and ``next_since``, never before
            ``now - MAX_HITS_RECOVERY``.
        """
        try:
            state = self._connector_state()
        except Exception as err:  # noqa: BLE001 - a start never fails on the state
            self._logger.warning(
                f"{_LOG_PREFIX} The hit checkpoint could not be read, the hits are "
                "read from the lookback window.",
                meta={"error": str(err)},
            )
            return next_since
        checkpoint = parse_datetime(
            state.get(HITS_CHECKPOINT_STATE_KEY) if state else None
        )
        if checkpoint is None or checkpoint >= next_since:
            return next_since
        return max(checkpoint, now - MAX_HITS_RECOVERY)

    def _save_hits_checkpoint(self) -> None:
        """Keep the hit checkpoint in the state of the connector, for the next start.

        The stream listener of pycti writes its position in the same state from its
        own thread: both writers go through ``_ConnectorStateGuard``, so neither the
        checkpoint nor the stream position is ever rolled back by the other one.
        """
        checkpoint = format_datetime(self._hits_checkpoint())
        helper = self._reporter.helper
        if (
            checkpoint is None
            or not callable(getattr(helper, "set_state", None))
            or not callable(getattr(helper, "get_state", None))
        ):
            return
        try:
            _ConnectorStateGuard.of(helper).update(
                HITS_CHECKPOINT_STATE_KEY, checkpoint
            )
        except Exception as err:  # noqa: BLE001 - the hits are reported anyway
            self._logger.warning(
                f"{_LOG_PREFIX} The hit checkpoint could not be saved, a restart reads "
                "the hits from the lookback window.",
                meta={"error": str(err)},
            )

    def _hit_watermark(self, deployment: IndicatorDeployment) -> datetime | None:
        """Return the time up to which the hits of a deployment are already counted.

        The hit reads overlap; a hit up to the last one OpenCTI recorded, or up to
        the last one of a report still waiting for delivery (OpenCTI has not moved
        its ``last_hit_at`` yet), is not counted again.

        Args:
            deployment: The deployment.

        Returns:
            The newest counted hit time, or ``None`` when no hit was counted yet.
        """
        watermark = deployment.last_hit_at
        for pending in self._pending_hits.get(deployment.indicator_id, ()):
            if watermark is None or pending.last_hit > watermark:
                watermark = pending.last_hit
        return watermark

    def _send_hit_reports(self, aggregated: dict[str, list[Any]], now: datetime) -> int:
        """Send the hit reports of a run after the ones not delivered by earlier runs.

        A report that was not delivered (outage, timeout, rate limit) may still have
        been recorded: OpenCTI ignores a report ending before the last hit it recorded,
        or ending at it with a report id it already counted. Such a report is sent
        again unchanged, with the same report id, for at most
        ``MAX_PENDING_HITS_AGE``, and the newer hits of an indicator wait behind it in
        one report never sent, so the hit window moves on without losing or counting
        twice a detection it already read. A report OpenCTI rejects (deleted or
        unreadable indicator) is dropped.

        Args:
            aggregated: Per indicator: count, first hit and last hit of this run.
            now: The reference time.

        Returns:
            The number of indicators with a report accepted.
        """
        queues = self._pending_hits
        self._pending_hits = {}
        for indicator_id, (count, first_hit, last_hit) in aggregated.items():
            queue = queues.setdefault(indicator_id, [])
            if queue and queue[-1].failing_since is None:
                tail = queue[-1]
                tail.count += count
                tail.first_hit = min(tail.first_hit, first_hit)
                tail.last_hit = max(tail.last_hit, last_hit)
            else:
                queue.append(_PendingHits(count, first_hit, last_hit, None))
        reported = 0
        dropped = 0
        for indicator_id, queue in queues.items():
            accepted = False
            while queue:
                report = queue[0]
                outcome = self._reporter.report_indicator_hits_outcome(
                    indicator_id,
                    report.count,
                    last_hit=report.last_hit,
                    first_hit=report.first_hit,
                    report_id=report.report_id,
                )
                if outcome == REPORT_UNSENT:
                    failing_since = report.failing_since or now
                    if now - failing_since <= MAX_PENDING_HITS_AGE:
                        report.failing_since = failing_since
                        self._pending_hits[indicator_id] = queue
                        break
                    dropped += 1
                elif outcome == REPORT_SENT:
                    accepted = True
                queue.pop(0)
            if accepted:
                reported += 1
        if self._pending_hits or dropped:
            self._logger.warning(
                f"{_LOG_PREFIX} Some hit reports were not delivered, they are sent "
                "again with the next run.",
                meta={"kept": len(self._pending_hits), "dropped": dropped},
            )
        return reported
