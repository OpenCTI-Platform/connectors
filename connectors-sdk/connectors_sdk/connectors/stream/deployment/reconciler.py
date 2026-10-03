"""Reconciliation of deployment statuses with the security platform.

A stream connector able to read indicators back from its vendor implements a
``DeploymentVendorAdapter``; the ``DeploymentReconciler`` periodically compares the
vendor content with the ``deployed-on`` relationships of the platform in OpenCTI:

1. List the vendor indicators (bounded, paginated by the adapter).
2. List the deployments of the platform (``pending``, ``deployed``, ``active``,
   ``failed`` and ``expired``).
3. Present on the vendor -> report ``active`` (with the vendor id).
4. Absent and ``deployed`` / ``active`` -> report ``removed``.
5. ``pending`` (analyst retry) and absent -> push again, report the outcome.
6. Withdrawal requested (relationship revoked), indicator revoked or expired, and
   present -> remove from the vendor, report ``removed`` (absent -> ``removed``).
7. Vendor indicators carrying an OpenCTI id with no deployment -> report
   ``active`` (backfill of indicators pushed before the write-back existed).

All reports of a run are sent with ``indicatorReportDeployments`` (batch). When the
adapter can read detections, hits observed since the previous run are reported.

A vendor whose API cannot list the pushed indicators implements a
``DeploymentPushAdapter`` instead: its reconciliation only pushes the ``pending``
deployments again (step 5, analyst retry) and reports hits; presence, absence,
withdrawal and backfill need the read-back of a ``DeploymentVendorAdapter``.
"""

import threading
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from connectors_sdk.connectors.stream.deployment.models import (
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
    DeploymentListingError,
    DeploymentReporter,
)
from connectors_sdk.connectors.stream.deployment.utils import (
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

_LOG_PREFIX = "[DEPLOYMENT]"


class DeploymentPushAdapter(ABC):
    """Vendor operations of a security platform whose API cannot list indicators.

    The reconciliation pushes the ``pending`` deployments again and reports hits;
    adapters able to read the pushed indicators back implement
    ``DeploymentVendorAdapter``.
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

    def collect_hits(
        self, deployments: Sequence[IndicatorDeployment], since: datetime
    ) -> Iterable[VendorHit] | HitCollection:
        """Read the detections of deployed indicators observed since a date.

        Adapters able to read detections (alerts, incidents, matches) override it;
        the default implementation reports no hit.

        Args:
            deployments: The live deployments (``deployed`` or ``active``).
            since: Only return detections that happened after this date.

        Returns:
            The hits, matched to deployments by indicator id, vendor id or value. A
            capped read returns a ``HitCollection`` telling how far it is complete.
        """
        return ()


class DeploymentVendorAdapter(DeploymentPushAdapter):
    """Vendor operations needed by the full reconciliation of a stream connector."""

    @abstractmethod
    def list_vendor_indicators(self) -> Iterable[VendorIndicator]:
        """Read the indicators pushed by the connector back from the vendor.

        The adapter paginates the vendor API and only returns the indicators the
        connector manages (same source, list or tag).

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

    def find(
        self, identifiers: Iterable[str], external_id: Any, values: Iterable[str]
    ) -> Any:
        matches = self.find_all(identifiers, external_id, values)
        return matches[0] if matches else None


class DeploymentReconciler:
    """Reconcile deployment statuses with the security platform, periodically.

    Example:
        >>> reconciler = DeploymentReconciler(reporter, MyVendorAdapter(client))
        >>> reconciler.start()  # every DEPLOYMENT_RECONCILIATION_INTERVAL minutes
    """

    def __init__(
        self,
        reporter: DeploymentReporter,
        adapter: DeploymentPushAdapter,
        *,
        max_vendor_indicators: int = DEFAULT_MAX_VENDOR_INDICATORS,
        hits_lookback: timedelta | None = None,
        initial_delay: float = 60.0,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Initialize the reconciler.

        Args:
            reporter: The deployment reporter of the connector.
            adapter: The vendor adapter (``DeploymentVendorAdapter`` for the full
                reconciliation, ``DeploymentPushAdapter`` for re-push and hits only).
            max_vendor_indicators: Read-back limit of a run. When reached, absence
                based decisions (``removed``, re-push) are skipped for that run.
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
        interval = timedelta(minutes=reporter.options.reconciliation_interval)
        self._hits_lookback = hits_lookback or max(interval, timedelta(hours=1))
        self._initial_delay = initial_delay
        self._clock = clock or (lambda: datetime.now(UTC))
        self._hits_since: datetime | None = None
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
            {"interval_minutes": self._reporter.options.reconciliation_interval},
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
                f"{_LOG_PREFIX} Deployment reconciliation failed.", {"error": str(err)}
            )
            summary = ReconciliationSummary(skipped=True, reason=str(err))
        finally:
            self._run_lock.release()
        log = self._logger.debug if summary.skipped else self._logger.info
        log(
            f"{_LOG_PREFIX} Deployment reconciliation completed.",
            summary.as_log_meta(),
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
        # From the vendor snapshot to its reports, the stream outcomes are held and sent
        # right after: a removal pushed meanwhile always lands after a stale `active`.
        with reporter.holding_queued_reports():
            now = self._clock()
            adapter = self._adapter

            vendor_indicators: list[VendorIndicator] | None = None
            if isinstance(adapter, DeploymentVendorAdapter):
                try:
                    vendor_indicators = self._read_vendor_indicators(adapter, summary)
                except Exception as err:
                    self._logger.warning(
                        f"{_LOG_PREFIX} Cannot read the indicators back from the vendor, "
                        "reconciliation skipped.",
                        {"error": str(err)},
                    )
                    return ReconciliationSummary(
                        skipped=True, reason=f"Vendor read-back failed: {err}"
                    )
            try:
                deployments = list(reporter.list_indicator_deployments(LISTED_STATUSES))
            except DeploymentListingError as err:
                self._logger.warning(
                    f"{_LOG_PREFIX} Cannot list the deployments, reconciliation skipped.",
                    {"error": str(err)},
                )
                return ReconciliationSummary(skipped=True, reason=str(err))
            summary.deployments = len(deployments)

            if (
                isinstance(adapter, DeploymentVendorAdapter)
                and vendor_indicators is not None
            ):
                reports = self._compare(
                    adapter, vendor_indicators, deployments, now, summary
                )
            else:
                reports = self._repush_pending(deployments, now, summary)

            result = reporter.report_indicator_deployments(reports)
            summary.report_errors = len(result.errors)

        if reporter.hits_enabled:
            live = [
                deployment
                for deployment in deployments
                if deployment.is_live and not deployment.requires_removal(now)
            ]
            summary.hits_reported = self._report_hits(live, now)
        return summary

    def _compare(
        self,
        adapter: DeploymentVendorAdapter,
        vendor_indicators: list[VendorIndicator],
        deployments: list[IndicatorDeployment],
        now: datetime,
        summary: ReconciliationSummary,
    ) -> list[DeploymentReport]:
        """Compare the deployments with the indicators read back from the vendor.

        Args:
            adapter: The vendor adapter.
            vendor_indicators: The vendor indicators.
            deployments: The listed deployments.
            now: The reference time.
            summary: The run counters, updated.

        Returns:
            The reports to send.
        """
        vendor_index = _Index.of_vendor_indicators(vendor_indicators)
        matched: set[int] = set()
        reports: list[DeploymentReport] = []
        for deployment in deployments:
            vendor_matches = vendor_index.find_all(
                deployment.identifiers, deployment.external_id, deployment.values
            )
            matched.update(id(vendor_indicator) for vendor_indicator in vendor_matches)
            report = self._reconcile_deployment(
                adapter, deployment, vendor_matches, now, summary
            )
            if report is not None:
                reports.append(report)
        reports.extend(
            self._discover(vendor_indicators, deployments, matched, now, summary)
        )
        return reports

    def _repush_pending(
        self,
        deployments: list[IndicatorDeployment],
        now: datetime,
        summary: ReconciliationSummary,
    ) -> list[DeploymentReport]:
        """Push the ``pending`` deployments again (vendor without read-back).

        Deployments whose withdrawal is requested, or whose indicator is revoked or
        expired, are not pushed.

        Args:
            deployments: The listed deployments.
            now: The reference time.
            summary: The run counters, updated.

        Returns:
            A ``deployed`` or ``failed`` report per pending deployment.
        """
        return [
            self._repush(deployment, now, summary)
            for deployment in deployments
            if deployment.status == DeploymentStatus.PENDING
            and not deployment.requires_removal(now)
        ]

    def _read_vendor_indicators(
        self, adapter: DeploymentVendorAdapter, summary: ReconciliationSummary
    ) -> list[VendorIndicator]:
        """Read the vendor indicators, up to the read-back limit.

        Args:
            adapter: The vendor adapter.
            summary: The run counters, updated.

        Returns:
            The vendor indicators.
        """
        vendor_indicators: list[VendorIndicator] = []
        for vendor_indicator in adapter.list_vendor_indicators():
            if len(vendor_indicators) >= self._max_vendor_indicators:
                summary.vendor_listing_truncated = True
                self._logger.warning(
                    f"{_LOG_PREFIX} Vendor read-back limit reached, absent indicators "
                    "are not reported removed during this run.",
                    {"limit": self._max_vendor_indicators},
                )
                break
            vendor_indicators.append(vendor_indicator)
        summary.vendor_indicators = len(vendor_indicators)
        return vendor_indicators

    def _reconcile_deployment(
        self,
        adapter: DeploymentVendorAdapter,
        deployment: IndicatorDeployment,
        vendor_matches: Sequence[VendorIndicator],
        now: datetime,
        summary: ReconciliationSummary,
    ) -> DeploymentReport | None:
        """Decide the report of one deployment.

        Args:
            adapter: The vendor adapter.
            deployment: The deployment.
            vendor_matches: The vendor indicators of the deployment (several when
                the vendor holds one item per observable, or duplicates).
            now: The start of the run, taken before the vendor read-back.
            summary: The run counters, updated.

        Returns:
            The report to send, if any.
        """
        vendor_indicator = vendor_matches[0] if vendor_matches else None
        must_remove = (
            deployment.requires_removal(now)
            or deployment.status == DeploymentStatus.EXPIRED
        )
        if must_remove and vendor_matches:
            return self._withdraw(adapter, deployment, vendor_matches, now, summary)
        if vendor_indicator is None:
            if summary.vendor_listing_truncated:
                return None
            if deployment.last_sync_at is not None and deployment.last_sync_at >= now:
                # Pushed by the stream while the vendor was being read back.
                summary.deferred += 1
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
        if vendor_indicator is not None:
            summary.confirmed_active += 1
            return DeploymentReport(
                indicator_id=deployment.indicator_id,
                status=DeploymentStatus.ACTIVE,
                external_id=vendor_indicator.external_id or deployment.external_id,
                synced_at=now,
            )
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

    def _withdraw(
        self,
        adapter: DeploymentVendorAdapter,
        deployment: IndicatorDeployment,
        vendor_matches: Sequence[VendorIndicator],
        now: datetime,
        summary: ReconciliationSummary,
    ) -> DeploymentReport | None:
        """Remove every vendor item of an indicator from the vendor.

        Args:
            adapter: The vendor adapter.
            deployment: The deployment to withdraw.
            vendor_matches: The vendor indicators of the deployment (at least one).
            now: The reference time.
            summary: The run counters, updated.

        Returns:
            A ``removed`` report once every item is removed, or ``None`` when one
            removal failed (the next run retries the items still listed; OpenCTI
            flags the deployment ``expired`` if no removal is confirmed in time).
        """
        for vendor_indicator in vendor_matches:
            try:
                adapter.remove_vendor_indicator(vendor_indicator, deployment)
            except Exception as err:
                summary.withdrawal_failed += 1
                self._logger.warning(
                    f"{_LOG_PREFIX} Cannot remove an indicator from the vendor.",
                    {
                        "indicator_id": deployment.indicator_id,
                        "external_id": vendor_indicator.external_id,
                        "error": str(err),
                    },
                )
                return None
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
        """Push a ``pending`` indicator again.

        Args:
            deployment: The pending deployment.
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
                {"indicator_id": deployment.indicator_id, "error": str(err)},
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
        """Report vendor indicators carrying an OpenCTI id but no deployment.

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
                vendor_indicator.indicator_id is None
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
        try:
            collected = self._adapter.collect_hits(deployments, since)
            if not isinstance(collected, HitCollection):
                return list(collected), next_since
            hits = list(collected.hits)
        except Exception as err:
            self._logger.warning(
                f"{_LOG_PREFIX} Cannot read the detections from the vendor.",
                {"error": str(err)},
            )
            return None
        complete_until = collected.complete_until
        if complete_until is None:
            return hits, next_since
        if complete_until <= since:
            self._logger.warning(
                f"{_LOG_PREFIX} Detection read capped at the start of its window, "
                "the hits of this run are a lower bound.",
                {"since": since.isoformat()},
            )
            return hits, next_since
        self._logger.warning(
            f"{_LOG_PREFIX} Detection read capped by the vendor, the next run "
            "resumes where this one stopped.",
            {"since": since.isoformat(), "complete_until": complete_until.isoformat()},
        )
        return [
            hit
            for hit in hits
            if (timestamp := parse_datetime(hit.timestamp)) is not None
            and timestamp < complete_until
        ], complete_until

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
            return 0
        since = self._hits_since if self._hits_since is not None else next_since
        collected = self._read_hits(deployments, since, next_since)
        if collected is None:
            return 0
        hits, next_since = collected
        index = _Index.of_deployments(deployments)
        aggregated: dict[str, list[Any]] = {}
        for hit in hits:
            timestamp = parse_datetime(hit.timestamp)
            if timestamp is None or hit.count < 1:
                continue
            identifier = normalize_value(hit.indicator_id)
            value = normalize_value(hit.value)
            deployment = index.find(
                [identifier] if identifier else [],
                hit.external_id,
                [value] if value else [],
            )
            if deployment is None:
                continue
            if (
                deployment.last_hit_at is not None
                and timestamp <= deployment.last_hit_at
            ):
                continue
            entry = aggregated.setdefault(
                deployment.indicator_id, [0, timestamp, timestamp]
            )
            entry[0] += hit.count
            entry[1] = min(entry[1], timestamp)
            entry[2] = max(entry[2], timestamp)
        reported = 0
        for indicator_id, (count, first_hit, last_hit) in aggregated.items():
            if self._reporter.report_indicator_hits(
                indicator_id, count, last_hit=last_hit, first_hit=first_hit
            ):
                reported += 1
        if aggregated and reported == 0:
            # Nothing accepted (OpenCTI unavailable): read the same detections again on
            # the next run. A single rejected indicator (deleted, no longer readable)
            # does not hold the window back, or it would block every other detection.
            self._logger.warning(
                f"{_LOG_PREFIX} No hit report was accepted, the detections are read "
                "again on the next run.",
                {"since": since.isoformat(), "indicators": len(aggregated)},
            )
            return 0
        self._hits_since = next_since
        return reported
