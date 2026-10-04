"""Deployment write-back to OpenCTI.

The ``DeploymentReporter`` reports to OpenCTI the lifecycle of the indicators a
stream connector pushes to a security platform (``deployed-on`` relationship
between the indicator and the Security Platform entity) and the hits observed on
the platform.

Design rules:

- Feature detection: the ``Mutation`` type is introspected once (cached). On an
  OpenCTI platform without the write-back API, the reporter logs once at info level
  and becomes a no-op.
- Graceful degradation: no reporting method raises. Errors are logged as warnings;
  dissemination never breaks because of the write-back.
- pycti helpers (``helper.report_indicator_deployment``...) are used when the
  installed pycti release ships them; otherwise the GraphQL documents of the
  write-back API are sent through ``helper.api.query``.
- ``Too many requests`` errors are retried with an exponential backoff.
"""

import atexit
import threading
import time
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import datetime
from typing import Any

from connectors_sdk.connectors.stream.deployment import _graphql
from connectors_sdk.connectors.stream.deployment.models import (
    DeploymentBatchResult,
    DeploymentReport,
    DeploymentStatus,
    IndicatorDeployment,
)
from connectors_sdk.connectors.stream.deployment.settings import (
    DeploymentAssuranceOptions,
)
from connectors_sdk.connectors.stream.deployment.utils import (
    format_datetime,
    get_opencti_indicator_id,
    is_stix_indicator,
)
from connectors_sdk.settings.base_settings import BaseConnectorSettings
from pycti import OpenCTIConnectorHelper

REPORT_DEPLOYMENT_MUTATION = "indicatorReportDeployment"
REPORT_DEPLOYMENTS_MUTATION = "indicatorReportDeployments"
REPORT_HITS_MUTATION = "indicatorReportHits"

MAX_BATCH_SIZE = 500
"""Maximum number of reports per ``indicatorReportDeployments`` call."""

LISTING_PAGE_SIZE = 500
"""Page size of the deployments listing."""

MAX_ERROR_MESSAGE_LENGTH = 2000
"""Maximum length of a vendor error message stored on a deployment."""

MAX_QUEUED_REPORTS = 10_000
"""Maximum number of queued reports (write-back not available yet, sends held): the oldest are dropped beyond."""

MAX_UNSENT_AGE = 24 * 3600.0
"""Seconds during which a report that never reached OpenCTI is sent again."""

MAX_RETRY_DELAY = 300.0
"""Longest delay between two sends of undelivered reports (doubled from the flush interval)."""

_LOG_PREFIX = "[DEPLOYMENT]"

REPORT_SENT = "sent"
"""Outcome of a report accepted by OpenCTI."""

REPORT_REJECTED = "rejected"
"""Outcome of a report refused by OpenCTI or that cannot be sent: sending it again cannot succeed."""

REPORT_UNSENT = "unsent"
"""Outcome of a report whose call did not complete (or was rate limited): it can be sent again."""


class DeploymentListingError(Exception):
    """Raised when the deployments of the security platform cannot be listed."""


def is_rate_limit_error(error: BaseException) -> bool:
    """Tell whether an OpenCTI API error is a rate limit rejection.

    Args:
        error: The exception raised by ``helper.api.query``.

    Returns:
        ``True`` for ``Too many requests`` errors.
    """
    return "too many requests" in str(error).lower()


def is_rejection_error(error: BaseException) -> bool:
    """Tell whether OpenCTI answered and rejected a call, as opposed to a call that never completed.

    pycti raises ``ValueError`` carrying the GraphQL error (a mapping with its
    ``name``) when OpenCTI rejects a call, and a text or transport error otherwise.

    Args:
        error: The exception raised by ``helper.api.query``.

    Returns:
        ``True`` for a GraphQL error other than a rate limit: sending it again
        cannot succeed.
    """
    if is_rate_limit_error(error):
        return False
    return (
        isinstance(error, ValueError)
        and bool(error.args)
        and isinstance(error.args[0], Mapping)
        and "name" in error.args[0]
    )


class _NoMutationResultError(Exception):
    """A mutation answered without its result: the call is treated as undelivered."""


def _mutation_result(response: Any, field: str) -> Any:
    """Return the result of a mutation from a GraphQL response.

    Args:
        response: The GraphQL response.
        field: The mutation field.

    Returns:
        The non-null result of the mutation.

    Raises:
        _NoMutationResultError: When the response carries no result for the field
            (``{"data": null}`` or a null field without any error).
    """
    data = response.get("data") if isinstance(response, Mapping) else None
    result = data.get(field) if isinstance(data, Mapping) else None
    if result is None:
        raise _NoMutationResultError(f"OpenCTI returned no {field} result")
    return result


def _is_batch_result(data: Any) -> bool:
    """Tell whether a batch payload carries its result (the ``processed`` count).

    Args:
        data: The ``indicatorReportDeployments`` payload.

    Returns:
        ``True`` for a mapping with a ``processed`` count.
    """
    return isinstance(data, Mapping) and data.get("processed") is not None


def _deployments_page(response: Any) -> tuple[list[Mapping[str, Any]], str | None]:
    """Return the relationship nodes and the next cursor of a deployments page.

    The reconciler acts on the absence of a deployment, so a page that is not a
    complete connection is never read as empty or as the last page.

    Args:
        response: The ``IndicatorDeploymentsOfPlatform`` response.

    Returns:
        The nodes of the page and the cursor of the next page (``None`` on the
        last page).

    Raises:
        DeploymentListingError: When the response carries no connection, edges
            or page information, an edge without its relationship, or a next page
            without its cursor.
    """
    data = response.get("data") if isinstance(response, Mapping) else None
    connection = (
        data.get("stixCoreRelationships") if isinstance(data, Mapping) else None
    )
    if not isinstance(connection, Mapping):
        raise DeploymentListingError("OpenCTI returned no deployments connection")
    edges = connection.get("edges")
    page_info = connection.get("pageInfo")
    if not isinstance(edges, list) or not isinstance(page_info, Mapping):
        raise DeploymentListingError(
            "OpenCTI returned a deployments page without its edges or page information"
        )
    nodes: list[Mapping[str, Any]] = []
    for edge in edges:
        node = edge.get("node") if isinstance(edge, Mapping) else None
        if not isinstance(node, Mapping):
            raise DeploymentListingError(
                "OpenCTI returned a deployments edge without its relationship"
            )
        nodes.append(node)
    has_next_page = page_info.get("hasNextPage")
    if not isinstance(has_next_page, bool):
        raise DeploymentListingError(
            "OpenCTI returned a deployments page without hasNextPage"
        )
    if not has_next_page:
        return nodes, None
    end_cursor = page_info.get("endCursor")
    if not end_cursor:
        raise DeploymentListingError(
            "OpenCTI announced a next deployments page without its cursor"
        )
    return nodes, str(end_cursor)


class _MalformedIntrospectionError(Exception):
    """The ``Mutation`` introspection answered without a complete field list."""


def _mutation_names(response: Any) -> frozenset[str]:
    """Return the mutation names of a ``Mutation`` introspection response.

    The detection result is cached, so a response that is not a complete field
    list is never read as a platform without the write-back API.

    Args:
        response: The ``DeploymentWriteBackFeatures`` response.

    Returns:
        The mutation names (empty only for a valid empty field list).

    Raises:
        _MalformedIntrospectionError: When the response carries no ``Mutation``
            type, no field list, or a field without its name.
    """
    data = response.get("data") if isinstance(response, Mapping) else None
    mutation_type = data.get("__type") if isinstance(data, Mapping) else None
    if not isinstance(mutation_type, Mapping):
        raise _MalformedIntrospectionError("OpenCTI returned no Mutation type")
    fields = mutation_type.get("fields")
    if not isinstance(fields, list):
        raise _MalformedIntrospectionError(
            "OpenCTI returned the Mutation type without its fields"
        )
    names: set[str] = set()
    for field in fields:
        name = field.get("name") if isinstance(field, Mapping) else None
        if not isinstance(name, str) or not name:
            raise _MalformedIntrospectionError(
                "OpenCTI returned a Mutation field without its name"
            )
        names.add(name)
    return frozenset(names)


def _is_folded_call_failure(
    chunk: Sequence[DeploymentReport], result: DeploymentBatchResult
) -> bool:
    """Tell whether a pycti batch result stands for a call that never completed.

    The pycti helper turns a failed call into one identical error per report: the
    text of a transport error, or of the GraphQL error that rejected the whole call
    (a rate limit is the only one worth sending again).

    Args:
        chunk: The reports of the call.
        result: The result returned by the helper.

    Returns:
        ``True`` when nothing was processed and every report carries the same
        transport or rate limit error.
    """
    messages = {error.message for error in result.errors}
    if result.processed != 0 or len(result.errors) != len(chunk) or len(messages) != 1:
        return False
    message = next(iter(messages))
    return "'name':" not in message or "too many requests" in message.lower()


class DeploymentReporter:
    """Report deployment statuses and hits of indicators to OpenCTI.

    Example:
        >>> reporter = DeploymentReporter.from_settings(helper, settings)
        >>> reporter.start()
        >>> reporter.report_pushed(stix_indicator, external_id="vendor-id")
        >>> reporter.report_push_failed(stix_indicator, error)
        >>> reporter.report_removed(stix_indicator)

    The ``report_pushed`` / ``report_push_failed`` / ``report_removed`` methods queue
    the reports: they are coalesced per indicator (latest wins) and flushed in
    batches every ``flush_interval`` seconds or as soon as 500 reports are queued,
    so the stream processing is not slowed down by the write-back.
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        options: DeploymentAssuranceOptions,
        *,
        flush_interval: float = 5.0,
        max_retries: int = 3,
        retry_backoff: float = 1.0,
        retry_delay: float = 300.0,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        """Initialize the reporter.

        Args:
            helper: The connector helper.
            options: The deployment write-back options.
            flush_interval: Seconds before queued reports are flushed.
            max_retries: Retries of a call rejected with ``Too many requests``.
            retry_backoff: Initial backoff in seconds (doubled at each retry).
            retry_delay: Seconds before a failed feature detection or security
                platform resolution is attempted again.
            sleep: Sleep function (injectable for tests).
            monotonic: Monotonic clock (injectable for tests).
        """
        self._helper = helper
        self._logger: Any = helper.connector_logger
        self.options = options
        self._flush_interval = flush_interval
        self._max_retries = max_retries
        self._retry_backoff = retry_backoff
        self._retry_delay = retry_delay
        self._sleep = sleep
        self._monotonic = monotonic

        self._lock = threading.RLock()
        # One OpenCTI call of each kind at a time, never under `_lock`: the stream
        # thread takes `_lock` to queue its outcomes and must not wait for the network.
        self._detection_lock = threading.Lock()
        self._resolution_lock = threading.Lock()
        self._mutations: frozenset[str] | None = None
        self._next_detection_at = 0.0
        self._detection_failure_logged = False
        self._unsupported_logged: set[str] = set()
        self._platform_id: str | None = options.security_platform_id
        self._next_resolution_at = 0.0

        self._buffer: dict[str, DeploymentReport] = {}
        self._buffer_lock = threading.Lock()
        self._send_lock = threading.Lock()
        self._flush_timer: threading.Timer | None = None
        # An immediate flush is scheduled and has not taken the queue yet.
        self._flush_soon = False
        self._waiting_for_write_back = False
        self._queue_overflow_logged = False
        self._unsent_since: dict[str, tuple[DeploymentReport, float]] = {}
        self._unsent_retry_delay = 0.0
        self._closed = False
        self._exit_handler_registered = False

    @classmethod
    def from_settings(
        cls,
        helper: OpenCTIConnectorHelper,
        settings: BaseConnectorSettings,
        **kwargs: Any,
    ) -> "DeploymentReporter":
        """Build a reporter from connector settings.

        Args:
            helper: The connector helper.
            settings: Connector settings declaring the ``security_platform`` namespace
                (and optionally ``deployment`` and ``hits``).
            **kwargs: Extra arguments of ``DeploymentReporter``.

        Returns:
            The reporter.
        """
        return cls(helper, DeploymentAssuranceOptions.from_settings(settings), **kwargs)

    @property
    def helper(self) -> OpenCTIConnectorHelper:
        """Return the connector helper."""
        return self._helper

    @property
    def logger(self) -> Any:
        """Return the connector logger."""
        return self._logger

    @property
    def enabled(self) -> bool:
        """Tell whether the deployment write-back is enabled by configuration."""
        return self.options.reporting_enabled

    @property
    def hits_enabled(self) -> bool:
        """Tell whether hits reporting is enabled by configuration."""
        return self.options.reporting_enabled and self.options.hits_reporting_enabled

    def start(self) -> bool:
        """Detect the platform support and resolve the security platform eagerly.

        Also registers a flush of the queued reports at interpreter exit.

        Returns:
            ``True`` when the write-back is operational.
        """
        if not self.enabled:
            self._logger.info(
                f"{_LOG_PREFIX} Deployment write-back disabled by configuration "
                "(DEPLOYMENT_REPORTING_ENABLED=false)."
            )
            return False
        # Before the detection: reports queued once OpenCTI is reachable again must
        # still be flushed at exit when the platform was unreachable at startup.
        with self._lock:
            if not self._exit_handler_registered:
                atexit.register(self.close)
                self._exit_handler_registered = True
        platform_id = self._ready(REPORT_DEPLOYMENT_MUTATION)
        if platform_id is None:
            return False
        self._logger.info(
            f"{_LOG_PREFIX} Deployment write-back enabled.",
            {
                "security_platform_id": platform_id,
                "security_platform_name": self.options.security_platform_name,
                "batch_reports": self.is_supported(REPORT_DEPLOYMENTS_MUTATION),
                "hits_reports": self.hits_enabled
                and self.is_supported(REPORT_HITS_MUTATION),
            },
        )
        return True

    def is_supported(self, mutation: str = REPORT_DEPLOYMENT_MUTATION) -> bool:
        """Tell whether the OpenCTI platform exposes a write-back mutation.

        Args:
            mutation: The mutation name, ``indicatorReportDeployment`` by default.

        Returns:
            ``False`` when the write-back is disabled, the feature detection failed
            (it is retried later) or the mutation is absent (logged once at info level).
        """
        if not self.enabled:
            return False
        mutations = self._available_mutations()
        if mutations is None:
            return False
        if mutation in mutations:
            return True
        with self._lock:
            if mutation not in self._unsupported_logged:
                self._unsupported_logged.add(mutation)
                self._logger.info(
                    f"{_LOG_PREFIX} The OpenCTI platform does not support '{mutation}', "
                    "the related write-back is disabled.",
                    {"mutation": mutation},
                )
        return False

    @property
    def security_platform_id(self) -> str | None:
        """Return the id of the Security Platform entity, resolving it if needed.

        The entity is resolved once through ``securityPlatformAdd`` (upsert by name)
        unless ``SECURITY_PLATFORM_ID`` is configured. A failed resolution is retried
        after ``retry_delay`` seconds; while another thread resolves it, ``None`` is
        returned at once.
        """
        if not self._resolution_lock.acquire(blocking=False):
            with self._lock:
                return self._platform_id
        try:
            with self._lock:
                if self._platform_id:
                    return self._platform_id
                now = self._monotonic()
                if now < self._next_resolution_at:
                    return None
            platform_id = self._resolve_security_platform()
            with self._lock:
                if platform_id is None:
                    self._next_resolution_at = now + self._retry_delay
                    return None
                self._platform_id = platform_id
        finally:
            self._resolution_lock.release()
        self._logger.info(
            f"{_LOG_PREFIX} Security platform resolved.",
            {
                "security_platform_id": platform_id,
                "security_platform_name": self.options.security_platform_name,
                "security_platform_type": self.options.security_platform_type,
            },
        )
        return platform_id

    def report_indicator_deployment(
        self,
        indicator_id: str,
        status: DeploymentStatus | str,
        *,
        external_id: str | None = None,
        error_message: str | None = None,
        deployed_at: datetime | str | None = None,
        synced_at: datetime | str | None = None,
        removed_at: datetime | str | None = None,
    ) -> bool:
        """Report the deployment status of one indicator immediately.

        Args:
            indicator_id: OpenCTI internal id, standard id or STIX id of the indicator.
            status: Any deployment status but ``expired``.
            external_id: The id of the indicator on the vendor side.
            error_message: The vendor error (stored when ``status`` is ``failed``).
            deployed_at: First successful push.
            synced_at: Last confirmation of the state.
            removed_at: Removal confirmation.

        Returns:
            ``True`` when OpenCTI accepted the report.
        """
        report = self._build_report(
            indicator_id=indicator_id,
            status=status,
            external_id=external_id,
            error_message=error_message,
            deployed_at=deployed_at,
            synced_at=synced_at,
            removed_at=removed_at,
        )
        if report is None:
            return False
        platform_id = self._ready(REPORT_DEPLOYMENT_MUTATION)
        if platform_id is None:
            return False
        return self._send_report(platform_id, report) == REPORT_SENT

    def report_indicator_deployments(
        self, reports: Iterable[DeploymentReport | Mapping[str, Any]]
    ) -> DeploymentBatchResult:
        """Report the deployment statuses of several indicators.

        Reports are sent in chunks of 500 with ``indicatorReportDeployments``, or one
        by one when the platform only exposes ``indicatorReportDeployment``.

        Args:
            reports: ``DeploymentReport`` instances or mappings in the pycti helper
                shape (``indicator_id``, ``status``, ``external_id``...).

        Returns:
            The aggregated result. Reports that could not be sent are listed in
            ``errors``.
        """
        normalized = [
            report
            for report in (self._coerce_report(item) for item in reports)
            if report is not None
        ]
        if not normalized:
            return DeploymentBatchResult()
        platform_id = self._ready(REPORT_DEPLOYMENT_MUTATION)
        if platform_id is None:
            return DeploymentBatchResult()
        if not self.is_supported(REPORT_DEPLOYMENTS_MUTATION):
            return self._send_reports_one_by_one(platform_id, normalized)
        result = DeploymentBatchResult()
        for start in range(0, len(normalized), MAX_BATCH_SIZE):
            chunk = normalized[start : start + MAX_BATCH_SIZE]
            result = result.merge(self._send_chunk(platform_id, chunk))
        if result.errors:
            # Per-report rejections are expected (e.g. the indicator of a stream
            # delete event no longer exists); transport errors are logged as warnings
            # where they happen.
            self._logger.info(
                f"{_LOG_PREFIX} Some deployment reports were not applied by OpenCTI.",
                {
                    "rejected": len(result.errors),
                    "sample": [
                        {"indicator_id": error.indicator_id, "message": error.message}
                        for error in result.errors[:5]
                    ],
                },
            )
        return result

    def report_indicator_hits(
        self,
        indicator_id: str,
        count: int,
        *,
        last_hit: datetime | str | None = None,
        first_hit: datetime | str | None = None,
    ) -> bool:
        """Report new hits of an indicator on the security platform.

        OpenCTI increments one stable sighting of the indicator on the platform and
        the ``hit_count`` of the deployment, and promotes ``deployed`` to ``active``.

        Args:
            indicator_id: OpenCTI internal id, standard id or STIX id of the indicator.
            count: Number of new hits (at least 1).
            last_hit: Time of the last hit (defaults to now on the platform side).
            first_hit: Time of the first hit (defaults to ``last_hit``).

        Returns:
            ``True`` when OpenCTI accepted the report.
        """
        return (
            self.report_indicator_hits_outcome(
                indicator_id, count, last_hit=last_hit, first_hit=first_hit
            )
            == REPORT_SENT
        )

    def report_indicator_hits_outcome(
        self,
        indicator_id: str,
        count: int,
        *,
        last_hit: datetime | str | None = None,
        first_hit: datetime | str | None = None,
    ) -> str:
        """Report new hits of an indicator and tell what became of the report.

        Args:
            indicator_id: OpenCTI internal id, standard id or STIX id of the indicator.
            count: Number of new hits (at least 1).
            last_hit: Time of the last hit (defaults to now on the platform side).
            first_hit: Time of the first hit (defaults to ``last_hit``).

        Returns:
            ``REPORT_SENT`` when OpenCTI accepted it, ``REPORT_REJECTED`` when it was
            refused or cannot be sent (hits disabled, empty report, write-back not
            available), ``REPORT_UNSENT`` when the call did not complete or was rate
            limited and can be sent again. The pycti helper does not tell a rejection
            from a failed call: a report it does not accept is ``REPORT_UNSENT``.
        """
        if not self.hits_enabled:
            return REPORT_REJECTED
        if not indicator_id or count < 1:
            self._logger.debug(
                f"{_LOG_PREFIX} Ignoring an empty hit report.",
                {"indicator_id": indicator_id, "count": count},
            )
            return REPORT_REJECTED
        platform_id = self._ready(REPORT_HITS_MUTATION)
        if platform_id is None:
            return REPORT_UNSENT if self._awaiting_write_back() else REPORT_REJECTED
        try:
            if hasattr(self._helper, "report_indicator_hits"):
                result = self._helper.report_indicator_hits(
                    indicator_id=indicator_id,
                    platform_id=platform_id,
                    count=count,
                    last_hit=format_datetime(last_hit),
                    first_hit=format_datetime(first_hit),
                )
                return REPORT_SENT if result is not None else REPORT_UNSENT
            variables: dict[str, Any] = {
                "indicatorId": indicator_id,
                "platformId": platform_id,
                "count": count,
            }
            if last_hit is not None:
                variables["lastHit"] = format_datetime(last_hit)
            if first_hit is not None:
                variables["firstHit"] = format_datetime(first_hit)
            _mutation_result(
                self._execute(_graphql.REPORT_HITS_MUTATION, variables),
                "indicatorReportHits",
            )
            return REPORT_SENT
        except Exception as err:
            self._logger.warning(
                f"{_LOG_PREFIX} Cannot report indicator hits.",
                {"indicator_id": indicator_id, "count": count, "error": str(err)},
            )
            return REPORT_REJECTED if is_rejection_error(err) else REPORT_UNSENT

    def list_indicator_deployments(
        self, statuses: Iterable[DeploymentStatus | str] | None = None
    ) -> Iterator[IndicatorDeployment]:
        """List the ``deployed-on`` relationships of the security platform.

        Args:
            statuses: Only list deployments with these statuses (all when ``None``).

        Yields:
            The deployments, page by page (500 per page).

        Raises:
            DeploymentListingError: If a page cannot be read or is malformed.
                Callers that decide on the absence of an indicator must not rely
                on a partial listing.
        """
        platform_id = self._ready(REPORT_DEPLOYMENT_MUTATION)
        if platform_id is None:
            return
        status_values = (
            [DeploymentStatus(status).value for status in statuses]
            if statuses is not None
            else None
        )
        # Never the pycti helper listing: it ends quietly on a failed page, and a
        # partial listing would make the reconciler report deployments as removed.
        for node in self._list_nodes_with_graphql(platform_id, status_values):
            deployment = IndicatorDeployment.from_node(node)
            if deployment is not None:
                yield deployment

    def _list_nodes_with_graphql(
        self, platform_id: str, status_values: list[str] | None
    ) -> Iterator[Mapping[str, Any]]:
        """List deployment nodes with the ``stixCoreRelationships`` query.

        Args:
            platform_id: The security platform id.
            status_values: The statuses to list, all when ``None``.

        Yields:
            The relationship nodes, page by page.

        Raises:
            DeploymentListingError: If a page cannot be read, is malformed, or
                points back to a page already read.
        """
        filters = (
            {
                "mode": "and",
                "filterGroups": [],
                "filters": [{"key": "deployment_status", "values": status_values}],
            }
            if status_values
            else None
        )
        after: str | None = None
        followed: set[str] = set()
        while True:
            try:
                response = self._execute(
                    _graphql.DEPLOYMENTS_LIST_QUERY,
                    {
                        "relationshipTypes": ["deployed-on"],
                        "toId": [platform_id],
                        "first": LISTING_PAGE_SIZE,
                        "after": after,
                        "filters": filters,
                    },
                )
            except Exception as err:
                raise DeploymentListingError(
                    f"Cannot list the deployments of the security platform: {err}"
                ) from err
            nodes, next_cursor = _deployments_page(response)
            yield from nodes
            if next_cursor is None:
                return
            if next_cursor in followed:
                raise DeploymentListingError(
                    "OpenCTI returned a deployments cursor that was already followed"
                )
            followed.add(next_cursor)
            after = next_cursor

    def enqueue(self, report: DeploymentReport) -> bool:
        """Queue a report, flushed with the next batch.

        Reports are coalesced per indicator: the latest report of an indicator
        replaces any queued one. The batch is sent from a timer thread, after the
        flush interval or at once when ``MAX_BATCH_SIZE`` reports are queued: the
        caller (the stream callback) never waits for OpenCTI. Beyond
        ``MAX_QUEUED_REPORTS`` queued reports (write-back unavailable, or sends
        held by a reconciliation), the oldest one is dropped.

        Args:
            report: The report.

        Returns:
            ``True`` when the report was queued.
        """
        if not self.enabled or self._closed:
            return False
        with self._lock:
            known_unsupported = (
                self._mutations is not None
                and REPORT_DEPLOYMENT_MUTATION not in self._mutations
            )
        if known_unsupported:
            return False
        with self._buffer_lock:
            self._buffer.pop(report.indicator_id, None)
            self._buffer[report.indicator_id] = report
            if len(self._buffer) > MAX_QUEUED_REPORTS:
                del self._buffer[next(iter(self._buffer))]
                if not self._queue_overflow_logged:
                    self._queue_overflow_logged = True
                    self._logger.warning(
                        f"{_LOG_PREFIX} Too many queued deployment reports, "
                        "dropping the oldest ones.",
                        {"queued": MAX_QUEUED_REPORTS},
                    )
            flush_now = (
                len(self._buffer) >= MAX_BATCH_SIZE
                and not self._waiting_for_write_back
                and not self._flush_soon
            )
            if flush_now or self._flush_timer is None:
                if self._flush_timer is not None:
                    self._flush_timer.cancel()
                timer = threading.Timer(
                    0.0 if flush_now else self._flush_interval, self._flush_on_timer
                )
                timer.daemon = True
                self._flush_timer = timer
                self._flush_soon = self._flush_soon or flush_now
                timer.start()
        return True

    @contextmanager
    def holding_queued_reports(self) -> Iterator[None]:
        """Hold the queued (stream) reports while a snapshot based batch is built and sent.

        The reports queued before are sent first and the ones queued while held are
        sent right after, so an outcome newer than the snapshot is always applied last.

        Yields:
            Nothing; the queued reports are held until the block ends.
        """
        self.flush()
        self._send_lock.acquire()
        try:
            yield
        finally:
            self._send_lock.release()
        self.flush()

    def flush(self, *, wait: bool = True) -> DeploymentBatchResult:
        """Send the queued reports now.

        While the write-back is not available yet (feature detection or security
        platform resolution failed and is retried later), the reports stay queued
        (at most ``MAX_QUEUED_REPORTS``). They are dropped when the platform is known
        not to support the write-back.

        Args:
            wait: Wait for the sends held by another batch. When ``False`` and the
                sends are held, the reports stay queued for the next flush.

        Returns:
            The result of the batch.
        """
        if not self._send_lock.acquire(blocking=wait):
            return DeploymentBatchResult()
        try:
            return self._flush_queued()
        finally:
            self._send_lock.release()

    def _flush_queued(self) -> DeploymentBatchResult:
        """Send the queued reports, the send lock being held.

        Returns:
            The result of the batch.
        """
        with self._buffer_lock:
            reports = list(self._buffer.values())
            self._buffer.clear()
            if self._flush_timer is not None:
                self._flush_timer.cancel()
                self._flush_timer = None
            self._flush_soon = False
            self._queue_overflow_logged = False
        if not reports:
            return DeploymentBatchResult()
        if self._awaiting_write_back():
            self._requeue(reports, write_back_unavailable=True)
            return DeploymentBatchResult()
        self._waiting_for_write_back = False
        result = self.report_indicator_deployments(reports)
        self._retry_unsent(reports, result.unsent)
        return result

    def _retry_unsent(
        self, sent: list[DeploymentReport], unsent: Sequence[DeploymentReport]
    ) -> None:
        """Queue again the reports that never reached OpenCTI (outage, transport error).

        Rejections by OpenCTI are final and dropped. Undelivered reports are sent
        again with a growing delay, for at most ``MAX_UNSENT_AGE`` seconds. The age
        belongs to the report itself: a newer report of the same indicator, which
        replaced it in the queue, starts its own.

        Args:
            sent: The reports of the flush.
            unsent: The reports of the flush that were not delivered.
        """
        now = self._monotonic()
        unsent_ids = {report.indicator_id for report in unsent}
        for report in sent:
            if report.indicator_id not in unsent_ids:
                self._unsent_since.pop(report.indicator_id, None)
        if not unsent:
            self._unsent_retry_delay = 0.0
            return
        retried: list[DeploymentReport] = []
        expired = 0
        for report in unsent:
            tracked = self._unsent_since.get(report.indicator_id)
            first_failure = (
                tracked[1] if tracked is not None and tracked[0] is report else now
            )
            if now - first_failure > MAX_UNSENT_AGE:
                del self._unsent_since[report.indicator_id]
                expired += 1
            else:
                self._unsent_since[report.indicator_id] = (report, first_failure)
                retried.append(report)
        if expired:
            self._logger.warning(
                f"{_LOG_PREFIX} Dropping deployment reports undelivered for too long.",
                {"dropped": expired, "max_age_seconds": MAX_UNSENT_AGE},
            )
        self._unsent_retry_delay = min(
            max(self._flush_interval, self._unsent_retry_delay * 2), MAX_RETRY_DELAY
        )
        self._requeue(retried, delay=self._unsent_retry_delay)

    def _awaiting_write_back(self) -> bool:
        """Tell whether the write-back is expected to become available later.

        Returns:
            ``True`` when the feature detection or the security platform resolution
            failed and will be retried.
        """
        if not self.enabled or self._closed:
            return False
        mutations = self._available_mutations()
        if mutations is None:
            return True
        if REPORT_DEPLOYMENT_MUTATION not in mutations:
            return False
        return self.security_platform_id is None

    def _requeue(
        self,
        reports: list[DeploymentReport],
        *,
        write_back_unavailable: bool = False,
        delay: float | None = None,
    ) -> None:
        """Put reports back in the queue, behind nothing newer for the same indicator.

        Args:
            reports: The reports that could not be sent yet, oldest first.
            write_back_unavailable: ``True`` while the write-back itself is not
                available yet (feature detection or platform resolution pending).
            delay: Seconds before the next flush (the flush interval by default).
        """
        with self._buffer_lock:
            merged = {
                report.indicator_id: report
                for report in reports
                if report.indicator_id not in self._buffer
            }
            merged.update(self._buffer)
            overflow = len(merged) - MAX_QUEUED_REPORTS
            if overflow > 0:
                for indicator_id in list(merged)[:overflow]:
                    del merged[indicator_id]
                self._logger.warning(
                    f"{_LOG_PREFIX} Deployment write-back unavailable, dropping the "
                    "oldest queued reports.",
                    {"dropped": overflow, "queued": MAX_QUEUED_REPORTS},
                )
            self._buffer = merged
            if write_back_unavailable:
                self._waiting_for_write_back = True
            if self._flush_timer is None and self._buffer:
                timer = threading.Timer(
                    self._flush_interval if delay is None else delay,
                    self._flush_on_timer,
                )
                timer.daemon = True
                self._flush_timer = timer
                timer.start()

    def close(self) -> None:
        """Flush the queued reports and stop accepting new ones."""
        self._closed = True
        self.flush()

    def report_pushed(
        self,
        stix_object: Mapping[str, Any],
        *,
        external_id: str | None = None,
        deployed_at: datetime | str | None = None,
    ) -> bool:
        """Queue a ``deployed`` report after a successful push of a stream indicator.

        Args:
            stix_object: The STIX indicator of the stream event.
            external_id: The id of the indicator on the vendor side.
            deployed_at: Time of the push (defaults to now on the platform side).

        Returns:
            ``True`` when a report was queued (``False`` for non-indicators).
        """
        return self._enqueue_for(
            stix_object,
            DeploymentStatus.DEPLOYED,
            external_id=external_id,
            deployed_at=deployed_at,
        )

    def report_push_failed(
        self,
        stix_object: Mapping[str, Any],
        error: BaseException | str,
        *,
        external_id: str | None = None,
    ) -> bool:
        """Queue a ``failed`` report after the vendor rejected a stream indicator.

        Args:
            stix_object: The STIX indicator of the stream event.
            error: The vendor error.
            external_id: The id of the indicator on the vendor side, if any.

        Returns:
            ``True`` when a report was queued (``False`` for non-indicators).
        """
        return self._enqueue_for(
            stix_object,
            DeploymentStatus.FAILED,
            external_id=external_id,
            error_message=str(error) or type(error).__name__,
        )

    def report_removed(
        self,
        stix_object: Mapping[str, Any],
        *,
        external_id: str | None = None,
        removed_at: datetime | str | None = None,
    ) -> bool:
        """Queue a ``removed`` report after a stream indicator was removed from the vendor.

        Args:
            stix_object: The STIX indicator of the stream event.
            external_id: The id of the indicator on the vendor side.
            removed_at: Time of the removal (defaults to now on the platform side).

        Returns:
            ``True`` when a report was queued (``False`` for non-indicators).
        """
        return self._enqueue_for(
            stix_object,
            DeploymentStatus.REMOVED,
            external_id=external_id,
            removed_at=removed_at,
        )

    def _enqueue_for(
        self,
        stix_object: Mapping[str, Any],
        status: DeploymentStatus,
        **fields: Any,
    ) -> bool:
        """Queue a report for the indicator of a stream event.

        Args:
            stix_object: The STIX object of the stream event.
            status: The status to report.
            **fields: Other report fields.

        Returns:
            ``True`` when a report was queued.
        """
        if not self.enabled or not is_stix_indicator(stix_object):
            return False
        indicator_id = get_opencti_indicator_id(stix_object)
        if indicator_id is None:
            return False
        report = self._build_report(indicator_id=indicator_id, status=status, **fields)
        return report is not None and self.enqueue(report)

    def _flush_on_timer(self) -> None:
        """Flush queued reports from the timer thread (never raises).

        The timer never waits for the send lock: while a reconciliation (or another
        flush) holds it, the flush is armed again after the flush interval, one
        timer at a time, and ``holding_queued_reports`` sends the queue once the
        reconciliation releases it.
        """
        with self._buffer_lock:
            self._flush_timer = None
        try:
            if not self._send_lock.acquire(blocking=False):
                with self._buffer_lock:
                    if self._flush_timer is None and self._buffer and not self._closed:
                        timer = threading.Timer(
                            self._flush_interval, self._flush_on_timer
                        )
                        timer.daemon = True
                        self._flush_timer = timer
                        timer.start()
                return
            try:
                self._flush_queued()
            finally:
                self._send_lock.release()
        except Exception as err:
            self._logger.warning(
                f"{_LOG_PREFIX} Cannot flush the deployment reports.",
                {"error": str(err)},
            )

    def _build_report(self, **fields: Any) -> DeploymentReport | None:
        """Build a report, logging invalid ones.

        Args:
            **fields: The report fields.

        Returns:
            The report, or ``None`` when invalid.
        """
        error_message = fields.get("error_message")
        if isinstance(error_message, str) and len(error_message) > (
            MAX_ERROR_MESSAGE_LENGTH
        ):
            fields["error_message"] = (
                error_message[: MAX_ERROR_MESSAGE_LENGTH - 3] + "..."
            )
        try:
            return DeploymentReport(**fields)
        except (TypeError, ValueError) as err:
            self._logger.warning(
                f"{_LOG_PREFIX} Ignoring an invalid deployment report.",
                {"report": {k: str(v) for k, v in fields.items()}, "error": str(err)},
            )
            return None

    def _coerce_report(
        self, report: DeploymentReport | Mapping[str, Any]
    ) -> DeploymentReport | None:
        """Accept reports as instances or pycti helper mappings.

        Args:
            report: The report.

        Returns:
            The report, or ``None`` when invalid.
        """
        if isinstance(report, DeploymentReport):
            return report
        if isinstance(report, Mapping):
            return self._build_report(
                indicator_id=report.get("indicator_id"),
                status=report.get("status"),
                external_id=report.get("external_id"),
                error_message=report.get("error_message"),
                deployed_at=report.get("deployed_at"),
                synced_at=report.get("synced_at"),
                removed_at=report.get("removed_at"),
            )
        self._logger.warning(
            f"{_LOG_PREFIX} Ignoring a deployment report of an unexpected type.",
            {"type": type(report).__name__},
        )
        return None

    def _ready(self, mutation: str) -> str | None:
        """Return the security platform id when a mutation can be used.

        Args:
            mutation: The mutation to use.

        Returns:
            The security platform id, or ``None`` when the write-back is unavailable.
        """
        if not self.is_supported(mutation):
            return None
        return self.security_platform_id

    def _available_mutations(self) -> frozenset[str] | None:
        """Return the mutations of the platform (introspected once, then cached).

        Returns:
            The mutation names, or ``None`` when the detection failed or answered a
            malformed introspection (retried after ``retry_delay`` seconds) or is
            running in another thread.
        """
        if not self._detection_lock.acquire(blocking=False):
            with self._lock:
                return self._mutations
        try:
            with self._lock:
                if self._mutations is not None:
                    return self._mutations
                now = self._monotonic()
                if now < self._next_detection_at:
                    return None
            try:
                mutations = _mutation_names(
                    self._helper.api.query(_graphql.MUTATION_FIELDS_QUERY)
                )
            except Exception as err:
                with self._lock:
                    self._next_detection_at = now + self._retry_delay
                    already_logged = self._detection_failure_logged
                    self._detection_failure_logged = True
                log = self._logger.debug if already_logged else self._logger.warning
                log(
                    f"{_LOG_PREFIX} Cannot detect the deployment write-back support of "
                    "the OpenCTI platform, retrying later.",
                    {"error": str(err), "retry_in_seconds": self._retry_delay},
                )
                return None
            with self._lock:
                self._mutations = mutations
            return mutations
        finally:
            self._detection_lock.release()

    def _resolve_security_platform(self) -> str | None:
        """Resolve the Security Platform entity by name (upsert).

        Returns:
            The entity id, or ``None`` on error.
        """
        name = self.options.security_platform_name
        platform_type = self.options.security_platform_type
        try:
            platform: Any
            if hasattr(self._helper, "get_or_create_security_platform"):
                platform = self._helper.get_or_create_security_platform(
                    name, security_platform_type=platform_type
                )
            else:
                platform_input: dict[str, Any] = {"name": name, "update": True}
                if platform_type:
                    platform_input["security_platform_type"] = platform_type
                response = self._execute(
                    _graphql.SECURITY_PLATFORM_ADD_MUTATION, {"input": platform_input}
                )
                platform = (response.get("data") or {}).get("securityPlatformAdd")
            platform_id = platform.get("id") if isinstance(platform, Mapping) else None
            if not platform_id:
                self._logger.warning(
                    f"{_LOG_PREFIX} Cannot resolve the security platform, retrying later.",
                    {"security_platform_name": name},
                )
                return None
            return str(platform_id)
        except Exception as err:
            self._logger.warning(
                f"{_LOG_PREFIX} Cannot resolve the security platform, retrying later.",
                {"security_platform_name": name, "error": str(err)},
            )
            return None

    def _send_report(self, platform_id: str, report: DeploymentReport) -> str:
        """Send one report with ``indicatorReportDeployment``.

        Args:
            platform_id: The security platform id.
            report: The report.

        Returns:
            ``REPORT_SENT``, ``REPORT_REJECTED`` (OpenCTI answered with an error) or
            ``REPORT_UNSENT`` (the call did not complete; the pycti helper does not
            tell them apart).
        """
        try:
            if hasattr(self._helper, "report_indicator_deployment"):
                result = self._helper.report_indicator_deployment(
                    platform_id=platform_id, **report.to_helper_kwargs()
                )
                return REPORT_SENT if result is not None else REPORT_UNSENT
            _mutation_result(
                self._execute(
                    _graphql.REPORT_DEPLOYMENT_MUTATION,
                    {"platformId": platform_id, **report.to_graphql_input()},
                ),
                "indicatorReportDeployment",
            )
            return REPORT_SENT
        except Exception as err:
            self._logger.warning(
                f"{_LOG_PREFIX} Cannot report the deployment status.",
                {
                    "indicator_id": report.indicator_id,
                    "status": report.status.value,
                    "error": str(err),
                },
            )
            return REPORT_REJECTED if is_rejection_error(err) else REPORT_UNSENT

    def _send_reports_one_by_one(
        self, platform_id: str, reports: Sequence[DeploymentReport]
    ) -> DeploymentBatchResult:
        """Send reports one by one (platforms without the batch mutation).

        Args:
            platform_id: The security platform id.
            reports: The reports.

        Returns:
            The aggregated result.
        """
        processed = 0
        rejected: list[DeploymentReport] = []
        unsent: list[DeploymentReport] = []
        for report in reports:
            outcome = self._send_report(platform_id, report)
            if outcome == REPORT_SENT:
                processed += 1
            elif outcome == REPORT_REJECTED:
                rejected.append(report)
            else:
                unsent.append(report)
        result = DeploymentBatchResult(processed=processed)
        if rejected:
            rejection = DeploymentBatchResult.failure(
                rejected, "Report rejected by OpenCTI"
            )
            result = result.merge(DeploymentBatchResult(errors=rejection.errors))
        if unsent:
            result = result.merge(
                DeploymentBatchResult.failure(unsent, "Report not accepted by OpenCTI")
            )
        return result

    def _send_chunk(
        self, platform_id: str, chunk: list[DeploymentReport]
    ) -> DeploymentBatchResult:
        """Send one chunk of reports with ``indicatorReportDeployments``.

        Args:
            platform_id: The security platform id.
            chunk: At most 500 reports.

        Returns:
            The result of the call.
        """
        try:
            if hasattr(self._helper, "report_indicator_deployments"):
                data = self._helper.report_indicator_deployments(
                    platform_id,
                    [
                        {
                            key: value
                            for key, value in report.to_helper_kwargs().items()
                            if value is not None
                        }
                        for report in chunk
                    ],
                )
                if not _is_batch_result(data):
                    return DeploymentBatchResult.failure(
                        chunk, "Reports not accepted by OpenCTI"
                    )
                result = DeploymentBatchResult.from_graphql(data)
                if _is_folded_call_failure(chunk, result):
                    return DeploymentBatchResult.failure(
                        chunk, result.errors[0].message
                    )
                return result
            payload = _mutation_result(
                self._execute(
                    _graphql.REPORT_DEPLOYMENTS_MUTATION,
                    {
                        "platformId": platform_id,
                        "reports": [report.to_graphql_input() for report in chunk],
                    },
                ),
                "indicatorReportDeployments",
            )
            if not _is_batch_result(payload):
                raise _NoMutationResultError(
                    "OpenCTI returned no indicatorReportDeployments result"
                )
            return DeploymentBatchResult.from_graphql(payload)
        except Exception as err:
            self._logger.warning(
                f"{_LOG_PREFIX} Cannot report a batch of deployment statuses.",
                {"reports": len(chunk), "error": str(err)},
            )
            failure = DeploymentBatchResult.failure(chunk, str(err))
            if is_rejection_error(err):
                return DeploymentBatchResult(errors=failure.errors)
            return failure

    def _execute(
        self, query: str, variables: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Send a GraphQL document, retrying ``Too many requests`` rejections.

        Args:
            query: The GraphQL document.
            variables: The variables.

        Returns:
            The GraphQL response.

        Raises:
            Exception: The last error when retries are exhausted or for other errors.
        """
        attempt = 0
        while True:
            try:
                response: dict[str, Any] = self._helper.api.query(
                    query, variables or {}
                )
                return response
            except Exception as err:
                if not is_rate_limit_error(err) or attempt >= self._max_retries:
                    raise
                delay = self._retry_backoff * (2**attempt)
                attempt += 1
                self._logger.debug(
                    f"{_LOG_PREFIX} OpenCTI rate limit reached, backing off.",
                    {"attempt": attempt, "delay_seconds": delay},
                )
                self._sleep(delay)
