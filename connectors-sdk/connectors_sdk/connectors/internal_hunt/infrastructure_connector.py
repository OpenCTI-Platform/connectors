"""Base class of the hunt connectors of internet scanning services."""

import math
from abc import abstractmethod
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, ClassVar, NoReturn

from connectors_sdk.connectors.internal_hunt.analysis import (
    HitFields,
    event_time_bounds,
)
from connectors_sdk.connectors.internal_hunt.errors import (
    HuntExecutionError,
    HuntTimeoutError,
    HuntTranslationError,
)
from connectors_sdk.connectors.internal_hunt.fingerprints import (
    FINGERPRINT_FIELDS,
    FINGERPRINT_LANGUAGE,
    Fingerprint,
    FingerprintRule,
    describe_fingerprints,
    join_matches,
    load_queries,
    parse_fingerprint_rule,
    render_queries,
)
from connectors_sdk.connectors.internal_hunt.infrastructure import (
    CERTIFICATE,
    CERTIFICATES_FIELD,
    DOMAIN,
    IPV4,
    Host,
    HostSearchResult,
    build_infrastructure_objects,
    collect_infrastructure_observables,
)
from connectors_sdk.connectors.internal_hunt.internal_hunt_connector import (
    InternalHuntConnector,
)
from connectors_sdk.connectors.internal_hunt.models import (
    HuntEvent,
    HuntLimits,
    HuntRequest,
    HuntResult,
    HuntTimeWindow,
    NativeQuery,
)
from connectors_sdk.connectors.internal_hunt.timing import RunDeadline
from connectors_sdk.settings.base_settings import (
    HUNT_INFRASTRUCTURE_PLATFORMS,
    BaseConnectorSettings,
)


@dataclass
class _PlanRun:
    """Hosts, failures and counters of the queries of a plan run."""

    max_hosts: int
    hosts: dict[str, Host] = field(default_factory=dict)
    errors: list[HuntExecutionError] = field(default_factory=list)
    skipped: int = 0
    truncated: bool = False
    total: int = 0
    requests: int = 0

    def add(self, result: HostSearchResult) -> None:
        """Merge the hosts a query found, up to ``max_hosts``.

        Args:
            result: The hosts a query found.
        """
        # A failed query counts the request it sent
        self.requests += result.requests
        if result.truncated:
            self.truncated = True
            self.total = max(self.total, result.total or 0)
        for host in result.hosts:
            if host.key in self.hosts:
                self.hosts[host.key].merge(host)
            elif len(self.hosts) < self.max_hosts:
                self.hosts[host.key] = host
            else:
                self.truncated = True

    def result(self) -> HuntResult:
        """Build the result of the run.

        Returns:
            One event per host, partial when a query failed or was skipped.
        """
        events = [
            HuntEvent(timestamp=host.last_seen, fields=host.fields())
            for host in self.hosts.values()
        ]
        return HuntResult(
            events=events,
            total_hits=max(len(events), self.total),
            truncated=self.truncated or bool(self.errors) or self.skipped > 0,
            queries_count=self.requests,
        )


class InfrastructureHuntConnector(InternalHuntConnector):
    """Hunt connector tracking infrastructure fingerprints on an internet scanning service.

    The hunts of its platform carry a fingerprint document (see
    ``fingerprints``): the connector turns the fingerprints its service indexes
    into service queries, runs them within one result budget, merges the hosts
    they find and maps them to an infrastructure, its observables and
    indicators. Implement ``search``, and declare ``fingerprint_matches`` (or
    override ``fingerprint_queries``).

    Attributes:
        service_name: Name of the service, in messages and descriptions.
        fingerprint_matches: Service query matching a fingerprint, by kind.
        fingerprint_join: Operator joining the matches of several fingerprints,
            ``None`` for a service query per fingerprint.
        create_certificates: Whether the certificates found are created.
    """

    languages = (FINGERPRINT_LANGUAGE,)
    entity_fields = ("ip", "domain")
    # A hit is a host: its address, else its domain, names it in the evidence and is its identity
    # across runs (its time is when the service last saw it, which moves from one run to the next)
    hit_fields = HitFields(event_id=("ip", "domain"), host=("ip", "domain"))
    evidence_excluded_fields = frozenset({CERTIFICATES_FIELD})
    service_name: ClassVar[str] = ""
    fingerprint_matches: ClassVar[Mapping[str, Callable[[Fingerprint], str]]] = (
        MappingProxyType({})
    )
    fingerprint_join: ClassVar[str | None] = " OR "

    def __init__(self, settings: BaseConnectorSettings) -> None:
        """Initialize the connector.

        Args:
            settings: Connector settings, scoped to an internet scanning platform.

        Raises:
            ValueError: If the platform is not an internet scanning platform or
                the connector names no service.
        """
        super().__init__(settings)
        if self.platform not in HUNT_INFRASTRUCTURE_PLATFORMS:
            raise ValueError(
                f"An infrastructure hunt connector runs on one of "
                f"{', '.join(HUNT_INFRASTRUCTURE_PLATFORMS)} (got '{self.platform}')."
            )
        if not self.service_name:
            raise ValueError("An infrastructure hunt connector must name its service.")
        self.create_certificates = True

    def sigma_backend(self, pipeline: str | None) -> NoReturn:
        """Reject Sigma rules: infrastructure hunts search fingerprints.

        Raises:
            HuntTranslationError: Always.
        """
        raise HuntTranslationError(
            f"Sigma rules describe telemetry and are not translated for {self.service_name}: "
            f"give the hunt a native query in the '{FINGERPRINT_LANGUAGE}' language "
            "listing the infrastructure fingerprints."
        )

    def translate(self, sigma_rule: str, pipeline: str | None) -> NoReturn:
        """Reject Sigma rules (see :meth:`sigma_backend`)."""
        self.sigma_backend(pipeline)

    def fingerprint_queries(self, rule: FingerprintRule) -> list[str]:
        """Return the service queries of a fingerprint document.

        By default, one query matches any of the fingerprints of the kinds of
        ``fingerprint_matches`` (one query per fingerprint when
        ``fingerprint_join`` is ``None``), and the raw query of the platform
        runs apart.

        Args:
            rule: Fingerprint document.

        Returns:
            The queries, empty when the service searches none of its fingerprints.
        """
        matches = [
            self.fingerprint_matches[fp.kind](fp)
            for fp in rule.of_kinds(tuple(self.fingerprint_matches))
        ]
        if self.fingerprint_join is None:
            queries = matches
        else:
            queries = [join_matches(matches, self.fingerprint_join)] if matches else []
        raw = rule.raw_query(self.platform)
        if raw:
            queries.append(raw)
        return list(dict.fromkeys(queries))

    def resolve_query(self, request: HuntRequest) -> NativeQuery:
        """Plan the service queries of the fingerprint document of a hunt.

        The plan (the queries, as JSON) is the query reported to OpenCTI, in
        preview as in execution.

        Args:
            request: The hunt run request.

        Returns:
            The query plan, with the event fields of the fingerprints searched.

        Raises:
            HuntTranslationError: If the document is invalid or holds nothing the service searches.
        """
        native = super().resolve_query(request)
        rule = parse_fingerprint_rule(native.query)
        queries = self.fingerprint_queries(rule)
        if not queries:
            kinds = ", ".join(sorted({fp.kind for fp in rule.fingerprints}))
            raise HuntTranslationError(
                f"{self.service_name} searches none of the fingerprints of the hunt ({kinds}): "
                f"add a raw query for the '{self.platform}' platform."
            )
        searched = rule.of_kinds(tuple(self.fingerprint_matches))
        fields = tuple(dict.fromkeys(FINGERPRINT_FIELDS[fp.kind] for fp in searched))
        return NativeQuery(
            language=FINGERPRINT_LANGUAGE, query=render_queries(queries), fields=fields
        )

    @abstractmethod
    def search(
        self,
        query: str,
        time_window: HuntTimeWindow,
        limit: int,
        deadline: RunDeadline,
    ) -> HostSearchResult:
        """Run one query on the service.

        Args:
            query: Service query.
            time_window: Time window of the run.
            limit: Maximum number of records read.
            deadline: Run deadline.

        Returns:
            The hosts found (observed within the window when the service dates them).
        """

    def execute(
        self,
        native_query: NativeQuery,
        time_window: HuntTimeWindow,
        limits: HuntLimits,
        deadline: RunDeadline | None = None,
    ) -> HuntResult:
        """Run the queries of a plan and merge the hosts they find.

        The queries share one budget of ``limits.max_results`` records: each
        query reads at most an equal share of what is left of it, so the run
        never reads more than the budget whatever the number of queries. A
        failing query is logged and skipped; the run fails only when every
        query fails.

        Args:
            native_query: Query plan.
            time_window: Time window of the run.
            limits: Run limits.
            deadline: Run deadline shared with the SDK (started from the limits on direct calls).

        Returns:
            One event per host (IP address, else host name).
        """
        queries = load_queries(native_query.query)
        deadline = deadline or RunDeadline(limits.timeout_seconds)
        plan = _PlanRun(max_hosts=limits.max_results)
        remaining = limits.max_results
        for index, query in enumerate(queries):
            share = math.ceil(max(remaining, 0) / (len(queries) - index))
            if share == 0:
                plan.skipped += 1
                continue
            result = self._search_query(query, time_window, share, deadline, plan)
            remaining -= result.read
            plan.add(result)
        if plan.skipped:
            self.logger.info(
                "[HUNT] Result budget of the run spent, infrastructure queries skipped",
                {"max_results": limits.max_results, "skipped_queries": plan.skipped},
            )
        if plan.errors and len(plan.errors) + plan.skipped == len(queries):
            raise plan.errors[0]
        return plan.result()

    def _search_query(
        self,
        query: str,
        time_window: HuntTimeWindow,
        limit: int,
        deadline: RunDeadline,
        plan: "_PlanRun",
    ) -> HostSearchResult:
        """Run one query of a plan, a failure leaving an empty result.

        Args:
            query: Service query.
            time_window: Time window of the run.
            limit: Maximum number of records read.
            deadline: Run deadline.
            plan: The plan run, which keeps the failures.

        Returns:
            The hosts found, none when the query failed.
        """
        try:
            return self.search(query, time_window, limit, deadline)
        except HuntTimeoutError:
            raise
        except HuntExecutionError as err:
            plan.errors.append(err)
            self.logger.warning(
                "[HUNT] Infrastructure query failed",
                {"service": self.service_name, "error": str(err)},
            )
            return HostSearchResult(hosts=[])

    def to_stix(self, request: HuntRequest, result: HuntResult) -> list[Any]:
        """Map the hosts found to an infrastructure, its observables and indicators.

        Args:
            request: The hunt run request.
            result: The host events, after benign suppression.

        Returns:
            connectors-sdk models and STIX dictionaries.
        """
        allowed = [t for t in (IPV4, DOMAIN) if t in self.config.observable_types]
        if self.create_certificates:
            allowed.append(CERTIFICATE)
        expected = request.hunt.expected_observables
        if expected:
            allowed = [t for t in allowed if t in expected]
        first_seen, last_seen = event_time_bounds(result.events, request.time_window)
        native = request.hunt.native_query
        rule = parse_fingerprint_rule(native.query) if native else FingerprintRule()
        observables = collect_infrastructure_observables(
            result.events, allowed, self.config.max_observables
        )
        return list(
            build_infrastructure_objects(
                request,
                result.hits_count,
                first_seen,
                last_seen,
                observables,
                describe_fingerprints(rule),
                self.service_name,
            )
        )
