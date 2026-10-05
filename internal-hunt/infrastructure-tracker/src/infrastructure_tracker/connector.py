"""Infrastructure tracker: hunts adversary infrastructure on internet scanning sources."""

import math
from dataclasses import replace
from datetime import date, datetime, timedelta, timezone
from typing import Any, NoReturn

from connectors_sdk import InternalHuntConnector
from connectors_sdk.connectors.internal_hunt import (
    HuntConnectionCheck,
    HuntEvent,
    HuntExecutionError,
    HuntLimits,
    HuntRequest,
    HuntResult,
    HuntTimeoutError,
    HuntTimeWindow,
    HuntTranslationError,
    NativeQuery,
    RunDeadline,
    event_time_bounds,
    is_public_ip,
)
from infrastructure_tracker.rule import (
    FingerprintRule,
    build_plan,
    load_plan,
    parse_rule,
    render_plan,
)
from infrastructure_tracker.settings import ConnectorSettings
from infrastructure_tracker.sources import (
    CERTIFICATES_FIELD,
    CensysClient,
    Host,
    InternetDbClient,
    ScoutClient,
    SilentPushClient,
    SourceResult,
    UrlscanClient,
)
from infrastructure_tracker.stix import (
    CERTIFICATE,
    DOMAIN,
    IPV4,
    build_infrastructure_objects,
    collect_observables,
)

LANGUAGE = "internet"

FINGERPRINT_FIELDS = {
    "jarm": "jarm",
    "ja4x": "ja4x",
    "ja4s": "ja4s",
    "certificate_sha256": "certificate.sha256",
    "certificate_subject": "certificate.subject",
    "certificate_issuer": "certificate.issuer",
    "http_title": "http.title",
    "http_body_sha256": "http.body_sha256",
    "http_server": "http.server",
    "banner_sha256": "banner_sha256",
    "asn": "asn",
}
"""Host event field holding each fingerprint kind."""

SCOUT_MAX_AGE_DAYS = 89
SCOUT_MAX_RANGE_DAYS = 29
ENRICHMENT_MARGIN_SECONDS = 5.0


def scout_window(window: HuntTimeWindow, today: date) -> tuple[date, date] | None:
    """Clamp a run window to the dates Team Cymru Scout searches.

    Scout searches the last 90 days, at most 30 days at a time: the most
    recent part of the window is kept.

    Args:
        window: Time window of the run.
        today: Current UTC date.

    Returns:
        The first and last days to search, or ``None`` when the window is too old.
    """
    end = min(window.end.astimezone(timezone.utc).date(), today)
    start = max(
        window.start.astimezone(timezone.utc).date(),
        today - timedelta(days=SCOUT_MAX_AGE_DAYS),
        end - timedelta(days=SCOUT_MAX_RANGE_DAYS),
    )
    return (start, end) if start <= end else None


def within_window(result: SourceResult, window: HuntTimeWindow) -> SourceResult:
    """Keep the hosts a source last scanned within the run window.

    Censys and Silent Push search their current view of the internet, without
    time bounds, and urlscan.io searches whole days: a host whose last scan
    falls outside the window is dropped, and a host without scan time is kept. The records read still count against
    the run budget. The source total also counts hosts outside the window: it
    stays the hit count only when every match was read and kept. Once a host is
    dropped, or when matches were left unread (their scan time unknown), only
    the hosts kept count, and the truncation of the source is kept apart.

    Args:
        result: Hosts found by one source query.
        window: Time window of the run.

    Returns:
        The hosts observed within the window.
    """
    hosts = [
        host
        for host in result.hosts
        if host.last_seen is None or window.start <= host.last_seen <= window.end
    ]
    if len(hosts) == len(result.hosts) and not result.truncated:
        return result
    return SourceResult(hosts, None, result.read, more=result.truncated)


def describe_rule(rule: FingerprintRule, max_items: int = 5) -> str:
    """Describe the fingerprints of a rule in a few words."""
    parts = [f"{fp.kind} {fp.value}" for fp in rule.fingerprints[:max_items]]
    if len(rule.fingerprints) > max_items:
        parts.append(f"{len(rule.fingerprints) - max_items} more")
    if rule.queries:
        parts.append(f"queries on {', '.join(sorted(rule.queries))}")
    return ", ".join(parts)


def _today() -> date:
    """Return the current UTC date."""
    return datetime.now(timezone.utc).date()


DOCUMENTATION_URL = (
    "https://docs.opencti.io/latest/usage/hunt-connectors/#infrastructure-tracker"
)

REQUIRED_PERMISSIONS = (
    (
        "Censys Platform: Global Search API",
        "Personal access token (and the organization ID of an organization account): search hosts and web properties.",
    ),
    (
        "Silent Push: Explore web scan data API",
        "API key: search the web scans on JARM, certificates, HTTP titles, bodies and Server headers.",
    ),
    (
        "urlscan.io: search API",
        "API key with search access: search the scans of the run window.",
    ),
    (
        "Team Cymru Scout: search queries",
        "API key: search the IP addresses of the last 90 days on TLS fingerprints.",
    ),
    (
        "Shodan InternetDB",
        "No key: enrichment of the IP addresses found (open ports, host names, tags).",
    ),
)
"""What each source needs, as (name, purpose): a source without a key is disabled."""

SOURCE_LABELS = {
    "censys": "Censys Platform",
    "silentpush": "Silent Push",
    "urlscan": "urlscan.io",
    "cymru_scout": "Team Cymru Scout",
}

ACCESS_DENIED_HINTS = {
    "censys": {
        401: "Censys refused the personal access token: check INFRASTRUCTURE_TRACKER_CENSYS_TOKEN",
        403: "the Censys account needs access to the Global Search API, and an organization account needs INFRASTRUCTURE_TRACKER_CENSYS_ORGANISATION_ID",
    },
    "silentpush": {
        401: "Silent Push refused the API key: check INFRASTRUCTURE_TRACKER_SILENTPUSH_API_KEY",
        403: "the Silent Push plan of the key needs the Explore web scan data API",
    },
    "urlscan": {
        401: "urlscan.io refused the API key: check INFRASTRUCTURE_TRACKER_URLSCAN_API_KEY",
        403: "the urlscan.io plan of the key needs search access",
    },
    "cymru_scout": {
        401: "Team Cymru Scout refused the API key: check INFRASTRUCTURE_TRACKER_CYMRU_SCOUT_API_KEY",
        403: "the Team Cymru Scout plan of the key needs search queries",
    },
}
"""What a refused source account lacks, by source and HTTP status."""

CONNECTION_TEST_QUERIES = {
    "censys": 'host.services.endpoints.http.html_title = "OpenCTI connection test"',
    "silentpush": 'htmltitle = "OpenCTI connection test"',
    "urlscan": 'page.title:"OpenCTI connection test"',
    "cymru_scout": "0" * 62,
}
"""One search per source, unlikely to match: it proves the key can search (and counts in its quota)."""


class InfrastructureTrackerConnector(InternalHuntConnector):
    """Hunt connector tracking infrastructure fingerprints on the internet."""

    languages = (LANGUAGE,)
    required_permissions = REQUIRED_PERMISSIONS
    documentation_url = DOCUMENTATION_URL
    entity_fields = ("ip", "domain")
    evidence_excluded_fields = frozenset({CERTIFICATES_FIELD})

    def __init__(self, settings: ConnectorSettings) -> None:
        """Initialize the connector (the helper is created by ``start()``).

        Args:
            settings: The connector settings.
        """
        super().__init__(settings)
        self.tracker_config = settings.infrastructure_tracker
        self.clients: dict[str, Any] = {}
        self.internetdb: InternetDbClient | None = None

    def post_init(self) -> None:
        """Create the clients of the configured sources."""
        config = self.tracker_config
        secrets = {
            "censys": config.censys_token,
            "silentpush": config.silentpush_api_key,
            "urlscan": config.urlscan_api_key,
            "cymru_scout": config.cymru_scout_api_key,
        }
        for source in config.sources:
            secret = secrets[source]
            key = secret.get_secret_value().strip() if secret else ""
            if source == "censys":
                self.clients[source] = CensysClient(
                    str(config.censys_api_url), key, config.censys_organisation_id
                )
            elif source == "silentpush":
                self.clients[source] = SilentPushClient(
                    str(config.silentpush_api_url), key
                )
            elif source == "urlscan":
                self.clients[source] = UrlscanClient(str(config.urlscan_api_url), key)
            else:
                self.clients[source] = ScoutClient(str(config.cymru_scout_api_url), key)
            self.clients[source].access_denied_hints = dict(ACCESS_DENIED_HINTS[source])
        if config.internetdb_enabled and config.internetdb_max_lookups > 0:
            self.internetdb = InternetDbClient(base_url=str(config.internetdb_url))

    def connection_checks(self, deadline: RunDeadline) -> list[HuntConnectionCheck]:
        """Run one search per source with a key (a source without one is disabled).

        Args:
            deadline: Deadline of the connection test.

        Returns:
            One check per source.
        """
        end = datetime.now(timezone.utc)
        window = HuntTimeWindow(start=end - timedelta(days=1), end=end)
        return [
            self.run_check(
                SOURCE_LABELS[source],
                lambda source=source: self._search(
                    source, CONNECTION_TEST_QUERIES[source], window, 1, deadline
                ),
                f"{SOURCE_LABELS[source]} accepted the key and ran a search.",
            )
            for source in self.tracker_config.sources
        ]

    def sigma_backend(self, pipeline: str | None) -> NoReturn:
        """Reject Sigma rules: infrastructure hunts search fingerprints.

        Raises:
            HuntTranslationError: Always.
        """
        raise HuntTranslationError(
            "Sigma rules describe telemetry and are not translated for the 'internet' "
            "platform: give the hunt a native query in the 'internet' language "
            "listing the infrastructure fingerprints."
        )

    def translate(self, sigma_rule: str, pipeline: str | None) -> NativeQuery:
        """Reject Sigma rules (see :meth:`sigma_backend`)."""
        self.sigma_backend(pipeline)

    def resolve_query(self, request: HuntRequest) -> NativeQuery:
        """Plan the source queries of the fingerprint rule of a hunt.

        The plan (the queries of every source, as JSON) is the query reported to
        OpenCTI, in preview as in execution.

        Args:
            request: The hunt run request.

        Returns:
            The query plan.

        Raises:
            HuntTranslationError: If the rule is invalid or no configured source runs it.
        """
        native = super().resolve_query(request)
        rule = parse_rule(native.query)
        plan = build_plan(rule, self.tracker_config.sources)
        fields = tuple(
            dict.fromkeys(FINGERPRINT_FIELDS[fp.kind] for fp in rule.fingerprints)
        )
        return NativeQuery(language=LANGUAGE, query=render_plan(plan), fields=fields)

    def execute(
        self,
        native_query: NativeQuery,
        time_window: HuntTimeWindow,
        limits: HuntLimits,
        deadline: RunDeadline | None = None,
    ) -> HuntResult:
        """Run the source queries of a plan and merge the hosts they find.

        The queries share one budget of ``limits.max_results`` records: each
        query reads at most an equal share of what is left of it, so the run
        never reads more than the budget whatever the number of queries. A
        failing source is logged and skipped; the run fails only when every
        query fails.

        Args:
            native_query: Query plan.
            time_window: Time window of the run.
            limits: Run limits.
            deadline: Run deadline shared with the SDK (started from the
                limits on direct calls).

        Returns:
            One event per host (IP address, else host name).
        """
        plan = load_plan(native_query.query)
        deadline = deadline or RunDeadline(limits.timeout_seconds)
        hosts: dict[str, Host] = {}
        errors: list[HuntExecutionError] = []
        answered = 0
        truncated = False
        reported_total = 0
        remaining = limits.max_results
        pending = sum(len(queries) for queries in plan.values())
        skipped = 0
        for source, queries in plan.items():
            for query in queries:
                share = math.ceil(remaining / pending) if remaining > 0 else 0
                pending -= 1
                if share == 0:
                    skipped += 1
                    continue
                try:
                    result = self._search(source, query, time_window, share, deadline)
                except HuntTimeoutError:
                    raise
                except HuntExecutionError as err:
                    errors.append(err)
                    self.logger.warning(
                        "[TRACKER] Source query failed",
                        {"source": source, "error": str(err)},
                    )
                    continue
                answered += 1
                remaining -= result.read
                truncated = truncated or result.truncated
                if result.total is not None and result.total > result.read:
                    reported_total = max(reported_total, result.total)
                for host in result.hosts:
                    if host.key in hosts:
                        hosts[host.key].merge(host)
                    elif len(hosts) < limits.max_results:
                        hosts[host.key] = host
                    else:
                        truncated = True
        if skipped:
            truncated = True
            self.logger.info(
                "[TRACKER] Result budget of the run spent, source queries skipped",
                {"max_results": limits.max_results, "skipped_queries": skipped},
            )
        if errors and not answered:
            raise errors[0]
        if errors:
            # Some source queries failed: the hosts found are a partial view.
            truncated = True
        self._enrich(list(hosts.values()), deadline)
        events = [
            HuntEvent(timestamp=host.last_seen, fields=host.fields())
            for host in hosts.values()
        ]
        return HuntResult(
            events=events,
            total_hits=max(len(events), reported_total),
            truncated=truncated,
        )

    def _search(
        self,
        source: str,
        query: str,
        window: HuntTimeWindow,
        limit: int,
        deadline: RunDeadline,
    ) -> SourceResult:
        """Run one query on a source."""
        client = self.clients.get(source)
        if client is None:
            raise HuntExecutionError(f"The '{source}' source is not configured.")
        if source == "urlscan":
            # The query is bounded by whole days: the scans outside the run window are dropped from its answer
            start = window.start.astimezone(timezone.utc).date()
            end = window.end.astimezone(timezone.utc).date()
            return within_window(
                client.search(query, start, end, limit, deadline), window
            )
        if source == "cymru_scout":
            dates = scout_window(window, _today())
            if dates is None:
                self.logger.info(
                    "[TRACKER] Run window older than the Team Cymru Scout history, skipped",
                    {"start": window.start.isoformat()},
                )
                # Nothing of the window was searched: no host found proves nothing
                return SourceResult([], more=True)
            result = client.search(query, dates[0], dates[1], limit, deadline)
            # Days cut from the start of the window (older than the Scout history or beyond its search range) were
            # not searched; days after today hold no scan yet
            if dates[0] > window.start.astimezone(timezone.utc).date():
                return replace(result, more=True)
            return result
        return within_window(client.search(query, limit, deadline), window)

    def _enrich(self, hosts: list[Host], deadline: RunDeadline) -> None:
        """Add the Shodan InternetDB data of the IP addresses found (best effort)."""
        if self.internetdb is None:
            return
        candidates = [h for h in hosts if h.ip and is_public_ip(h.ip)]
        for host in candidates[: self.tracker_config.internetdb_max_lookups]:
            if deadline.remaining() < ENRICHMENT_MARGIN_SECONDS:
                self.logger.info(
                    "[TRACKER] Run timeout close, InternetDB enrichment stopped", {}
                )
                return
            try:
                if self.internetdb.lookup(host, deadline):
                    host.sources.append("internetdb")
            except HuntTimeoutError as err:
                self.logger.warning(
                    "[TRACKER] InternetDB enrichment stopped", {"error": str(err)}
                )
                return
            except HuntExecutionError as err:
                self.logger.warning(
                    "[TRACKER] InternetDB lookup failed",
                    {"ip": host.ip, "error": str(err)},
                )

    def to_stix(self, request: HuntRequest, result: HuntResult) -> list[Any]:
        """Map the hosts found to an infrastructure, its observables and indicators.

        Args:
            request: The hunt run request.
            result: The host events, after benign suppression.

        Returns:
            connectors-sdk models and STIX dictionaries.
        """
        allowed = [t for t in (IPV4, DOMAIN) if t in self.config.observable_types]
        if self.tracker_config.create_certificates:
            allowed.append(CERTIFICATE)
        expected = request.hunt.expected_observables
        if expected:
            allowed = [t for t in allowed if t in expected]
        first_seen, last_seen = event_time_bounds(result.events, request.time_window)
        native = request.hunt.native_query
        rule = parse_rule(native.query) if native else FingerprintRule()
        return build_infrastructure_objects(
            request,
            result.hits_count,
            first_seen,
            last_seen,
            collect_observables(result.events, allowed, self.config.max_observables),
            describe_rule(rule),
        )
