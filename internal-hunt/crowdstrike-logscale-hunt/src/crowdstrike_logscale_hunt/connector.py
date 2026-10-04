"""CrowdStrike LogScale hunt connector: executes OpenCTI hunts as LogScale query jobs."""

from typing import Any

from connectors_sdk import InternalHuntConnector
from connectors_sdk.connectors.internal_hunt import (
    DEFAULT_ENTITY_FIELDS,
    HuntEvent,
    HuntLimits,
    HuntResult,
    HuntTimeWindow,
    NativeQuery,
    RunDeadline,
    build_pipeline,
    flatten_fields,
    parse_timestamp,
)
from crowdstrike_logscale_hunt.client import COUNT_FIELD, MAX_EVENTS, LogScaleClient
from crowdstrike_logscale_hunt.settings import ConnectorSettings
from sigma.backends.crowdstrike import LogScaleBackend
from sigma.pipelines.crowdstrike import pipelines as crowdstrike_pipelines

FALCON_API_PREFIX = "/humio"
"""Path of the LogScale API of Falcon Next-Gen SIEM under the CrowdStrike API."""

TIME_FIELDS: tuple[str, ...] = ("@timestamp", "timestamp")
"""Fields holding the event time, by order of preference."""

RAW_FIELDS = frozenset(
    {
        "@rawstring",
        "@id",
        "@timestamp.nanos",
        "@ingesttimestamp",
        "@timezone",
        "#repo",
        "#type",
        "#humioBackfill",
        "aid",
        "cid",
    }
)
"""Raw event and LogScale bookkeeping fields, never sampled as evidence."""


def strip_statement_end(query: str) -> str:
    """Remove the trailing pipes and blanks of a LogScale query."""
    return query.strip().rstrip("|").rstrip()


DOCUMENTATION_URL = (
    "https://docs.opencti.io/latest/usage/hunt-connectors/#crowdstrike-logscale"
)

REQUIRED_PERMISSIONS = (
    (
        "NGSIEM Read",
        "Falcon API client scope: read the status and results of the query jobs.",
    ),
    (
        "NGSIEM Write",
        "Falcon API client scope: start and stop the query jobs.",
    ),
    (
        "Search on CROWDSTRIKE_LOGSCALE_HUNT_REPOSITORY",
        "LogScale token permission (ReadAccess or QueryDashboard): run query jobs on the repository or view.",
    ),
)
"""Least-privilege permissions of the account of the connector, as (name, purpose)."""

ACCESS_DENIED_HINTS = {
    401: "CrowdStrike refused the credentials: check the API client ID and secret (Falcon) or the LogScale API token, and that they are not revoked",
    403: "the API client needs the NGSIEM Read and Write scopes (Support and resources > API clients and keys), or the LogScale token needs search access to CROWDSTRIKE_LOGSCALE_HUNT_REPOSITORY",
}
"""What a refused account lacks, by HTTP status."""


class CrowdstrikeLogscaleHuntConnector(InternalHuntConnector):
    """Hunt connector running Sigma and LogScale hunts on CrowdStrike Falcon and LogScale."""

    languages = ("logscale",)
    required_permissions = REQUIRED_PERMISSIONS
    documentation_url = DOCUMENTATION_URL
    query_join = " or "
    evidence_excluded_fields = RAW_FIELDS
    entity_fields = (
        *DEFAULT_ENTITY_FIELDS,
        "ComputerName",
        "UserName",
        "UserPrincipal",
        "RemoteAddressIP4",
        "RemoteAddressIP6",
        "LocalAddressIP4",
    )

    def __init__(self, settings: ConnectorSettings) -> None:
        """Initialize the connector (the helper is created by ``start()``).

        Args:
            settings: The connector settings.
        """
        super().__init__(settings)
        self.logscale_config = settings.crowdstrike_logscale_hunt
        self.client: LogScaleClient | None = None

    def post_init(self) -> None:
        """Create the LogScale query jobs client."""
        config = self.logscale_config
        common: dict[str, Any] = {
            "repository": config.repository,
            "verify_ssl": config.verify_ssl,
            "poll_interval": config.poll_interval,
            "logger": self.logger,
        }
        if config.deployment == "falcon":
            self.client = LogScaleClient(
                base_url=str(config.base_url),
                path_prefix=FALCON_API_PREFIX,
                client_id=config.client_id,
                client_secret=(
                    config.client_secret.get_secret_value()
                    if config.client_secret
                    else None
                ),
                **common,
            )
        else:
            self.client = LogScaleClient(
                base_url=str(config.logscale_url),
                path_prefix="",
                api_token=(
                    config.logscale_token.get_secret_value()
                    if config.logscale_token
                    else None
                ),
                **common,
            )
        self.client.access_denied_hints = dict(ACCESS_DENIED_HINTS)

    def connection_test_query(self) -> NativeQuery:
        """Return the test search: one event of the repository."""
        return NativeQuery(language="logscale", query="*")

    def sigma_backend(self, pipeline: str | None) -> LogScaleBackend:
        """Create the pySigma LogScale backend.

        Args:
            pipeline: Pipeline requested by the hunt, or ``None`` for the configured one.

        Returns:
            The LogScale backend.
        """
        return LogScaleBackend(
            build_pipeline(
                pipeline or self.logscale_config.sigma_pipeline, crowdstrike_pipelines
            )
        )

    def execute(
        self,
        native_query: NativeQuery,
        time_window: HuntTimeWindow,
        limits: HuntLimits,
        deadline: RunDeadline | None = None,
    ) -> HuntResult:
        """Run the hunt as a LogScale query job over the run window.

        The query is capped with ``tail``; the total hit count is read with
        ``count()`` only when the cap is reached.

        Args:
            native_query: LogScale query.
            time_window: Time window of the run.
            limits: Run limits.
            deadline: Run deadline shared with the SDK (started from the
                limits on direct calls).

        Returns:
            The hunt results.
        """
        if self.client is None:
            raise RuntimeError("The LogScale client is created by start().")
        deadline = deadline or RunDeadline(limits.timeout_seconds)
        query = strip_statement_end(native_query.query)
        cap = min(limits.max_results, MAX_EVENTS)
        start, end = time_window.start, time_window.end
        job_key = id(native_query)
        result = self.client.query(
            f"{query}\n| tail(limit={cap})", start, end, deadline, job_key
        )
        warnings = list(result.warnings)
        total = len(result.events)
        count_unknown = False
        if total >= cap:
            counted = self.client.query(
                f"{query}\n| count()", start, end, deadline, job_key
            )
            warnings.extend(counted.warnings)
            counted_total = _count(counted.events)
            # A full page without a usable count (missing, not a number or below
            # the page size) cannot prove that every match was returned: the
            # page size is kept as a lower bound.
            count_unknown = counted_total is None or counted_total < total
            total = max(total, counted_total or 0)
        if warnings:
            self.logger.warning("[LOGSCALE] Query warnings", {"warnings": warnings[:5]})
        events = []
        for raw in result.events:
            fields = flatten_fields(raw)
            events.append(HuntEvent(timestamp=_event_time(fields), fields=fields))
        # LogScale warnings flag partial results (segments not searched, limits
        # reached) without a structured flag: they are kept as truncation, for
        # the count query as much as for the data query.
        return HuntResult(
            events=events,
            total_hits=total,
            truncated=total > len(events) or count_unknown or bool(warnings),
        )

    def on_timeout(self, native_query: NativeQuery) -> None:
        """Delete the query job of a timed out run.

        Args:
            native_query: Query that timed out.
        """
        if self.client is not None:
            self.client.cancel(id(native_query))


def _event_time(fields: dict[str, Any]) -> Any:
    """Return the event time from the first time field present."""
    for name in TIME_FIELDS:
        timestamp = parse_timestamp(fields.get(name))
        if timestamp is not None:
            return timestamp
    return None


def _count(events: list[dict[str, Any]]) -> int | None:
    """Read the result of a ``count()`` query, None when it is unusable."""
    value = events[0].get(COUNT_FIELD) if events else None
    if isinstance(value, str) and value.strip().isdigit():
        return int(value)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return int(value)
    return None
