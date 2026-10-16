"""SentinelOne hunt connector: executes OpenCTI hunts as Singularity Data Lake PowerQueries."""

from collections.abc import Sequence
from typing import Any

from connectors_sdk import InternalHuntConnector
from connectors_sdk.connectors.internal_hunt import (
    DEFAULT_ENTITY_FIELDS,
    DEFAULT_HIT_FIELDS,
    HitFields,
    HuntEvent,
    HuntLimits,
    HuntResult,
    HuntTimeWindow,
    IocBatch,
    NativeQuery,
    RunDeadline,
    build_pipeline,
    parse_timestamp,
)
from sentinelone_hunt.client import SentinelOneClient
from sentinelone_hunt.lookups import batch_lookup, build_powerquery_lookup
from sentinelone_hunt.powerquery import PIPELINES, PowerQueryBackend
from sentinelone_hunt.settings import ConnectorSettings

MAX_ROWS = 10000
"""Largest number of rows read per query (bounds the ``limit`` of the query)."""

COUNT_COLUMN = "opencti_hit_count"
"""Column of the count query run when a page is full."""

EDR_FILTER = "dataSource.name='SentinelOne' and dataSource.category='security'"
"""Initial filter of the SentinelOne EDR telemetry, recommended by SentinelOne."""

RESULT_COLUMNS: tuple[str, ...] = (
    "timestamp",
    "event.id",
    "event.type",
    "agent.uuid",
    "endpoint.name",
    "src.process.user",
    "src.process.name",
    "src.process.cmdline",
    "src.process.image.path",
    "tgt.process.image.path",
    "tgt.file.path",
    "tgt.file.sha256",
    "dst.ip.address",
    "url.address",
)
"""Columns read from every event of a translated rule or indicator lookup, besides
the fields of its detection: PowerQuery returns the columns it is asked for."""

RAW_FIELDS = frozenset({"message", "event.id", "agent.uuid"})
"""Raw text, event and sensor identifiers, never sampled as evidence."""

HIT_FIELDS = HitFields(
    event_id=("event.id", *DEFAULT_HIT_FIELDS.event_id),
    host=("endpoint.name", *DEFAULT_HIT_FIELDS.host),
    user=("src.process.user", "tgt.process.user", *DEFAULT_HIT_FIELDS.user),
    process=(
        "tgt.process.image.path",
        "src.process.image.path",
        "src.process.name",
        *DEFAULT_HIT_FIELDS.process,
    ),
)
"""Fields of a hit: SentinelOne gives every event its id (``event.id``), the key of its hits."""

DOCUMENTATION_URL = "https://docs.opencti.io/latest/usage/hunt-connectors/#sentinelone"

REQUIRED_PERMISSIONS = (
    (
        "Service user API token",
        "A SentinelOne service user and its API token, sent as a Bearer token to the console of the tenant.",
    ),
    (
        "Read-only role on the accounts or sites to hunt (e.g. Viewer)",
        "Search the events of the Singularity Data Lake with PowerQuery; no write permission is needed.",
    ),
)
"""Least-privilege permissions of the account of the connector, as (name, purpose)."""

ACCESS_DENIED_HINTS = {
    401: "SentinelOne refused the API token: check SENTINELONE_HUNT_API_TOKEN, that it is not expired or revoked, and that SENTINELONE_HUNT_API_URL is the console of its tenant",
    403: "the service user needs a role that can search events on the accounts or sites to hunt, and access to every account of SENTINELONE_HUNT_ACCOUNT_IDS",
}
"""What a refused account lacks, by HTTP status."""


def strip_statement_end(query: str) -> str:
    """Remove the trailing pipes and blanks of a PowerQuery."""
    return query.strip().rstrip("|").rstrip()


def event_time(value: Any) -> Any:
    """Return the time of an event (``timestamp`` is in nanoseconds since the epoch)."""
    if isinstance(value, str) and value.strip().isdigit():
        value = int(value.strip())
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if abs(value) >= 1e17:
            value = value / 1e9
        elif abs(value) >= 1e14:
            value = value / 1e6
    return parse_timestamp(value)


class SentinelOneHuntConnector(InternalHuntConnector):
    """Hunt connector running Sigma and PowerQuery hunts on SentinelOne Singularity."""

    languages = ("powerquery",)
    required_permissions = REQUIRED_PERMISSIONS
    documentation_url = DOCUMENTATION_URL
    query_join = " or "
    evidence_excluded_fields = RAW_FIELDS
    hit_fields = HIT_FIELDS
    ioc_host_fields = ("endpoint.name",)
    entity_fields = (
        *DEFAULT_ENTITY_FIELDS,
        "endpoint.name",
        "src.process.user",
        "tgt.process.user",
        "dst.ip.address",
        "src.ip.address",
    )

    def __init__(self, settings: ConnectorSettings) -> None:
        """Initialize the connector (the helper is created by ``start()``).

        Args:
            settings: The connector settings.
        """
        super().__init__(settings)
        self.s1_config = settings.sentinelone_hunt
        self.client: SentinelOneClient | None = None

    def post_init(self) -> None:
        """Create the Singularity Data Lake query client."""
        config = self.s1_config
        self.client = SentinelOneClient(
            base_url=str(config.api_url),
            api_token=config.api_token.get_secret_value(),
            account_ids=config.account_ids,
            verify_ssl=config.verify_ssl,
            poll_interval=config.poll_interval,
            logger=self.logger,
        )
        self.client.access_denied_hints = dict(ACCESS_DENIED_HINTS)

    def connection_test_query(self) -> NativeQuery:
        """Return the test search: one event of the hunted data."""
        query = EDR_FILTER if self.s1_config.edr_only else "dataSource.name = *"
        return NativeQuery(language="powerquery", query=query)

    def sigma_backend(self, pipeline: str | None) -> PowerQueryBackend:
        """Create the pySigma SentinelOne PowerQuery backend.

        Args:
            pipeline: Pipeline requested by the hunt, or ``None`` for the configured one.

        Returns:
            The PowerQuery backend.
        """
        return PowerQueryBackend(
            build_pipeline(pipeline or self.s1_config.sigma_pipeline, PIPELINES)
        )

    def finalize_query(self, query: str, fields: Sequence[str]) -> str:
        """Scope a translated rule or a lookup to the EDR telemetry and name its columns.

        Args:
            query: PowerQuery filter.
            fields: Fields of the detection, read besides ``RESULT_COLUMNS``.

        Returns:
            The PowerQuery executed (and shown in previews).
        """
        if self.s1_config.edr_only:
            query = f"{EDR_FILTER} and ({query})"
        columns = ", ".join(dict.fromkeys((*RESULT_COLUMNS, *fields)))
        return f"{query} | columns {columns}"

    def translate(self, sigma_rule: str, pipeline: str | None) -> NativeQuery:
        """Translate a Sigma rule into the PowerQuery of its events.

        Args:
            sigma_rule: Sigma rule (YAML).
            pipeline: pySigma pipeline requested by the hunt, or ``None``.

        Returns:
            The PowerQuery, restricted to the EDR telemetry when configured.
        """
        native = super().translate(sigma_rule, pipeline)
        return native.model_copy(
            update={"query": self.finalize_query(native.query, native.fields)}
        )

    def ioc_query(self, batch: IocBatch) -> NativeQuery | None:
        """Look up a batch of indicator values in the EDR fields that hold them.

        Args:
            batch: Values of one observable type (and hash algorithm).

        Returns:
            The PowerQuery of the events holding a value, or ``None`` for a type
            no field holds (its values are reported not searched).
        """
        lookup = batch_lookup(batch)
        if lookup is None:
            return None
        return NativeQuery(
            language="powerquery",
            query=self.finalize_query(
                build_powerquery_lookup(batch, lookup), lookup.fields
            ),
            fields=lookup.fields,
        )

    def execute(
        self,
        native_query: NativeQuery,
        time_window: HuntTimeWindow,
        limits: HuntLimits,
        deadline: RunDeadline | None = None,
    ) -> HuntResult:
        """Run the hunt as a Long Running PowerQuery over the run window.

        The query is capped with ``limit``; the total hit count is read with
        ``group count()`` only when the cap is reached. A query restricted to
        the EDR telemetry has its field names checked against the EDR schema.

        Args:
            native_query: PowerQuery.
            time_window: Time window of the run.
            limits: Run limits.
            deadline: Run deadline shared with the SDK (started from the
                limits on direct calls).

        Returns:
            The hunt results.
        """
        if self.client is None:
            raise RuntimeError("The SentinelOne client is created by start().")
        deadline = deadline or RunDeadline(limits.timeout_seconds)
        query = strip_statement_end(native_query.query)
        edr_schema = query.startswith(EDR_FILTER)
        cap = min(limits.max_results, MAX_ROWS)
        start, end = time_window.start, time_window.end
        job_key = id(native_query)
        result = self.client.query(
            f"{query} | limit {cap}", start, end, deadline, job_key, edr_schema
        )
        total = len(result.rows)
        truncated = False
        queries = 1
        if total >= cap:
            queries = 2
            counted = self.client.query(
                f"{query} | group {COUNT_COLUMN} = count()",
                start,
                end,
                deadline,
                job_key,
                edr_schema,
            )
            counted_total = _count(counted.rows)
            # A full page without a usable count (missing, not a number or below
            # the page size) cannot prove that every match was returned: the
            # page size is kept as a lower bound.
            count_unknown = counted_total is None or counted_total < total
            total = max(total, counted_total or 0)
            truncated = count_unknown or total > len(result.rows)
        events = []
        for row in result.rows:
            fields = {name: value for name, value in row.items() if value is not None}
            events.append(
                HuntEvent(timestamp=event_time(fields.get("timestamp")), fields=fields)
            )
        return HuntResult(
            events=events,
            total_hits=total,
            truncated=truncated,
            queries_count=queries,
        )

    def on_timeout(self, native_query: NativeQuery) -> None:
        """Delete the query of a timed out run.

        Args:
            native_query: Query that timed out.
        """
        if self.client is not None:
            self.client.cancel(id(native_query))


def _count(rows: list[dict[str, Any]]) -> int | None:
    """Read the result of a ``group count()`` query, None when it is unusable."""
    value = rows[0].get(COUNT_COLUMN) if rows else None
    if isinstance(value, bool):
        return None
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    if isinstance(value, (int, float)):
        return int(value)
    return None
