"""Microsoft Defender XDR hunt connector: executes OpenCTI hunts as advanced hunting queries."""

import re
from collections.abc import Callable, Sequence
from typing import Any

from connectors_sdk import InternalHuntConnector
from connectors_sdk.connectors.internal_hunt import (
    DEFAULT_ENTITY_FIELDS,
    HitFields,
    HuntEvent,
    HuntLimits,
    HuntRequest,
    HuntResult,
    HuntSigmaRule,
    HuntTimeWindow,
    IocBatch,
    NativeQuery,
    RunDeadline,
    batch_iocs,
    build_pipeline,
    flatten_fields,
    parse_timestamp,
)
from microsoft_defender_hunt.client import (
    DefenderHuntingClient,
    EntraTokenClient,
    timespan,
)
from microsoft_defender_hunt.lookups import (
    SOURCE_TABLE_COLUMN,
    batch_lookups,
    build_kql_lookup,
    time_filter,
)
from microsoft_defender_hunt.settings import ConnectorSettings
from sigma.backends.kusto import KustoBackend
from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
from sigma.pipelines.microsoftxdr.tables import MICROSOFT_XDR_TABLES
from sigma.processing.pipeline import ProcessingPipeline

SIGMA_PIPELINES: dict[str, Callable[[], ProcessingPipeline]] = {
    "microsoft_xdr": microsoft_xdr_pipeline,
}
"""pySigma pipelines selectable in the configuration or by a hunt native query."""

MAX_ROWS = 10_000
"""Most rows read from one query, whatever ``max_results``: the result limit of the
advanced hunting portal, which bounds the memory of a run."""

TIME_COLUMNS: tuple[str, ...] = ("Timestamp", "TimeGenerated")
"""Columns holding the event time, by order of preference."""

EVENT_ID_FIELD = "HuntEventId"
"""Field the connector adds to each event: the id of the event in advanced hunting."""

EVENT_SCOPE_COLUMNS: tuple[str, ...] = (
    "DeviceId",
    "NetworkMessageId",
    "RecipientEmailAddress",
)
"""Columns scoping the ``ReportId`` of an event: its device, or its message and recipient."""

REPORT_ID_COLUMNS: tuple[str, ...] = ("ReportId", "ReportId_string", "ReportId_long")
"""Columns holding the ``ReportId`` of an event: a union of tables typing it as a
long and as a string splits it in two."""

RAW_COLUMNS = frozenset({"AdditionalFields", "RawEventData", "Data"})
"""Columns holding raw payloads: never decoded nor sampled as evidence."""

BOOKKEEPING_COLUMNS = frozenset(
    {
        EVENT_ID_FIELD,
        *REPORT_ID_COLUMNS,
        "DeviceId",
        "NetworkMessageId",
        "TenantId",
        "MachineGroup",
        "AppGuardContainerId",
        "SourceSystem",
        "Type",
    }
)
"""Advanced hunting bookkeeping columns, never sampled as evidence: the id of an
event is in the evidence of each hit."""

HOST_COLUMNS: tuple[str, ...] = ("DeviceName",)
"""Columns naming the machine an event happened on. The remote end of an event
(the address or URL reached) is never the machine hunted for."""

HIT_FIELDS = HitFields(
    event_id=(EVENT_ID_FIELD,),
    host=HOST_COLUMNS,
    user=(
        "AccountName",
        "InitiatingProcessAccountName",
        "RecipientEmailAddress",
        "AccountUpn",
        "InitiatingProcessAccountUpn",
    ),
    process=("InitiatingProcessFolderPath", "InitiatingProcessFileName"),
)
"""Columns naming the event id, host, user and process of a hit."""

SCHEMA_COLUMNS = frozenset(
    column.strip() for columns in MICROSOFT_XDR_TABLES.values() for column in columns
) - {"Timestamp", "ReportId", "DeviceId"}
"""Columns of the advanced hunting tables a native query may reference."""

_IDENTIFIER = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")

DOCUMENTATION_URL = (
    "https://docs.opencti.io/latest/usage/hunt-connectors/#microsoft-defender-xdr"
)

REQUIRED_PERMISSIONS = (
    (
        "ThreatHunting.Read.All",
        "Microsoft Graph application permission, with admin consent: run read-only advanced hunting queries.",
    ),
)
"""Least-privilege permissions of the account of the connector, as (name, purpose)."""

ACCESS_DENIED_HINTS = {
    401: "Microsoft Graph refused the access token of the app registration: check MICROSOFT_DEFENDER_HUNT_TENANT_ID and that the app registration lives in the tenant of Microsoft Defender XDR",
    403: "the app registration needs the Microsoft Graph application permission ThreatHunting.Read.All, with admin consent granted (Microsoft Entra ID > App registrations > API permissions)",
}
"""What a refused account lacks, by HTTP status."""


def strip_statement_end(query: str) -> str:
    """Remove the trailing semicolons and blanks of a KQL query."""
    return query.strip().rstrip(";").rstrip()


def event_id(row: dict[str, Any]) -> str | None:
    """Return the id of the event of a row: its ``ReportId`` within its device or message, and its time.

    ``ReportId`` alone repeats across devices: Microsoft documents it as unique
    together with the device and the time of the event.

    Args:
        row: Row of an advanced hunting answer.

    Returns:
        The id, None for a row without ``ReportId`` (an aggregation).
    """
    report = next(
        (
            row[column]
            for column in REPORT_ID_COLUMNS
            if row.get(column) is not None and str(row[column]).strip() != ""
        ),
        None,
    )
    if report is None:
        return None
    parts = [
        str(row[column])
        for column in EVENT_SCOPE_COLUMNS
        if row.get(column) not in (None, "")
    ]
    parts.append(str(report))
    parts.append(str(row.get("Timestamp") or ""))
    return "|".join(parts)


class MicrosoftDefenderHuntConnector(InternalHuntConnector):
    """Hunt connector running Sigma, KQL and indicator hunts on Microsoft Defender XDR."""

    languages = ("kql",)
    required_permissions = REQUIRED_PERMISSIONS
    documentation_url = DOCUMENTATION_URL
    evidence_excluded_fields = RAW_COLUMNS | BOOKKEEPING_COLUMNS
    entity_fields = (
        *DEFAULT_ENTITY_FIELDS,
        "InitiatingProcessAccountName",
        "InitiatingProcessAccountUpn",
        "AccountUpn",
        "RecipientEmailAddress",
        "SenderFromAddress",
        "SenderIPv4",
        "SenderIPv6",
        "LocalIP",
        "RemoteDeviceName",
    )
    hit_fields = HIT_FIELDS
    ioc_host_fields = HOST_COLUMNS

    def __init__(self, settings: ConnectorSettings) -> None:
        """Initialize the connector (the helper is created by ``start()``).

        Args:
            settings: The connector settings.
        """
        super().__init__(settings)
        self.defender_config = settings.microsoft_defender_hunt
        self.client: DefenderHuntingClient | None = None

    def post_init(self) -> None:
        """Create the Microsoft Entra token client and the advanced hunting client."""
        config = self.defender_config
        graph_url = str(config.graph_url).rstrip("/")
        tokens = EntraTokenClient(
            login_url=str(config.login_url),
            tenant_id=config.tenant_id,
            client_id=config.client_id,
            client_secret=config.client_secret.get_secret_value(),
            scope=f"{graph_url}/.default",
        )
        self.client = DefenderHuntingClient(graph_url, tokens, RAW_COLUMNS)
        self.client.access_denied_hints = dict(ACCESS_DENIED_HINTS)

    def _require_client(self) -> DefenderHuntingClient:
        if self.client is None:
            raise RuntimeError("The advanced hunting client is created by start().")
        return self.client

    def sigma_backend(self, pipeline: str | None) -> KustoBackend:
        """Create the pySigma Kusto backend.

        Args:
            pipeline: Pipeline requested by the hunt, or ``None`` for the configured one.

        Returns:
            The Kusto backend.
        """
        return KustoBackend(
            build_pipeline(
                pipeline or self.defender_config.sigma_pipeline, SIGMA_PIPELINES
            )
        )

    def combine_queries(self, queries: Sequence[str]) -> str:
        """Combine the KQL queries of several Sigma rules with ``union``.

        Args:
            queries: Queries produced by the pySigma backend.

        Returns:
            A single query.
        """
        if len(queries) > 1:
            return "union " + ", ".join(f"({query})" for query in queries)
        return super().combine_queries(queries)

    def resolve_query(self, request: HuntRequest) -> NativeQuery:
        """Return the query of a run, naming the columns a native query references.

        Args:
            request: The hunt run request.

        Returns:
            The query, with the advanced hunting columns it references.
        """
        return _with_fields(super().resolve_query(request))

    def resolve_rule_query(self, rule: HuntSigmaRule) -> NativeQuery:
        """Return the query of one Sigma rule, naming the columns a native query references.

        Args:
            rule: The rule, with its native query for the platform if any.

        Returns:
            The query, with the advanced hunting columns it references.
        """
        return _with_fields(super().resolve_rule_query(rule))

    def ioc_query(self, batch: IocBatch) -> NativeQuery | None:
        """Look up a batch of indicator values in the tables and columns that hold them.

        Args:
            batch: Values of one observable type (and hash algorithm).

        Returns:
            The advanced hunting query of the events holding a value, or
            ``None`` for a type no column holds (its values are reported not searched).
        """
        return self._lookup(batch, None)

    def plan_ioc_lookups(
        self, request: HuntRequest
    ) -> list[tuple[IocBatch, NativeQuery | None]]:
        """Return the lookups of an indicator hunt run, each filtered on the run window.

        Args:
            request: The hunt run request.

        Returns:
            Each batch with its lookup, ``None`` for a type no column holds.
        """
        return [
            (batch, self._lookup(batch, request.time_window))
            for batch in batch_iocs(request.hunt.iocs, request.limits.ioc_batch_size)
        ]

    def _lookup(
        self, batch: IocBatch, window: HuntTimeWindow | None
    ) -> NativeQuery | None:
        lookups = batch_lookups(batch)
        if lookups is None:
            return None
        return NativeQuery(
            language="kql",
            query=build_kql_lookup(batch, lookups, window),
            fields=tuple(
                dict.fromkeys(column for lookup in lookups for column in lookup.columns)
            ),
        )

    def execute(
        self,
        native_query: NativeQuery,
        time_window: HuntTimeWindow,
        limits: HuntLimits,
        deadline: RunDeadline | None = None,
    ) -> HuntResult:
        """Run the hunt with advanced hunting over the run window.

        The window is the ``Timespan`` of the query, and a translated Sigma rule
        also filters it on ``Timestamp``. The query is capped with ``take`` at
        ``max_results`` (at most ``MAX_ROWS``); the total hit count is read with
        ``count`` only when the cap is reached.

        Args:
            native_query: KQL query.
            time_window: Time window of the run.
            limits: Run limits.
            deadline: Run deadline shared with the SDK (started from the
                limits on direct calls).

        Returns:
            The hunt results.
        """
        client = self._require_client()
        deadline = deadline or RunDeadline(limits.timeout_seconds)
        query = strip_statement_end(native_query.query)
        if native_query.translated:
            query = f"{query}\n| where {time_filter(time_window)}"
        span = timespan(time_window.start, time_window.end)
        cap = min(limits.max_results, MAX_ROWS)
        rows = client.run_query(f"{query}\n| take {cap}", span, deadline).rows
        total = len(rows)
        truncated = False
        if total >= cap:
            counted_total = _count(
                client.run_query(f"{query}\n| count", span, deadline).rows
            )
            # A full page without a usable count (missing, not a number or below
            # the page size) cannot prove that every match was returned: the
            # page size is kept as a lower bound.
            count_unknown = counted_total is None or counted_total < total
            total = max(total, counted_total or 0)
            truncated = count_unknown or total > len(rows)
            self.logger.info(
                "[DEFENDER] Query results capped",
                {"returned": len(rows), "total": total, "truncated": truncated},
            )
        events = [
            HuntEvent(timestamp=_event_time(row), fields=_event_fields(row))
            for row in rows
        ]
        return HuntResult(events=events, total_hits=total, truncated=truncated)


def _with_fields(query: NativeQuery) -> NativeQuery:
    """Name the advanced hunting columns a native query references (a translation names its own)."""
    if query.fields or query.translated:
        return query
    fields = tuple(
        dict.fromkeys(
            name
            for name in _IDENTIFIER.findall(query.query)
            if name in SCHEMA_COLUMNS and name != SOURCE_TABLE_COLUMN
        )
    )
    return query.model_copy(update={"fields": fields})


def _event_fields(row: dict[str, Any]) -> dict[str, Any]:
    """Return the fields of an event: its columns, and its id when it has one."""
    fields = flatten_fields(row)
    identifier = event_id(row)
    if identifier is not None:
        fields[EVENT_ID_FIELD] = identifier
    return fields


def _event_time(row: dict[str, Any]) -> Any:
    """Return the event time of a row from the first time column present."""
    for column in TIME_COLUMNS:
        timestamp = parse_timestamp(row.get(column))
        if timestamp is not None:
            return timestamp
    return None


def _count(rows: list[dict[str, Any]]) -> int | None:
    """Read the result of a ``count`` query, None when it is unusable."""
    value = rows[0].get("Count") if rows else None
    if isinstance(value, str) and value.strip().isdigit():
        return int(value)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return int(value)
    return None
