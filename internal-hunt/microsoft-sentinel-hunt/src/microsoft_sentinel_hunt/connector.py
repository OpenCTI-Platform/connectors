"""Microsoft Sentinel hunt connector: executes OpenCTI hunts as KQL queries."""

from collections.abc import Callable, Sequence
from typing import Any

from azure.core.credentials import TokenCredential
from azure.identity import ClientSecretCredential, DefaultAzureCredential
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
from microsoft_sentinel_hunt.client import LogAnalyticsClient, TokenRequestTransport
from microsoft_sentinel_hunt.settings import ConnectorSettings
from sigma.backends.kusto import KustoBackend
from sigma.pipelines.azuremonitor import azure_monitor_pipeline
from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
from sigma.pipelines.sentinelasim import sentinel_asim_pipeline
from sigma.processing.pipeline import ProcessingPipeline

SIGMA_PIPELINES: dict[str, Callable[[], ProcessingPipeline]] = {
    "sentinel_asim": sentinel_asim_pipeline,
    "azure_monitor": azure_monitor_pipeline,
    "microsoft_xdr": microsoft_xdr_pipeline,
}
"""pySigma pipelines selectable in the configuration or by a hunt native query."""

TIME_COLUMNS: tuple[str, ...] = (
    "TimeGenerated",
    "Timestamp",
    "EventStartTime",
    "TimeCreated",
)
"""Columns holding the event time, by order of preference."""

RAW_COLUMNS = frozenset(
    {
        "EventData",
        "RawEventData",
        "AdditionalFields",
        "AdditionalExtensions",
        "EventOriginalPayload",
        "Message",
        "SyslogMessage",
        "RenderedDescription",
    }
)
"""Columns holding raw payloads: never decoded nor sampled as evidence."""

BOOKKEEPING_COLUMNS = frozenset(
    {
        "TenantId",
        "_ResourceId",
        "_SubscriptionId",
        "_ItemId",
        "_Internal_WorkspaceResourceId",
        "_BilledSize",
        "_IsBillable",
        "Type",
        "SourceSystem",
        "MG",
        "ManagementGroupName",
        "ReportId",
    }
)
"""Log Analytics bookkeeping columns, never sampled as evidence."""


def strip_statement_end(query: str) -> str:
    """Remove the trailing semicolons and blanks of a KQL query."""
    return query.strip().rstrip(";").rstrip()


class MicrosoftSentinelHuntConnector(InternalHuntConnector):
    """Hunt connector running Sigma and KQL hunts on Microsoft Sentinel."""

    languages = ("kql",)
    evidence_excluded_fields = RAW_COLUMNS | BOOKKEEPING_COLUMNS
    entity_fields = (
        *DEFAULT_ENTITY_FIELDS,
        "TargetHostname",
        "AccountUpn",
        "InitiatingProcessAccountName",
        "InitiatingProcessAccountUpn",
        "LocalIP",
        "SrcUsername",
        "DstUsername",
    )

    def __init__(self, settings: ConnectorSettings) -> None:
        """Initialize the connector (the helper is created by ``start()``).

        Args:
            settings: The connector settings.
        """
        super().__init__(settings)
        self.sentinel_config = settings.microsoft_sentinel_hunt
        self.client: LogAnalyticsClient | None = None

    def build_credential(self, transport: TokenRequestTransport) -> TokenCredential:
        """Create the Azure credential of the configured authentication method.

        Args:
            transport: Transport of the token requests, bounded by the run deadline.
        """
        config = self.sentinel_config
        if config.auth_type == "azure_credential":
            return DefaultAzureCredential(
                authority=config.authority_host, transport=transport
            )
        return ClientSecretCredential(
            tenant_id=str(config.tenant_id),
            client_id=str(config.client_id),
            client_secret=(
                config.client_secret.get_secret_value() if config.client_secret else ""
            ),
            authority=config.authority_host,
            transport=transport,
        )

    def post_init(self) -> None:
        """Create the Log Analytics query API client."""
        config = self.sentinel_config
        transport = TokenRequestTransport()
        self.client = LogAnalyticsClient(
            api_url=str(config.api_url),
            workspace_id=config.workspace_id,
            credential=self.build_credential(transport),
            additional_workspaces=list(config.additional_workspaces),
            raw_columns=RAW_COLUMNS,
            token_transport=transport,
        )

    def sigma_backend(self, pipeline: str | None) -> KustoBackend:
        """Create the pySigma Kusto backend.

        Args:
            pipeline: Pipeline requested by the hunt, or ``None`` for the configured one.

        Returns:
            The Kusto backend.
        """
        return KustoBackend(
            build_pipeline(
                pipeline or self.sentinel_config.sigma_pipeline, SIGMA_PIPELINES
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

    def execute(
        self,
        native_query: NativeQuery,
        time_window: HuntTimeWindow,
        limits: HuntLimits,
        deadline: RunDeadline | None = None,
    ) -> HuntResult:
        """Run the hunt on the Log Analytics workspace.

        The query is restricted to the run window with the API ``timespan`` and
        capped with ``take``; the total hit count is read with ``count`` only
        when the cap is reached.

        Args:
            native_query: KQL query.
            time_window: Time window of the run.
            limits: Run limits.
            deadline: Run deadline shared with the SDK (started from the
                limits on direct calls).

        Returns:
            The hunt results.
        """
        if self.client is None:
            raise RuntimeError("The Log Analytics client is created by start().")
        deadline = deadline or RunDeadline(limits.timeout_seconds)
        query = strip_statement_end(native_query.query)
        result = self.client.query(
            f"{query}\n| take {limits.max_results}",
            time_window.start,
            time_window.end,
            deadline,
        )
        total = len(result.rows)
        truncated = result.partial_error is not None
        if result.partial_error:
            self.logger.warning(
                "[SENTINEL] Partial query results",
                {"error": result.partial_error},
            )
        if total >= limits.max_results:
            counted = self.client.query(
                f"{query}\n| count", time_window.start, time_window.end, deadline
            )
            total = max(total, _count(counted.rows))
            truncated = truncated or total > len(result.rows)
        events = [
            HuntEvent(timestamp=_event_time(row), fields=flatten_fields(row))
            for row in result.rows
        ]
        return HuntResult(events=events, total_hits=total, truncated=truncated)


def _event_time(row: dict[str, Any]) -> Any:
    """Return the event time of a row from the first time column present."""
    for column in TIME_COLUMNS:
        timestamp = parse_timestamp(row.get(column))
        if timestamp is not None:
            return timestamp
    return None


def _count(rows: list[dict[str, Any]]) -> int:
    """Read the result of a ``count`` query."""
    if not rows:
        return 0
    value = rows[0].get("Count")
    return int(value) if isinstance(value, (int, float)) else 0
