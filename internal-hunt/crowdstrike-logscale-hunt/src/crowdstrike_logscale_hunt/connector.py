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


class CrowdstrikeLogscaleHuntConnector(InternalHuntConnector):
    """Hunt connector running Sigma and LogScale hunts on CrowdStrike Falcon and LogScale."""

    languages = ("logscale",)
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
    ) -> HuntResult:
        """Run the hunt as a LogScale query job over the run window.

        The query is capped with ``tail``; the total hit count is read with
        ``count()`` only when the cap is reached.

        Args:
            native_query: LogScale query.
            time_window: Time window of the run.
            limits: Run limits.

        Returns:
            The hunt results.
        """
        if self.client is None:
            raise RuntimeError("The LogScale client is created by start().")
        deadline = RunDeadline(limits.timeout_seconds)
        query = strip_statement_end(native_query.query)
        cap = min(limits.max_results, MAX_EVENTS)
        start, end = time_window.start, time_window.end
        job_key = id(native_query)
        result = self.client.query(
            f"{query}\n| tail(limit={cap})", start, end, deadline, job_key
        )
        if result.warnings:
            self.logger.warning(
                "[LOGSCALE] Query warnings", {"warnings": result.warnings[:5]}
            )
        total = len(result.events)
        if total >= cap:
            counted = self.client.query(
                f"{query}\n| count()", start, end, deadline, job_key
            )
            total = max(total, _count(counted.events))
        events = []
        for raw in result.events:
            fields = flatten_fields(raw)
            events.append(HuntEvent(timestamp=_event_time(fields), fields=fields))
        return HuntResult(
            events=events,
            total_hits=total,
            truncated=total > len(events),
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


def _count(events: list[dict[str, Any]]) -> int:
    """Read the result of a ``count()`` query."""
    value = events[0].get(COUNT_FIELD) if events else None
    if isinstance(value, str) and value.strip().isdigit():
        return int(value)
    return int(value) if isinstance(value, (int, float)) else 0
