"""Splunk hunt connector: executes OpenCTI hunts as Splunk search jobs."""

import re
from collections.abc import Sequence

from connectors_sdk import InternalHuntConnector
from connectors_sdk.connectors.internal_hunt import (
    HuntEvent,
    HuntExecutionError,
    HuntLimits,
    HuntResult,
    HuntTimeWindow,
    HuntTranslationError,
    NativeQuery,
    RunDeadline,
    build_pipeline,
    parse_timestamp,
)
from sigma.backends.splunk import SplunkBackend
from sigma.pipelines.splunk import pipelines as splunk_pipelines
from splunk_hunt.client import SplunkClient
from splunk_hunt.settings import ConnectorSettings

SPLUNK_INTERNAL_FIELDS = frozenset(
    {
        "_raw",
        "_time",
        "_cd",
        "_bkt",
        "_si",
        "_serial",
        "_indextime",
        "_kv",
        "_eventtype_color",
        "_sourcetype",
        "punct",
        "linecount",
        "splunk_server",
        "splunk_server_group",
        "timestartpos",
        "timeendpos",
        "date_hour",
        "date_mday",
        "date_minute",
        "date_month",
        "date_second",
        "date_wday",
        "date_year",
        "date_zone",
    }
)
"""Raw event and Splunk bookkeeping fields, never sampled as evidence."""

TSTATS_RE = re.compile(r"^\|\s*tstats\b", re.IGNORECASE)


def split_first_pipe(query: str) -> tuple[str, str]:
    """Split an SPL query at its first pipe outside quotes.

    Args:
        query: SPL query.

    Returns:
        The search part and the rest of the pipeline (starting with ``|``, or empty).
    """
    quote: str | None = None
    escaped = False
    for index, char in enumerate(query):
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif quote:
            if char == quote:
                quote = None
        elif char in ("'", '"'):
            quote = char
        elif char == "|":
            return query[:index].strip(), query[index:].strip()
    return query.strip(), ""


def find_keyword(segment: str, keyword: str, start: int = 0) -> tuple[int, int] | None:
    """Find a whole-word SPL keyword outside quotes.

    Args:
        segment: One SPL command.
        keyword: Lowercase keyword (e.g. ``where``).
        start: Index the search starts from.

    Returns:
        The start and end index of the first match, or ``None``.
    """
    lowered = segment.lower()
    quote: str | None = None
    escaped = False
    for index in range(start, len(segment)):
        char = segment[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif quote:
            if char == quote:
                quote = None
        elif char in ("'", '"'):
            quote = char
        elif lowered.startswith(keyword, index):
            end = index + len(keyword)
            if (index == 0 or segment[index - 1].isspace()) and (
                end == len(segment) or segment[end].isspace()
            ):
                return index, end
    return None


def constrain_tstats(search: str, search_prefix: str) -> str:
    """Add the search prefix to the ``where`` clause of a ``| tstats`` search.

    The prefix is ANDed with the existing condition, both parenthesized, and
    stays before the ``by`` clause; a search without condition gets one.

    Args:
        search: A search starting with ``| tstats``.
        search_prefix: Connector-wide constraint (e.g. ``index=wineventlog``).

    Returns:
        The constrained search.
    """
    command, rest = split_first_pipe(search.strip()[1:])
    prefix = f"({search_prefix.strip()})"
    where = find_keyword(command, "where")
    by = find_keyword(command, "by", where[1] if where else 0)
    clause_end = by[0] if by else len(command)
    if where:
        condition = command[where[1] : clause_end].strip()
        head = command[: where[1]]
        constrained = (
            f"{head} {prefix} AND ({condition})" if condition else f"{head} {prefix}"
        )
    else:
        constrained = f"{command[:clause_end].rstrip()} where {prefix}"
    tail = command[clause_end:].strip()
    constrained = f"| {constrained} {tail}" if tail else f"| {constrained}"
    return f"{constrained} {rest}" if rest else constrained


def build_search(query: str, search_prefix: str) -> str:
    """Build the SPL search of a hunt query.

    Plain queries get the ``search`` command and the configured prefix
    constraint, both parenthesized so that their ``OR`` operators keep their
    meaning. Generating commands (queries starting with ``|``) run as written
    when no prefix is configured; with a prefix, a ``| tstats`` search gets it
    in its ``where`` clause and any other generating command is refused, so no
    query ever runs outside the configured scope.

    Args:
        query: Hunt query (translated or native).
        search_prefix: Connector-wide constraint (e.g. ``index=wineventlog``).

    Returns:
        The SPL search to run.

    Raises:
        HuntExecutionError: A prefix is configured and the query is a
            generating command it cannot constrain.
    """
    text = query.strip()
    if text.startswith("|"):
        if not search_prefix.strip():
            return text
        if TSTATS_RE.match(text):
            return constrain_tstats(text, search_prefix)
        command = text[1:].split(maxsplit=1)[0] if text[1:].strip() else ""
        raise HuntExecutionError(
            f"The search prefix cannot constrain the generating command '| {command}': "
            "the query is refused instead of running outside the configured scope "
            "(with a search prefix, only plain searches and '| tstats' searches run)."
        )
    if text.lower().startswith("search "):
        text = text[len("search ") :].strip()
    base, rest = split_first_pipe(text)
    terms = [f"({search_prefix.strip()})"] if search_prefix.strip() else []
    if base:
        terms.append(f"({base})")
    search = " ".join(["search", *terms])
    return f"{search} {rest}" if rest else search


class SplunkHuntConnector(InternalHuntConnector):
    """Hunt connector running Sigma and SPL hunts on Splunk."""

    languages = ("spl",)
    evidence_excluded_fields = SPLUNK_INTERNAL_FIELDS

    def __init__(self, settings: ConnectorSettings) -> None:
        """Initialize the connector (the helper is created by ``start()``).

        Args:
            settings: The connector settings.
        """
        super().__init__(settings)
        self.splunk_config = settings.splunk_hunt
        self.sigma_output_format = (
            None
            if self.splunk_config.output_format == "default"
            else self.splunk_config.output_format
        )
        self.client: SplunkClient | None = None

    def post_init(self) -> None:
        """Create the Splunk REST API client."""
        config = self.splunk_config
        self.client = SplunkClient(
            base_url=str(config.url),
            token=config.token.get_secret_value() if config.token else None,
            username=config.username,
            password=config.password.get_secret_value() if config.password else None,
            verify_ssl=config.verify_ssl,
            app=config.app,
            owner=config.owner,
            poll_interval=config.poll_interval,
            logger=self.logger,
        )

    def sigma_backend(self, pipeline: str | None) -> SplunkBackend:
        """Create the pySigma Splunk backend.

        Args:
            pipeline: Pipeline requested by the hunt, or ``None`` for the configured one.

        Returns:
            The Splunk backend.
        """
        return SplunkBackend(
            build_pipeline(
                pipeline or self.splunk_config.sigma_pipeline, splunk_pipelines
            )
        )

    def combine_queries(self, queries: Sequence[str]) -> str:
        """Join several plain searches with ``OR`` (generating commands cannot be joined).

        Args:
            queries: Queries produced by the pySigma backend.

        Returns:
            A single query.
        """
        if len(queries) > 1 and all("|" not in query for query in queries):
            return " OR ".join(f"({query})" for query in queries)
        if len(queries) > 1:
            raise HuntTranslationError(
                f"The Sigma rule translated into {len(queries)} Splunk pipelines, "
                "which cannot be combined into one search."
            )
        return super().combine_queries(queries)

    def execute(
        self,
        native_query: NativeQuery,
        time_window: HuntTimeWindow,
        limits: HuntLimits,
        deadline: RunDeadline | None = None,
    ) -> HuntResult:
        """Run the hunt as a Splunk search job.

        Args:
            native_query: SPL query.
            time_window: Time window of the run.
            limits: Run limits.
            deadline: Run deadline shared with the SDK (started from the
                limits on direct calls).

        Returns:
            The hunt results.
        """
        if self.client is None:
            raise RuntimeError("The Splunk client is created by start().")
        deadline = deadline or RunDeadline(limits.timeout_seconds)
        total, rows = self.client.search(
            build_search(native_query.query, self.splunk_config.search_prefix),
            time_window.start,
            time_window.end,
            limits.max_results,
            deadline,
            id(native_query),
        )
        events = [
            HuntEvent(timestamp=parse_timestamp(row.get("_time")), fields=row)
            for row in rows
        ]
        return HuntResult(
            events=events, total_hits=total, truncated=total > len(events)
        )

    def on_timeout(self, native_query: NativeQuery) -> None:
        """Cancel the Splunk search job of a timed out run.

        Args:
            native_query: Query that timed out.
        """
        if self.client is not None:
            self.client.cancel(id(native_query))
