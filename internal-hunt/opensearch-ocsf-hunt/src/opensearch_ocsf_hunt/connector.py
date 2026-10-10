"""OpenSearch OCSF hunt connector: executes OpenCTI hunts in PPL or Lucene."""

from collections.abc import Sequence

from connectors_sdk import InternalHuntConnector
from connectors_sdk.connectors.internal_hunt import (
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
from opensearch_ocsf_hunt.client import OpenSearchClient, SearchResult
from opensearch_ocsf_hunt.settings import ConnectorSettings
from sigma.backends.opensearch import OpensearchLuceneBackend, OpenSearchPPLBackend
from sigma.conversion.base import Backend
from sigma.pipelines.ocsf import ocsf_pipeline

SIGMA_PIPELINES = {"ocsf": ocsf_pipeline}
"""pySigma pipelines the connector supports, by name."""

RAW_FIELDS = frozenset(
    {
        "raw_data",
        "message",
        "_id",
        "_index",
        "_score",
        "metadata.uid",
        "metadata.version",
        "metadata.log_name",
        "metadata.product.version",
        "metadata.processed_time",
        "metadata.logged_time",
    }
)
"""Raw payload and bookkeeping fields, never sampled as evidence."""


def strip_statement_end(query: str) -> str:
    """Remove the trailing semicolons and blanks of a query."""
    return query.strip().rstrip(";").rstrip()


DOCUMENTATION_URL = (
    "https://docs.opencti.io/latest/usage/hunt-connectors/#opensearch-ocsf"
)

REQUIRED_PERMISSIONS = (
    (
        "cluster:admin/opensearch/ppl",
        "Cluster permission: run the PPL queries of the hunts (not needed with opensearch-lucene only).",
    ),
    (
        "read on OPENSEARCH_OCSF_HUNT_INDICES",
        "Index permission: search the OCSF events.",
    ),
    (
        "indices:admin/mappings/get on OPENSEARCH_OCSF_HUNT_INDICES",
        "Index permission: PPL reads the index mappings to resolve the fields.",
    ),
)
"""Least-privilege permissions of the account of the connector, as (name, purpose)."""

ACCESS_DENIED_HINTS = {
    401: "OpenSearch refused the user name and password: check OPENSEARCH_OCSF_HUNT_USERNAME and OPENSEARCH_OCSF_HUNT_PASSWORD, an internal user of the security plugin",
    403: "the role mapped to the user needs cluster:admin/opensearch/ppl, and read and indices:admin/mappings/get on OPENSEARCH_OCSF_HUNT_INDICES",
}
"""What a refused account lacks, by HTTP status."""


class OpenSearchOcsfHuntConnector(InternalHuntConnector):
    """Hunt connector running Sigma, PPL and Lucene hunts on OCSF events in OpenSearch."""

    languages = ("ppl", "opensearch-lucene")
    required_permissions = REQUIRED_PERMISSIONS
    documentation_url = DOCUMENTATION_URL
    evidence_excluded_fields = RAW_FIELDS

    def __init__(self, settings: ConnectorSettings) -> None:
        """Initialize the connector (the helper is created by ``start()``).

        Args:
            settings: The connector settings.
        """
        super().__init__(settings)
        self.opensearch_config = settings.opensearch_ocsf_hunt
        self.client: OpenSearchClient | None = None

    def post_init(self) -> None:
        """Create the OpenSearch client."""
        config = self.opensearch_config
        self.client = OpenSearchClient(
            base_url=str(config.url),
            username=config.username,
            password=config.password.get_secret_value() if config.password else None,
            verify_ssl=config.verify_ssl,
            ca_cert=config.ca_cert,
            timestamp_field=config.timestamp_field,
            timestamp_format=config.timestamp_format,
        )
        self.client.access_denied_hints = dict(ACCESS_DENIED_HINTS)

    def connection_test_query(self) -> NativeQuery:
        """Return the test search: one event of the hunted indices."""
        return NativeQuery(language="opensearch-lucene", query="*")

    def sigma_backend(self, pipeline: str | None) -> Backend:
        """Create the pySigma backend of the configured query language.

        Args:
            pipeline: Pipeline requested by the hunt, or ``None`` for the configured one.

        Returns:
            The PPL or Lucene backend, searching the configured indices.
        """
        config = self.opensearch_config
        processing = build_pipeline(pipeline or config.sigma_pipeline, SIGMA_PIPELINES)
        if config.query_language == "opensearch-lucene":
            return OpensearchLuceneBackend(processing, index_names=list(config.indices))
        return OpenSearchPPLBackend(
            processing, custom_logsource=",".join(config.indices)
        )

    def translate(self, sigma_rule: str, pipeline: str | None) -> NativeQuery:
        """Translate the Sigma rule of a hunt into the configured query language.

        Args:
            sigma_rule: Sigma rule (YAML).
            pipeline: pySigma pipeline requested by the hunt, or ``None``.

        Returns:
            The translated query.
        """
        query = super().translate(sigma_rule, pipeline)
        return query.model_copy(
            update={"language": self.opensearch_config.query_language}
        )

    def combine_queries(self, queries: Sequence[str]) -> str:
        """Join several Lucene queries with ``OR`` (PPL queries cannot be joined).

        Args:
            queries: Queries produced by the pySigma backend.

        Returns:
            A single query.
        """
        if (
            len(queries) > 1
            and self.opensearch_config.query_language == "opensearch-lucene"
        ):
            return " OR ".join(f"({query})" for query in queries)
        return super().combine_queries(queries)

    def execute(
        self,
        native_query: NativeQuery,
        time_window: HuntTimeWindow,
        limits: HuntLimits,
        deadline: RunDeadline | None = None,
    ) -> HuntResult:
        """Run the hunt on OpenSearch, restricted to the run window.

        Args:
            native_query: PPL or Lucene query.
            time_window: Time window of the run.
            limits: Run limits.
            deadline: Run deadline shared with the SDK (started from the
                limits on direct calls).

        Returns:
            The hunt results.
        """
        if self.client is None:
            raise RuntimeError("The OpenSearch client is created by start().")
        deadline = deadline or RunDeadline(limits.timeout_seconds)
        query = strip_statement_end(native_query.query)
        start, end = time_window.start, time_window.end
        result: SearchResult
        if native_query.language == "ppl":
            result = self.client.ppl(query, start, end, limits.max_results, deadline)
        else:
            result = self.client.lucene(
                list(self.opensearch_config.indices),
                query,
                start,
                end,
                limits.max_results,
                deadline,
            )
        if result.partial:
            self.logger.warning(
                "[OPENSEARCH] Partial search results",
                {"language": native_query.language, "total": result.total},
            )
        timestamp_field = self.opensearch_config.timestamp_field
        events = []
        for row in result.rows:
            fields = flatten_fields(row)
            events.append(
                HuntEvent(
                    timestamp=parse_timestamp(fields.get(timestamp_field)),
                    fields=fields,
                )
            )
        return HuntResult(
            events=events,
            total_hits=result.total,
            truncated=result.partial or result.total > len(events),
        )
