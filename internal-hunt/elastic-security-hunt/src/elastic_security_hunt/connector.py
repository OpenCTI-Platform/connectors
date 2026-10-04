"""Elastic Security hunt connector: executes OpenCTI hunts in ES|QL, EQL or Lucene."""

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
from elastic_security_hunt.client import ElasticsearchClient, SearchResult
from elastic_security_hunt.settings import ConnectorSettings
from sigma.backends.elasticsearch import EqlBackend, ESQLBackend, LuceneBackend
from sigma.conversion.base import Backend
from sigma.pipelines.elasticsearch import pipelines as elasticsearch_pipelines
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import SetStateTransformation

RAW_FIELDS = frozenset(
    {
        "event.original",
        "log.original",
        "message",
        "_id",
        "_index",
        "_version",
        "_score",
        "@version",
        "ecs.version",
        "agent.id",
        "agent.ephemeral_id",
        "elastic_agent.id",
    }
)
"""Raw payload and bookkeeping fields, never sampled as evidence."""


def strip_statement_end(query: str) -> str:
    """Remove the trailing semicolons and blanks of a query."""
    return query.strip().rstrip(";").rstrip()


DOCUMENTATION_URL = (
    "https://docs.opencti.io/latest/usage/hunt-connectors/#elastic-security"
)

REQUIRED_PERMISSIONS = (
    (
        "read on ELASTIC_SECURITY_HUNT_INDICES",
        "Index privilege: run the ES|QL, EQL and Lucene searches of the hunts on the hunted data.",
    ),
    (
        "view_index_metadata on ELASTIC_SECURITY_HUNT_INDICES",
        "Index privilege: resolve the index patterns and the field mappings.",
    ),
    (
        "read on remote indices",
        "Remote index privilege, only for cross-cluster search: hunt remote:index patterns.",
    ),
)
"""Least-privilege permissions of the account of the connector, as (name, purpose)."""

ACCESS_DENIED_HINTS = {
    401: "Elasticsearch refused the API key (or the user name and password): check the encoded value of ELASTIC_SECURITY_HUNT_API_KEY, and that the key is neither expired nor invalidated",
    403: "the role of the API key needs the read and view_index_metadata index privileges on ELASTIC_SECURITY_HUNT_INDICES",
}
"""What a refused account lacks, by HTTP status."""


class ElasticSecurityHuntConnector(InternalHuntConnector):
    """Hunt connector running Sigma, ES|QL, EQL and Lucene hunts on Elastic Security."""

    languages = ("esql", "eql", "lucene")
    required_permissions = REQUIRED_PERMISSIONS
    documentation_url = DOCUMENTATION_URL
    evidence_excluded_fields = RAW_FIELDS

    def __init__(self, settings: ConnectorSettings) -> None:
        """Initialize the connector (the helper is created by ``start()``).

        Args:
            settings: The connector settings.
        """
        super().__init__(settings)
        self.elastic_config = settings.elastic_security_hunt
        self.client: ElasticsearchClient | None = None

    def post_init(self) -> None:
        """Create the Elasticsearch client."""
        config = self.elastic_config
        self.client = ElasticsearchClient(
            base_url=str(config.url),
            api_key=config.api_key.get_secret_value() if config.api_key else None,
            username=config.username,
            password=config.password.get_secret_value() if config.password else None,
            verify_ssl=config.verify_ssl,
            ca_cert=config.ca_cert,
            timestamp_field=config.timestamp_field,
            logger=self.logger,
        )
        self.client.access_denied_hints = dict(ACCESS_DENIED_HINTS)

    def connection_test_query(self) -> NativeQuery:
        """Return the test search: one event of the hunted indices."""
        return NativeQuery(language="lucene", query="*")

    def sigma_backend(self, pipeline: str | None) -> Backend:
        """Create the pySigma backend of the configured query language.

        Args:
            pipeline: Pipeline requested by the hunt, or ``None`` for the configured one.

        Returns:
            The ES|QL, EQL or Lucene backend.
        """
        config = self.elastic_config
        processing = build_pipeline(
            pipeline or config.sigma_pipeline, elasticsearch_pipelines
        )
        if config.query_language == "eql":
            return EqlBackend(processing)
        if config.query_language == "lucene":
            return LuceneBackend(processing, index_names=list(config.indices))
        index_state = ProcessingPipeline(
            name="OpenCTI hunt indices",
            priority=5,
            items=[
                ProcessingItem(
                    SetStateTransformation("index", ",".join(config.indices))
                )
            ],
        )
        return ESQLBackend(index_state + processing if processing else index_state)

    def translate(self, sigma_rule: str, pipeline: str | None) -> NativeQuery:
        """Translate the Sigma rule of a hunt into the configured query language.

        Args:
            sigma_rule: Sigma rule (YAML).
            pipeline: pySigma pipeline requested by the hunt, or ``None``.

        Returns:
            The translated query.
        """
        query = super().translate(sigma_rule, pipeline)
        return query.model_copy(update={"language": self.elastic_config.query_language})

    def combine_queries(self, queries: Sequence[str]) -> str:
        """Join several Lucene queries with ``OR`` (ES|QL and EQL cannot be joined).

        Args:
            queries: Queries produced by the pySigma backend.

        Returns:
            A single query.
        """
        if len(queries) > 1 and self.elastic_config.query_language == "lucene":
            return " OR ".join(f"({query})" for query in queries)
        return super().combine_queries(queries)

    def execute(
        self,
        native_query: NativeQuery,
        time_window: HuntTimeWindow,
        limits: HuntLimits,
        deadline: RunDeadline | None = None,
    ) -> HuntResult:
        """Run the hunt on Elasticsearch, restricted to the run window.

        Args:
            native_query: ES|QL, EQL or Lucene query.
            time_window: Time window of the run.
            limits: Run limits.
            deadline: Run deadline shared with the SDK (started from the
                limits on direct calls).

        Returns:
            The hunt results.
        """
        if self.client is None:
            raise RuntimeError("The Elasticsearch client is created by start().")
        deadline = deadline or RunDeadline(limits.timeout_seconds)
        query = strip_statement_end(native_query.query)
        indices = list(self.elastic_config.indices)
        start, end = time_window.start, time_window.end
        result: SearchResult
        if native_query.language == "esql":
            result = self.client.esql(
                query, start, end, limits.max_results, deadline, id(native_query)
            )
        elif native_query.language == "eql":
            result = self.client.eql(
                indices,
                query,
                start,
                end,
                limits.max_results,
                deadline,
                id(native_query),
            )
        else:
            result = self.client.lucene(
                indices, query, start, end, limits.max_results, deadline
            )
        if result.partial:
            self.logger.warning(
                "[ELASTIC] Partial search results",
                {"language": native_query.language, "total": result.total},
            )
        timestamp_field = self.elastic_config.timestamp_field
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

    def on_timeout(self, native_query: NativeQuery) -> None:
        """Delete the async search of a timed out run.

        Args:
            native_query: Query that timed out.
        """
        if self.client is not None:
            self.client.cancel(id(native_query))
