"""Google SecOps hunt connector: executes OpenCTI hunts as UDM searches or YARA-L rules."""

from collections.abc import Sequence
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
from google.oauth2 import service_account
from google_secops_hunt.client import Credentials, SearchResult, SecOpsClient
from google_secops_hunt.settings import ConnectorSettings
from sigma.backends.secops import SecOpsBackend
from sigma.pipelines.secops import secops_udm_pipeline

SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]

SIGMA_PIPELINES = {"secops_udm": secops_udm_pipeline}
"""pySigma pipelines selectable in the configuration or by a hunt native query."""

TIME_FIELDS: tuple[str, ...] = ("metadata.event_timestamp", "detectionTime")
"""Fields holding the event time, by order of preference."""

BOOKKEEPING_FIELDS = frozenset(
    {
        "name",
        "metadata.id",
        "metadata.product_log_id",
        "metadata.ingested_timestamp",
        "metadata.collected_timestamp",
        "metadata.base_labels.log_types",
        "metadata.enrichment_state",
    }
)
"""UDM bookkeeping fields, never sampled as evidence."""


class GoogleSecopsHuntConnector(InternalHuntConnector):
    """Hunt connector running Sigma, UDM search and YARA-L hunts on Google SecOps."""

    languages = ("udm", "yara-l")
    evidence_excluded_fields = BOOKKEEPING_FIELDS
    entity_fields = (
        *DEFAULT_ENTITY_FIELDS,
        "principal.user.userid",
        "target.user.userid",
        "principal.asset.hostname",
        "target.asset.hostname",
    )

    def __init__(self, settings: ConnectorSettings) -> None:
        """Initialize the connector (the helper is created by ``start()``).

        Args:
            settings: The connector settings.
        """
        super().__init__(settings)
        self.secops_config = settings.google_secops_hunt
        self.sigma_output_format = (
            "yara_l" if self.secops_config.query_language == "yara-l" else None
        )
        self.client: SecOpsClient | None = None

    def build_credentials(self) -> Credentials:
        """Create the service account credentials of the Chronicle API."""
        config = self.secops_config
        info = {
            "type": "service_account",
            "project_id": config.project_id,
            "private_key": config.private_key.get_secret_value(),
            "private_key_id": config.private_key_id,
            "client_email": config.client_email,
            "client_id": config.client_id,
            "auth_uri": config.auth_uri,
            "token_uri": config.token_uri,
            "auth_provider_x509_cert_url": config.auth_provider_cert,
            "client_x509_cert_url": config.client_cert_url,
        }
        credentials: Credentials = (
            service_account.Credentials.from_service_account_info(info, scopes=SCOPES)
        )
        return credentials

    def post_init(self) -> None:
        """Create the Chronicle API client."""
        config = self.secops_config
        self.client = SecOpsClient(
            base_url=str(config.base_url),
            project_id=config.project_id,
            region=config.project_region,
            instance=config.project_instance,
            credentials=self.build_credentials(),
        )

    def sigma_backend(self, pipeline: str | None) -> SecOpsBackend:
        """Create the pySigma SecOps backend.

        Args:
            pipeline: Pipeline requested by the hunt, or ``None`` for the configured one.

        Returns:
            The SecOps backend.
        """
        return SecOpsBackend(
            build_pipeline(
                pipeline or self.secops_config.sigma_pipeline, SIGMA_PIPELINES
            )
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
        return query.model_copy(update={"language": self.secops_config.query_language})

    def combine_queries(self, queries: Sequence[str]) -> str:
        """Join several UDM searches with ``OR`` (YARA-L rules cannot be joined).

        Args:
            queries: Queries produced by the pySigma backend.

        Returns:
            A single query.
        """
        if len(queries) > 1 and self.secops_config.query_language == "udm":
            return " OR ".join(f"({query})" for query in queries)
        return super().combine_queries(queries)

    def execute(
        self,
        native_query: NativeQuery,
        time_window: HuntTimeWindow,
        limits: HuntLimits,
    ) -> HuntResult:
        """Run the hunt as a UDM search or a YARA-L rule test over the run window.

        Args:
            native_query: UDM search query or YARA-L rule.
            time_window: Time window of the run.
            limits: Run limits.

        Returns:
            The hunt results.
        """
        if self.client is None:
            raise RuntimeError("The Chronicle API client is created by start().")
        deadline = RunDeadline(limits.timeout_seconds)
        query = native_query.query.strip()
        result: SearchResult
        if native_query.language == "yara-l":
            result = self.client.run_rule(
                query, time_window.start, time_window.end, limits.max_results, deadline
            )
        else:
            result = self.client.udm_search(
                query, time_window.start, time_window.end, limits.max_results, deadline
            )
        events = []
        for raw in result.events:
            fields = flatten_fields(raw)
            events.append(HuntEvent(timestamp=_event_time(fields), fields=fields))
        return HuntResult(
            events=events,
            total_hits=max(len(events), result.detections or 0),
            truncated=result.truncated,
        )


def _event_time(fields: dict[str, Any]) -> Any:
    """Return the event time from the first time field present."""
    for name in TIME_FIELDS:
        timestamp = parse_timestamp(fields.get(name))
        if timestamp is not None:
            return timestamp
    return None
