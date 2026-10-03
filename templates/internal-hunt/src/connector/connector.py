"""Hunt connector.

`TemplateConnector` is built on `InternalHuntConnector` (from `connectors-sdk`),
which already implements the whole hunt run lifecycle: platform registration,
native query override, preview mode, run timeout and `max_results`, benign
suppression, STIX sightings and observed-data, hashed and truncated evidence,
and the run report. A hunt connector only implements:

    - `languages`: the query languages it executes;
    - `sigma_backend()`: the pySigma backend translating Sigma rules;
    - `execute()`: the query execution on the platform.

TODO:
    - [ ] Set `languages` to the query language(s) of your platform
        (`spl`, `kql`, `esql`, `lucene`, `eql`, `logscale`, `udm`, `ppl`,
        `opensearch-lucene`, `sql`...). The first one is produced by translation.
    - [ ] Replace `TextQueryTestBackend` with the pySigma backend of your platform
        (e.g. `SplunkBackend` from `pysigma-backend-splunk`) and register its
        pipelines in `SIGMA_PIPELINES`.
    - [ ] Map the events returned by your platform in `execute()`: the event time
        and the event fields (flattened with `flatten_fields`).
"""

from datetime import datetime

from connector.settings import ConnectorSettings
from connectors_sdk import InternalHuntConnector
from connectors_sdk.connectors.internal_hunt import (
    HuntEvent,
    HuntLimits,
    HuntResult,
    HuntTimeWindow,
    NativeQuery,
    build_pipeline,
    flatten_fields,
)
from sigma.backends.test import TextQueryTestBackend
from sigma.pipelines.windows import windows_logsource_pipeline
from template_client import TemplateClient

SIGMA_PIPELINES = {
    "windows-logsources": windows_logsource_pipeline,
}
"""pySigma pipelines selectable with `TEMPLATE_SIGMA_PIPELINE` or a hunt native query."""


class TemplateConnector(InternalHuntConnector):
    """Hunt connector executing hunts on the platform search API."""

    languages = ("opensearch-lucene",)
    evidence_excluded_fields = frozenset({"_raw"})

    def __init__(self, settings: ConnectorSettings) -> None:
        """Initialize the connector (the helper is created by `start()`).

        Args:
            settings: The connector settings.
        """
        super().__init__(settings)
        self.template_config = settings.template
        self.client: TemplateClient | None = None

    def post_init(self) -> None:
        """Create the platform API client once the logger exists."""
        self.client = TemplateClient(
            base_url=str(self.template_config.api_base_url),
            api_key=self.template_config.api_key.get_secret_value(),
            verify_ssl=self.template_config.verify_ssl,
            logger=self.logger,
        )

    def sigma_backend(self, pipeline: str | None) -> TextQueryTestBackend:
        """Create the pySigma backend of the platform.

        Args:
            pipeline: Pipeline requested by the hunt, or `None` for the configured one.

        Returns:
            The pySigma backend.
        """
        return TextQueryTestBackend(
            build_pipeline(
                pipeline or self.template_config.sigma_pipeline, SIGMA_PIPELINES
            )
        )

    def execute(
        self,
        native_query: NativeQuery,
        time_window: HuntTimeWindow,
        limits: HuntLimits,
    ) -> HuntResult:
        """Execute a query on the platform search API.

        Args:
            native_query: Query to execute.
            time_window: Time window to search over.
            limits: Run limits.

        Returns:
            The hunt results.
        """
        if self.client is None:
            raise RuntimeError("The API client is created by start().")
        response = self.client.search(
            query=native_query.query,
            indices=list(self.template_config.indices),
            start=time_window.start,
            end=time_window.end,
            max_results=limits.max_results,
            timeout=limits.timeout_seconds,
        )
        events = [
            HuntEvent(
                timestamp=_event_time(event.get("@timestamp")),
                fields=flatten_fields(event),
            )
            for event in response["events"][: limits.max_results]
        ]
        return HuntResult(
            events=events,
            total_hits=response["total"],
            truncated=response["total"] > len(events),
        )


def _event_time(value: object) -> datetime | None:
    """Parse the ISO 8601 time of an event, if any."""
    if not isinstance(value, str) or not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else None
