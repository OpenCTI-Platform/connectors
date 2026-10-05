"""Google SecOps hunt connector: executes OpenCTI hunts as UDM searches or YARA-L rules."""

import re
from collections.abc import Mapping, Sequence
from typing import Any

from connectors_sdk import InternalHuntConnector
from connectors_sdk.connectors.internal_hunt import (
    DEFAULT_ENTITY_FIELDS,
    HitFields,
    HuntEvent,
    HuntLimits,
    HuntRequest,
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

TIME_FIELDS: tuple[str, ...] = ("metadata.event_timestamp", "detection_time")
"""Fields holding the event time, by order of preference."""

BOOKKEEPING_FIELDS = frozenset(
    {
        "metadata.id",
        "metadata.product_log_id",
        "metadata.event_timestamp",
        "metadata.ingested_timestamp",
        "metadata.collected_timestamp",
        "metadata.base_labels",
        "metadata.enrichment_state",
        "metadata.enrichment_labels",
        "metadata.ingestion_labels",
    }
)
"""UDM bookkeeping fields (with their sub-fields), never sampled as evidence: the
time and the id of an event are in the evidence of each hit."""

VERBATIM_FIELDS = frozenset({"additional"})
"""UDM fields whose keys are chosen by the log parser, kept as they are."""

_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")

UDM_ROOTS = (
    "about",
    "additional",
    "extensions",
    "intermediary",
    "metadata",
    "network",
    "observer",
    "principal",
    "security_result",
    "src",
    "target",
)
"""Top-level fields of a UDM event."""

_UDM_FIELD = re.compile(
    rf"(?<![\w.])(?:\$\w+\.)?((?:{'|'.join(UDM_ROOTS)})(?:\.\w+)+)", re.IGNORECASE
)

HIT_FIELDS = HitFields(
    event_id=("metadata.id",),
    host=(
        "principal.hostname",
        "principal.asset.hostname",
        "target.hostname",
        "target.asset.hostname",
        "src.hostname",
        "observer.hostname",
    ),
    user=(
        "principal.user.userid",
        "principal.user.user_display_name",
        "principal.user.email_addresses",
        "target.user.userid",
        "target.user.email_addresses",
    ),
    process=(
        "target.process.file.full_path",
        "principal.process.file.full_path",
        "target.process.command_line",
        "principal.process.command_line",
    ),
)
"""UDM fields naming the event id, host, user and process of a hit."""


DOCUMENTATION_URL = (
    "https://docs.opencti.io/latest/usage/hunt-connectors/#google-secops"
)

REQUIRED_PERMISSIONS = (
    (
        "Chronicle API Editor (roles/chronicle.editor)",
        "Role of the service account on the project: run UDM searches and test YARA-L rules, never saved nor enabled.",
    ),
    (
        "Chronicle API enabled",
        "On the Google Cloud project of the SecOps instance.",
    ),
)
"""Least-privilege permissions of the account of the connector, as (name, purpose)."""

ACCESS_DENIED_HINTS = {
    401: "Google refused the service account key: check the private key, the key ID and the client email of the JSON key",
    403: "the service account needs the Chronicle API Editor role (roles/chronicle.editor) on the project of the SecOps instance, with the Chronicle API enabled",
}
"""What a refused account lacks, by HTTP status."""


class GoogleSecopsHuntConnector(InternalHuntConnector):
    """Hunt connector running Sigma, UDM search and YARA-L hunts on Google SecOps."""

    languages = ("udm", "yara-l")
    required_permissions = REQUIRED_PERMISSIONS
    documentation_url = DOCUMENTATION_URL
    evidence_excluded_fields = BOOKKEEPING_FIELDS
    entity_fields = (
        *DEFAULT_ENTITY_FIELDS,
        "principal.user.userid",
        "target.user.userid",
        "principal.asset.hostname",
        "target.asset.hostname",
    )
    hit_fields = HIT_FIELDS

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
        self.client.access_denied_hints = dict(ACCESS_DENIED_HINTS)

    def connection_test_query(self) -> NativeQuery:
        """Return the test search: one UDM event."""
        return NativeQuery(
            language="udm", query='metadata.event_type != "EVENTTYPE_UNSPECIFIED"'
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

    def resolve_query(self, request: HuntRequest) -> NativeQuery:
        """Return the query of a run, naming the UDM fields a native query matches.

        Args:
            request: The hunt run request.

        Returns:
            The query, with the UDM fields it references.
        """
        query = super().resolve_query(request)
        if query.fields:
            return query
        return query.model_copy(update={"fields": udm_query_fields(query.query)})

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
        deadline: RunDeadline | None = None,
    ) -> HuntResult:
        """Run the hunt as a UDM search or a YARA-L rule test over the run window.

        Args:
            native_query: UDM search query or YARA-L rule.
            time_window: Time window of the run.
            limits: Run limits.
            deadline: Run deadline shared with the SDK (started from the
                limits on direct calls).

        Returns:
            The hunt results.
        """
        if self.client is None:
            raise RuntimeError("The Chronicle API client is created by start().")
        deadline = deadline or RunDeadline(limits.timeout_seconds)
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
        detections = result.event_detections or [None] * len(result.events)
        events = []
        for raw, detection in zip(result.events, detections, strict=True):
            fields = flatten_fields(udm_names(raw))
            events.append(
                HuntEvent(
                    timestamp=_event_time(fields), fields=fields, detection=detection
                )
            )
        # A YARA-L hit is a detection, whatever the number of events it references
        return HuntResult(
            events=events, total_hits=result.detections, truncated=result.truncated
        )


def udm_names(value: Any) -> Any:
    """Name the fields of a UDM event as UDM search, YARA-L and the Sigma pipeline do.

    The Chronicle API answers in JSON camelCase (``target.process.commandLine``);
    UDM field paths are snake_case (``target.process.command_line``). The keys
    of ``additional`` are chosen by the log parser and kept as they are.

    Args:
        value: A UDM event, or a part of it.

    Returns:
        The same document with snake_case keys.
    """
    if isinstance(value, Mapping):
        return {
            _snake_case(str(key)): (item if key in VERBATIM_FIELDS else udm_names(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [udm_names(item) for item in value]
    return value


def _snake_case(name: str) -> str:
    """Turn a JSON camelCase key into its UDM snake_case name."""
    return _CAMEL_BOUNDARY.sub("_", name).lower()


def udm_query_fields(query: str) -> tuple[str, ...]:
    """Return the UDM fields a UDM search or a YARA-L rule references.

    Args:
        query: UDM search or YARA-L rule.

    Returns:
        The field names (without event variable), in order of first appearance.
    """
    return tuple(
        dict.fromkeys(match.group(1).lower() for match in _UDM_FIELD.finditer(query))
    )


def _event_time(fields: dict[str, Any]) -> Any:
    """Return the event time from the first time field present."""
    for name in TIME_FIELDS:
        timestamp = parse_timestamp(fields.get(name))
        if timestamp is not None:
            return timestamp
    return None
