"""Deployment write-back (dissemination assurance) of the Microsoft Sentinel Intel connector.

The `MicrosoftSentinelIntelDeploymentAdapter` gives the connectors SDK reconciliation
access to Microsoft Sentinel:

- read-back: the threat intelligence indicators of the connector `source_system`,
  listed with the management API `threatIntelligence/main/query` endpoint;
- removal: deletion of a threat intelligence object by its resource id;
- re-push: the stream upload path (`threat-intelligence-stix-objects:upload`);
- hits: the Microsoft Sentinel incidents modified since the previous run, whose
  entities (IP addresses, URLs, domains, file hashes) match deployed indicators.
"""

from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from azure.core.exceptions import ResourceNotFoundError
from connectors_sdk import (
    DeploymentAssurance,
    DeploymentVendorAdapter,
    HitCollection,
    IndicatorDeployment,
    VendorHit,
    VendorIndicator,
)
from connectors_sdk.connectors.stream.deployment import (
    extract_pattern_values,
    normalize_value,
    parse_datetime,
)
from microsoft_sentinel_intel.client import ConnectorClient
from microsoft_sentinel_intel.errors import ConnectorClientError, ConnectorError
from microsoft_sentinel_intel.utils import describe_error

if TYPE_CHECKING:
    from microsoft_sentinel_intel.connector import Connector

TI_QUERY_PAGE_SIZE = 100
"""`maxPageSize` of the threat intelligence query (value of the API documentation example)."""

TI_QUERY_MAX_PAGES = 5_000
"""Hard cap of the pages read by one read-back (500,000 TI objects)."""

MAX_VENDOR_INDICATORS = 250_000
"""Read-back limit of a reconciliation run: beyond it, absence-based decisions are skipped."""

INCIDENTS_PAGE_SIZE = 100
"""`$top` of the incidents listing."""

INCIDENTS_MAX_PAGES = 20
"""Hard cap of the incident pages read by one hit collection."""

MAX_HIT_INCIDENTS = 200
"""Maximum number of incidents whose entities are read by one hit collection."""

ENTITY_VALUE_PROPERTIES = {
    "Ip": ("address",),
    "Url": ("url",),
    "DnsResolution": ("domainName",),
    "FileHash": ("hashValue",),
}
"""Incident entity kinds compared with the indicator values, and their value properties."""

_LOG_PREFIX = "[DEPLOYMENT]"


def _first_pattern_value(stix_object: dict[str, Any]) -> str | None:
    """Return the first observable value of a STIX indicator pattern."""
    values = extract_pattern_values(stix_object.get("pattern"))
    return values[0].value if values else None


def _is_not_found(error: ConnectorClientError) -> bool:
    """Tell whether a client error is a 404 (resource already deleted)."""
    cause = error.__cause__
    return isinstance(cause, ResourceNotFoundError) or (
        getattr(cause, "status_code", None) == 404
    )


class SentinelDeploymentError(Exception):
    """A Microsoft Sentinel API error raised to the reconciliation, with a readable message."""


@contextmanager
def _readable_errors() -> Iterator[None]:
    """Re-raise connector errors with their message and API error.

    `ConnectorError` keeps its message in an attribute (`str()` is empty); the SDK
    logs `str(error)` and stores it as the `error_message` of failed deployments.
    """
    try:
        yield
    except ConnectorError as err:
        raise SentinelDeploymentError(describe_error(err)) from err


class MicrosoftSentinelIntelDeploymentAdapter(DeploymentVendorAdapter):
    """Vendor operations of the deployment reconciliation for Microsoft Sentinel."""

    def __init__(self, connector: "Connector") -> None:
        """Initialize the adapter.

        :param connector: The connector, whose client, settings and upload path are used.
        """
        self._connector = connector

    @property
    def _client(self) -> ConnectorClient:
        return self._connector.client

    @property
    def _source_system(self) -> str:
        return self._connector.config.microsoft_sentinel_intel.source_system

    @property
    def _logger(self) -> Any:
        return self._connector.helper.connector_logger

    def list_vendor_indicators(self) -> Iterator[VendorIndicator]:
        """Read back the live indicators uploaded with the connector `source_system`.

        Revoked indicators and indicators whose `valid_until` is in the past are not
        live in Sentinel and are not returned.

        :raises SentinelDeploymentError: On any API error (never a partial listing).
        """
        now = datetime.now(UTC)
        with _readable_errors():
            for ti_object in self._client.iter_indicators(
                source_system=self._source_system,
                page_size=TI_QUERY_PAGE_SIZE,
                max_pages=TI_QUERY_MAX_PAGES,
            ):
                vendor_indicator = self._to_vendor_indicator(ti_object, now)
                if vendor_indicator is not None:
                    yield vendor_indicator

    @staticmethod
    def _to_vendor_indicator(
        ti_object: dict[str, Any], now: datetime
    ) -> VendorIndicator | None:
        """Map a TI object of the query API to a vendor indicator.

        :param ti_object: The TI object (`id`, `name`, `properties.data`...).
        :param now: The reference time of the expiry check.
        :return: The vendor indicator, or `None` when it is not a live indicator.
        """
        properties = ti_object.get("properties") or {}
        data = properties.get("data") or {}
        stix_id = data.get("id")
        if data.get("type", "indicator") != "indicator" or not stix_id:
            return None
        if data.get("revoked") is True:
            return None
        valid_until = parse_datetime(data.get("valid_until"))
        if valid_until is not None and valid_until < now:
            return None
        resource_id = ti_object.get("id")
        resource_name = ti_object.get("name")
        return VendorIndicator(
            # The upload API keeps the STIX id of the object: the OpenCTI standard id.
            indicator_id=str(stix_id),
            external_id=str(resource_name or resource_id or stix_id),
            value=_first_pattern_value(data),
            raw={"id": resource_id, "name": resource_name},
        )

    def remove_vendor_indicator(
        self, vendor_indicator: VendorIndicator, deployment: IndicatorDeployment
    ) -> None:
        """Delete an indicator from Sentinel (withdrawal, revocation or expiry).

        :raises SentinelDeploymentError: When Sentinel refuses the deletion.
        """
        resource_id = vendor_indicator.raw.get("id")
        with _readable_errors():
            if not resource_id:
                self._client.delete_indicator_by_id(
                    deployment.indicator_standard_id
                    or str(vendor_indicator.indicator_id),
                    source_system=self._source_system,
                )
                return
            try:
                self._client.delete_ti_object(str(resource_id))
            except ConnectorClientError as err:
                if not _is_not_found(err):
                    raise

    def push_indicator(self, stix_indicator: dict[str, Any]) -> str | None:
        """Upload an indicator again, with the stream upload path.

        :return: `None`: the upload API returns no id (the indicator keeps its STIX id).
        :raises SentinelDeploymentError: When the upload API rejects the indicator.
        """
        with _readable_errors():
            self._connector.push_indicator(stix_indicator)
        return None

    def collect_hits(
        self,
        deployments: Sequence[IndicatorDeployment],
        since: datetime,
        *,
        resume: frozenset[str] | None = None,
    ) -> Iterable[VendorHit] | HitCollection:
        """Read the Sentinel incidents whose entities match deployed indicators.

        Incidents modified since `since` are listed (oldest first); those whose last
        activity is older than `since` are skipped. Each incident counts one hit per
        matching indicator value, at the incident last activity time.

        The read stops at the first incident beyond `MAX_HIT_INCIDENTS` inspected
        incidents or whose entities cannot be read, and after `INCIDENTS_MAX_PAGES`
        pages: the collection is then complete until that incident's modification
        time, where the next run resumes. When that time is `since` itself, the
        next run skips the incidents already inspected there (`resume`).

        :param resume: Ids of the incidents already inspected at `since`, when the
            previous read stopped there.
        :raises SentinelDeploymentError: When the incidents cannot be listed.
        """
        deployed_values = set().union(
            *(deployment.values for deployment in deployments)
        )
        if not deployed_values:
            return []
        already_inspected = resume or frozenset()
        inspected_at_start: set[str] = set(already_inspected)
        hits: list[VendorHit] = []
        inspected = 0
        listed = 0
        modified_time: datetime | None = None
        stopped_at: datetime | None = None
        with _readable_errors():
            # Lazy iteration: the next incident pages are read only while needed.
            for incident in self._client.iter_incidents(
                modified_since=since,
                page_size=INCIDENTS_PAGE_SIZE,
                max_pages=INCIDENTS_MAX_PAGES,
            ):
                listed += 1
                properties = incident.get("properties") or {}
                modified_time = parse_datetime(properties.get("lastModifiedTimeUtc"))
                activity_time = (
                    parse_datetime(properties.get("lastActivityTimeUtc"))
                    or parse_datetime(properties.get("createdTimeUtc"))
                    or modified_time
                )
                incident_id = incident.get("id") or incident.get("name")
                if incident_id and str(incident_id) in already_inspected:
                    continue
                at_start = modified_time is None or modified_time <= since
                if activity_time is None or activity_time < since or not incident_id:
                    if incident_id and at_start:
                        inspected_at_start.add(str(incident_id))
                    continue
                if inspected >= MAX_HIT_INCIDENTS:
                    self._logger.warning(
                        f"{_LOG_PREFIX} Incident limit reached, the next run resumes "
                        "at the first incident not inspected.",
                        {"limit": MAX_HIT_INCIDENTS},
                    )
                    stopped_at = modified_time or since
                    break
                try:
                    entities = self._client.list_incident_entities(str(incident_id))
                except ConnectorClientError as err:
                    self._logger.warning(
                        f"{_LOG_PREFIX} Cannot read the entities of an incident, the "
                        "next run resumes at it.",
                        {"incident_id": incident_id, "error": describe_error(err)},
                    )
                    stopped_at = modified_time or since
                    break
                inspected += 1
                if at_start:
                    inspected_at_start.add(str(incident_id))
                matched = self._entity_values(entities) & deployed_values
                hits.extend(
                    VendorHit(timestamp=activity_time, value=value)
                    for value in sorted(matched)
                )
        if stopped_at is None and listed >= INCIDENTS_PAGE_SIZE * INCIDENTS_MAX_PAGES:
            stopped_at = modified_time or since
        if stopped_at is not None:
            if stopped_at <= since:
                return HitCollection(
                    hits=hits,
                    complete_until=since,
                    resume=frozenset(inspected_at_start),
                )
            return HitCollection(hits=hits, complete_until=stopped_at)
        return hits

    @staticmethod
    def _entity_values(entities: Iterable[dict[str, Any]]) -> set[str]:
        """Return the normalized observable values of incident entities."""
        values: set[str] = set()
        for entity in entities:
            properties = entity.get("properties") or {}
            for property_name in ENTITY_VALUE_PROPERTIES.get(entity.get("kind"), ()):
                if normalized := normalize_value(properties.get(property_name)):
                    values.add(normalized)
        return values


def build_deployment_assurance(connector: "Connector") -> DeploymentAssurance:
    """Build the deployment write-back of the connector, reconciliation and hits included.

    :param connector: The connector (settings `deployment`, `hits` and `security_platform`).
    :return: The deployment write-back, a no-op when `DEPLOYMENT_REPORTING_ENABLED` is false.
    """
    return DeploymentAssurance.from_settings(
        connector.helper,
        connector.config,
        adapter=MicrosoftSentinelIntelDeploymentAdapter(connector),
        max_vendor_indicators=MAX_VENDOR_INDICATORS,
    )
