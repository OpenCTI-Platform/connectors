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

from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
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

MAX_HANDLED_INCIDENTS = 20_000
"""Maximum number of incidents remembered by a hit read continued over several runs."""

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


@dataclass(frozen=True, slots=True)
class IncidentCursor:
    """Where a hit read stopped early continues.

    The incident listing restarts at `modified_since` (a modification time) and
    skips the incidents already handled by the read at their current activity
    time, whose hit-time lower bound stays the `since` of the reconciler. An
    incident active again since it was handled is read again, as the next window
    of an uncapped read would.
    """

    modified_since: datetime
    handled: Mapping[str, datetime]
    """The activity time at which each incident was handled, by incident id."""


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
        """Read back the indicators uploaded with the connector `source_system`.

        Revoked indicators and indicators whose `valid_until` is reached are not
        live in Sentinel, but Sentinel keeps them: they are listed as inactive, for a
        withdrawal to delete them.

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
        :return: The vendor indicator (inactive when revoked or expired), or `None`
            when it is not an indicator.
        :raises SentinelDeploymentError: For an indicator without its STIX id (never
            skipped: its deployment would look absent).
        """
        properties = ti_object.get("properties") or {}
        data = properties.get("data") or {}
        if data.get("type", "indicator") != "indicator":
            return None
        stix_id = data.get("id")
        if not stix_id:
            raise SentinelDeploymentError(
                "A Microsoft Sentinel indicator of the read-back carries no STIX id"
            )
        valid_until = parse_datetime(data.get("valid_until"))
        expired = valid_until is not None and valid_until <= now
        resource_id = ti_object.get("id")
        resource_name = ti_object.get("name")
        return VendorIndicator(
            # The upload API keeps the STIX id of the object: the OpenCTI standard id.
            indicator_id=str(stix_id),
            external_id=str(resource_name or resource_id or stix_id),
            value=_first_pattern_value(data),
            raw={"id": resource_id, "name": resource_name},
            active=data.get("revoked") is not True and not expired,
            # A failed upload keeps the previous object under the same STIX id: it
            # never confirms the current pattern of the indicator.
            pattern=data.get("pattern"),
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
        resume: IncidentCursor | None = None,
    ) -> Iterable[VendorHit] | HitCollection:
        """Read the Sentinel incidents whose entities match deployed indicators.

        Incidents modified since `since` are listed (oldest first); those whose last
        activity is older than `since` are skipped. Each incident counts one hit per
        matching indicator (whatever the number of its values in the incident, and
        for every indicator carrying a shared value), at the incident last activity
        time.

        The read stops at the first incident beyond `MAX_HIT_INCIDENTS` inspected
        incidents or whose entities cannot be read, and when the listing stops at
        `INCIDENTS_MAX_PAGES` with pages left. The listing is ordered by
        modification time while hits carry the activity time: an incident left
        unread can have any activity time after `since`, so the collection is then
        complete only until `since`. The reconciler holds its hits, and the next
        run continues the listing where this one stopped (`resume`), skipping the
        incidents already handled at their current activity time (an incident
        active again is read again), with the same `since` for the activity time.
        Beyond `MAX_HANDLED_INCIDENTS` handled incidents, the read is not
        continued and its hits are a lower bound.

        :param resume: Where the previous read, stopped early, continues.
        :raises SentinelDeploymentError: When the incidents cannot be listed.
        """
        indicators_by_value: dict[str, set[str]] = {}
        for deployment in deployments:
            for value in deployment.values:
                indicators_by_value.setdefault(value, set()).add(
                    deployment.indicator_id
                )
        if not indicators_by_value:
            return []
        listed_since = resume.modified_since if resume else since
        handled: dict[str, datetime] = dict(resume.handled) if resume else {}
        cursor = listed_since
        hits: list[VendorHit] = []
        inspected = 0
        stopped = False
        with _readable_errors():
            # Lazy iteration: the next incident pages are read only while needed.
            listing = self._client.iter_incidents(
                modified_since=listed_since,
                page_size=INCIDENTS_PAGE_SIZE,
                max_pages=INCIDENTS_MAX_PAGES,
            )
            for incident in listing:
                properties = incident.get("properties") or {}
                modified_time = parse_datetime(properties.get("lastModifiedTimeUtc"))
                activity_time = (
                    parse_datetime(properties.get("lastActivityTimeUtc"))
                    or parse_datetime(properties.get("createdTimeUtc"))
                    or modified_time
                )
                incident_id = incident.get("id") or incident.get("name")
                if not incident_id:
                    # Never skipped: the hit window would move past its entities.
                    raise SentinelDeploymentError(
                        "A Microsoft Sentinel incident of the hit read carries no id"
                    )
                if activity_time is None:
                    # Never skipped: the hit window would move past its entities.
                    raise SentinelDeploymentError(
                        "A Microsoft Sentinel incident of the hit read carries no "
                        "activity time"
                    )
                handled_at = handled.get(str(incident_id))
                if handled_at is not None and activity_time <= handled_at:
                    continue
                if activity_time >= since:
                    if inspected >= MAX_HIT_INCIDENTS:
                        self._logger.warning(
                            f"{_LOG_PREFIX} Incident limit reached, the next run "
                            "continues at the first incident not inspected.",
                            meta={"limit": MAX_HIT_INCIDENTS},
                        )
                        stopped = True
                        break
                    try:
                        entities = self._client.list_incident_entities(str(incident_id))
                    except ConnectorClientError as err:
                        self._logger.warning(
                            f"{_LOG_PREFIX} Cannot read the entities of an incident, "
                            "the next run continues at it.",
                            meta={
                                "incident_id": incident_id,
                                "error": describe_error(err),
                            },
                        )
                        stopped = True
                        break
                    inspected += 1
                    matched = {
                        indicator_id
                        for value in self._entity_values(entities)
                        for indicator_id in indicators_by_value.get(value, ())
                    }
                    hits.extend(
                        VendorHit(timestamp=activity_time, indicator_id=indicator_id)
                        for indicator_id in sorted(matched)
                    )
                handled[str(incident_id)] = activity_time
                if modified_time is not None and modified_time > cursor:
                    cursor = modified_time
        if not stopped and not listing.truncated:
            return hits
        if len(handled) > MAX_HANDLED_INCIDENTS:
            self._logger.warning(
                f"{_LOG_PREFIX} Too many incidents to continue the capped read, its "
                "hits are a lower bound.",
                meta={"handled": len(handled), "limit": MAX_HANDLED_INCIDENTS},
            )
            return HitCollection(hits=hits, complete_until=since)
        return HitCollection(
            hits=hits,
            complete_until=since,
            resume=IncidentCursor(modified_since=cursor, handled=handled),
        )

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
