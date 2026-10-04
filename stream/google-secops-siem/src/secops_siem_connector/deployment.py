"""Deployment write-back (dissemination assurance) of the Google SecOps SIEM connector.

Google SecOps cannot list nor delete the UDM entities imported by the connector (the
`entities` API only imports and gets them by name), so the
`SecOpsDeploymentAdapter` is a push adapter of the connectors SDK:

- re-push: the stream ingest path, for the `pending` deployments (analyst retry);
- hits: the IoC matches of the instance (`legacySearchEnterpriseWideIoCs`) whose
  artifact (domain, destination IP address, MD5, SHA-1 or SHA-256 hash) is the value
  of a deployed indicator.

Presence, absence and withdrawal are not reconciled: an imported entity stays live in
Google SecOps until the end of its validity interval (the indicator `valid_until`).
"""

from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from connectors_sdk import (
    DeploymentAssurance,
    DeploymentPushAdapter,
    HitCollection,
    IndicatorDeployment,
    VendorHit,
)
from connectors_sdk.connectors.stream.deployment import normalize_value, parse_datetime
from secops_siem_connector.connector import failure_reason
from secops_siem_services import SecOpsApiError

if TYPE_CHECKING:
    from secops_siem_connector.connector import SecOpsSIEMConnector


class SecOpsDeploymentError(Exception):
    """A re-push refused by Google SecOps, with the reason OpenCTI shows."""


MAX_HIT_MATCHES = 10_000
"""Maximum number of IoC matches read by one request of a hit collection."""

MAX_HIT_WINDOW_READS = 8
"""Maximum number of IoC match requests of one hit collection."""

MIN_HIT_WINDOW = timedelta(minutes=1)
"""Shortest time window of IoC matches (never halved again)."""

ARTIFACT_VALUE_FIELDS = (
    "domain",
    "destinationIpAddress",
    "hashMd5",
    "hashSha1",
    "hashSha256",
)
"""Fields of an IoC match artifact compared with the values of the deployed indicators."""


def _match_values(match: Mapping[str, Any]) -> set[str]:
    """Return the normalized artifact values of an IoC match."""
    candidates: list[Any] = []
    artifact = match.get("artifactIndicator")
    if isinstance(artifact, Mapping):
        candidates.extend(
            artifact.get(field_name) for field_name in ARTIFACT_VALUE_FIELDS
        )
    field_and_value = match.get("fieldAndValue")
    if isinstance(field_and_value, Mapping):
        candidates.append(field_and_value.get("value"))
    return {
        normalized
        for candidate in candidates
        if isinstance(candidate, str) and (normalized := normalize_value(candidate))
    }


class SecOpsDeploymentAdapter(DeploymentPushAdapter):
    """Vendor operations of the deployment reconciliation for Google SecOps."""

    def __init__(
        self,
        connector: "SecOpsSIEMConnector",
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Initialize the adapter.

        :param connector: The connector, whose API client and ingest path are used.
        :param clock: Current time provider (injectable for tests).
        """
        self._connector = connector
        self._clock = clock or (lambda: datetime.now(UTC))

    def push_indicator(self, stix_indicator: dict[str, Any]) -> str | None:
        """Ingest an indicator again, with the stream ingest path.

        :return: The STIX id of the indicator (`product_entity_id` of its entities).
        :raises SecOpsDeploymentError: When Google SecOps rejects the entities or
            cannot be reached, with the reason OpenCTI shows (the Google SecOps
            response is logged).
        :raises ValueError: When no observable of the indicator can be ingested.
        """
        try:
            return self._connector.push_indicator(stix_indicator)
        except SecOpsApiError as err:
            self._connector.helper.connector_logger.warning(
                "[DEPLOYMENT] Google SecOps did not take an indicator pushed again.",
                {"indicator_id": stix_indicator.get("id"), "error": str(err)},
            )
            raise SecOpsDeploymentError(failure_reason(err)) from err

    def collect_hits(
        self, deployments: Sequence[IndicatorDeployment], since: datetime
    ) -> Iterable[VendorHit] | HitCollection:
        """Read the IoC matches whose artifact is the value of a deployed indicator.

        A match counts one hit per matching indicator, at the time Google SecOps last saw
        the artifact in the environment (hits already reported are filtered by the SDK).

        :raises SecOpsApiError: When the IoC matches cannot be listed, or a match has
            no last seen time (the window is read again).
        """
        by_value: dict[str, list[IndicatorDeployment]] = {}
        for deployment in deployments:
            for value in deployment.values:
                by_value.setdefault(value, []).append(deployment)
        if not by_value:
            return []
        matches, complete_until = self._read_matches(since)
        hits: list[VendorHit] = []
        for match in matches:
            timestamp = parse_datetime(match.get("lastSeenTimestamp"))
            if timestamp is None:
                raise SecOpsApiError(
                    "Google SecOps listed an IoC match without last seen time, "
                    "the hit read is incomplete"
                )
            if timestamp < since:
                continue
            matched = {
                deployment.indicator_id
                for value in _match_values(match)
                for deployment in by_value.get(value, ())
            }
            hits.extend(
                VendorHit(timestamp=timestamp, indicator_id=indicator_id)
                for indicator_id in sorted(matched)
            )
        if complete_until is not None:
            return HitCollection(hits=hits, complete_until=complete_until)
        return hits

    def _read_matches(
        self, since: datetime
    ) -> tuple[list[dict[str, Any]], datetime | None]:
        """Read the IoC matches since a date, by time windows.

        The IoC matches API returns the most recent matches first and only tells that
        more were available: a truncated window is halved and its halves are read,
        oldest first, so the matches read are complete up to a known date. A window of
        `MIN_HIT_WINDOW` still truncated is kept as read (its count is a lower bound).
        A match returned by several windows is kept once.

        :return: The matches, and `None` when every window was read, otherwise the
            start of the first window left unread after `MAX_HIT_WINDOW_READS` reads.
        """
        matches: dict[tuple[Any, ...], dict[str, Any]] = {}
        windows = [(since, self._clock())]
        reads = 0
        while windows:
            start, end = windows.pop()
            if reads >= MAX_HIT_WINDOW_READS:
                return list(matches.values()), start
            window_matches, more_available = (
                self._connector.api_client.list_ioc_matches(start, end, MAX_HIT_MATCHES)
            )
            reads += 1
            if not more_available or end - start <= MIN_HIT_WINDOW:
                for match in window_matches:
                    key = (
                        match.get("id"),
                        repr(match.get("artifactIndicator")),
                        repr(match.get("fieldAndValue")),
                        match.get("lastSeenTimestamp"),
                    )
                    matches.setdefault(key, match)
                continue
            middle = start + (end - start) / 2
            windows.extend([(middle, end), (start, middle)])
        return list(matches.values()), None


def build_deployment_assurance(connector: "SecOpsSIEMConnector") -> DeploymentAssurance:
    """Build the deployment write-back of the connector, re-push and hits included.

    :param connector: The connector (settings `deployment`, `hits` and `security_platform`).
    :return: The deployment write-back, a no-op when `DEPLOYMENT_REPORTING_ENABLED` is false.
    """
    return DeploymentAssurance.from_settings(
        connector.helper,
        connector.config,
        adapter=SecOpsDeploymentAdapter(connector),
    )
