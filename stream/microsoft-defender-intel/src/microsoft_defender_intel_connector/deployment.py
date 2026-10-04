"""Deployment write-back (dissemination assurance) of the Microsoft Defender Intel connector.

The `MicrosoftDefenderDeploymentAdapter` gives the connectors SDK reconciliation
access to Microsoft Defender for Endpoint:

- read-back: the active indicators of the connector application
  (`application eq 'OpenCTI Microsoft Defender Intel'`), with their `externalId`
  (the OpenCTI id submitted by the connector);
- removal: deletion of the Defender indicator;
- re-push: the stream create path;
- hits: the Defender alerts whose evidence (file hashes, IP addresses, URLs) carries
  the value of a deployed indicator.
"""

from collections.abc import Callable, Iterable, Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

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
from microsoft_defender_intel_connector.api_handler import (
    APPLICATION_NAME,
    MAX_PAGE_SIZE,
    DefenderApiHandler,
    DefenderApiHandlerError,
)
from microsoft_defender_intel_connector.utils import FILE_HASH_TYPES_MAPPER, IOC_TYPES

if TYPE_CHECKING:
    from microsoft_defender_intel_connector.connector import (
        MicrosoftDefenderIntelConnector,
    )

MAX_HIT_ALERTS = MAX_PAGE_SIZE
"""Maximum number of alerts read by one request of a hit collection."""

MAX_HIT_WINDOW_READS = 8
"""Maximum number of alert requests of one hit collection."""

MIN_HIT_WINDOW = timedelta(seconds=1)
"""Shortest time window of alerts, never halved again (the filter precision)."""

MAX_ERROR_DETAIL_LENGTH = 500
"""Maximum length of the Defender response appended to a deployment error."""

EVIDENCE_VALUE_FIELDS = ("sha1", "sha256", "md5", "ipAddress", "url")
"""Evidence fields compared with the indicator values (`domainName` is an account domain)."""

PATTERN_VALUE_TYPES = frozenset(IOC_TYPES) - set(FILE_HASH_TYPES_MAPPER.values())
"""Observable types pushed with their own value, one Defender indicator each."""


def describe_error(error: BaseException) -> str:
    """Describe a Defender API error for logs and the deployment error message.

    :param error: The error raised by the API handler.
    :return: The message, followed by the HTTP error and the Defender response body.
    """
    if isinstance(error, DefenderApiHandlerError):
        message = str(error.msg)
        cause = error.__cause__
        if cause is not None:
            message = f"{message}: {cause}"
            response = getattr(cause, "response", None)
            detail = getattr(response, "text", None) if response is not None else None
            if isinstance(detail, str) and detail.strip():
                message = f"{message} - {detail.strip()[:MAX_ERROR_DETAIL_LENGTH]}"
        return message
    return str(error) or type(error).__name__


class DefenderDeploymentError(Exception):
    """A Defender API error raised to the reconciliation, with a readable message."""


@contextmanager
def _readable_errors() -> Iterator[None]:
    """Re-raise API handler errors with their message (`str()` of them is empty)."""
    try:
        yield
    except DefenderApiHandlerError as err:
        raise DefenderDeploymentError(describe_error(err)) from err


def _is_not_found(error: DefenderApiHandlerError) -> bool:
    """Tell whether an API handler error is a 404 (indicator already deleted)."""
    response = getattr(error.__cause__, "response", None)
    return getattr(response, "status_code", None) == 404


def _evidence_values(alert: dict[str, Any]) -> set[str]:
    """Return the normalized observable values of the evidence of an alert.

    :raises DefenderDeploymentError: When the evidence is not a list of objects:
        skipped, its matches would be lost as the hit window moves past the alert.
    """
    evidence_list = alert.get("evidence")
    if not isinstance(evidence_list, list):
        raise DefenderDeploymentError(
            "A Microsoft Defender alert of the hit read carries no evidence list"
        )
    values: set[str] = set()
    for evidence in evidence_list:
        if not isinstance(evidence, dict):
            raise DefenderDeploymentError(
                "A Microsoft Defender alert of the hit read carries an evidence "
                "that is not an object"
            )
        for field_name in EVIDENCE_VALUE_FIELDS:
            raw_value = evidence.get(field_name)
            if not isinstance(raw_value, str) or not (
                normalized := normalize_value(raw_value)
            ):
                continue
            values.add(normalized)
            if field_name == "url":
                # Domain indicators match the host of the URL evidence.
                host = urlsplit(
                    normalized if "://" in normalized else f"//{normalized}"
                ).hostname
                if host:
                    values.add(host)
    return values


class MicrosoftDefenderDeploymentAdapter(DeploymentVendorAdapter):
    """Vendor operations of the deployment reconciliation for Microsoft Defender."""

    def __init__(
        self,
        connector: "MicrosoftDefenderIntelConnector",
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Initialize the adapter.

        :param connector: The connector, whose API handler and create path are used.
        :param clock: Current time provider (injectable for tests).
        """
        self._connector = connector
        self._clock = clock or (lambda: datetime.now(UTC))

    @property
    def _api(self) -> DefenderApiHandler:
        return self._connector.api

    def list_vendor_indicators(self) -> Iterator[VendorIndicator]:
        """Read back the Defender indicators created by the connector.

        Indicators whose `expirationTime` is in the past are not live, but Defender
        keeps them: they are listed as inactive, for a withdrawal to delete them.

        :raises DefenderDeploymentError: On any API error (never a partial listing).
        """
        now = self._clock()
        with _readable_errors():
            for indicator in self._api.iter_application_indicators(APPLICATION_NAME):
                defender_id = indicator.get("id")
                if defender_id is None:
                    # Never skipped: its deployment would look absent.
                    raise DefenderDeploymentError(
                        "A Microsoft Defender indicator of the read-back carries no id"
                    )
                expiration = parse_datetime(indicator.get("expirationTime"))
                opencti_id = indicator.get("externalId") or indicator.get("externalID")
                yield VendorIndicator(
                    indicator_id=str(opencti_id) if opencti_id else None,
                    external_id=str(defender_id),
                    value=indicator.get("indicatorValue"),
                    raw={"id": defender_id},
                    active=expiration is None or expiration > now,
                )

    def remove_vendor_indicator(
        self, vendor_indicator: VendorIndicator, deployment: IndicatorDeployment
    ) -> None:
        """Delete an indicator from Defender (withdrawal, revocation or expiry).

        :raises DefenderDeploymentError: When Defender refuses the deletion.
        """
        defender_id = vendor_indicator.raw.get("id") or vendor_indicator.external_id
        try:
            self._api.delete_indicator(str(defender_id))
        except DefenderApiHandlerError as err:
            if not _is_not_found(err):
                raise DefenderDeploymentError(describe_error(err)) from err

    def is_complete(
        self,
        deployment: IndicatorDeployment,
        vendor_matches: Sequence[VendorIndicator],
    ) -> bool:
        """Tell whether every observable of the indicator has its Defender indicator.

        The connector creates one Defender indicator per IP address, domain, host
        name and URL of the pattern, and one per file (its SHA-256, SHA-1 or MD5).
        The pattern does not tell which hashes belong to the same file: the files
        are covered when one of their hashes is on Defender.

        :param deployment: The deployment.
        :param vendor_matches: Its Defender indicators.
        :return: False when an observable has no Defender indicator.
        """
        if deployment.pattern_type not in (None, "stix"):
            return True
        vendor_values = {
            normalized
            for vendor_indicator in vendor_matches
            if (normalized := normalize_value(vendor_indicator.value))
        }
        file_hashes: set[str] = set()
        for pattern_value in extract_pattern_values(deployment.pattern):
            value = normalize_value(pattern_value.value)
            if not value:
                continue
            algorithm = pattern_value.hash_algorithm
            if algorithm is not None:
                if algorithm.lower() in FILE_HASH_TYPES_MAPPER:
                    file_hashes.add(value)
            elif (
                pattern_value.object_type in PATTERN_VALUE_TYPES
                and value not in vendor_values
            ):
                return False
        return not file_hashes or not file_hashes.isdisjoint(vendor_values)

    def push_indicator(self, stix_indicator: dict[str, Any]) -> str | None:
        """Push an indicator again, with the stream create path.

        :return: The id of the first Defender indicator created.
        :raises DefenderDeploymentError: When Defender rejects the indicator.
        :raises ValueError: When no observable of the indicator can be pushed.
        """
        with _readable_errors():
            defender_ids = self._connector.push_indicator(stix_indicator)
        if not defender_ids:
            raise ValueError(
                "No observable of the indicator can be pushed to Microsoft Defender"
            )
        return defender_ids[0]

    def collect_hits(
        self,
        deployments: Sequence[IndicatorDeployment],
        since: datetime,
        *,
        resume: datetime | None = None,
    ) -> Iterable[VendorHit] | HitCollection:
        """Read the Defender alerts whose evidence matches deployed indicators.

        Each alert counts one hit per matching indicator, at the alert creation time;
        a value shared by several indicators credits each of them.

        :param resume: End of the first window to read, when the previous read ran
            out of requests while still halving the windows starting at `since`.
        :raises DefenderDeploymentError: When the alerts cannot be listed.
        """
        by_value: dict[str, list[IndicatorDeployment]] = {}
        for deployment in deployments:
            for value in deployment.values:
                by_value.setdefault(value, []).append(deployment)
        if not by_value:
            return []
        with _readable_errors():
            alerts, complete_until, next_resume = self._read_alerts(since, resume)
        hits: list[VendorHit] = []
        for alert in alerts:
            timestamp = parse_datetime(
                alert.get("alertCreationTime") or alert.get("firstEventTime")
            )
            if timestamp is None:
                # Never skipped: the hit window would move past its evidence.
                raise DefenderDeploymentError(
                    "A Microsoft Defender alert of the hit read carries no creation time"
                )
            if timestamp < since:
                continue
            matched = {
                deployment.indicator_id
                for value in _evidence_values(alert)
                for deployment in by_value.get(value, ())
            }
            hits.extend(
                VendorHit(timestamp=timestamp, indicator_id=indicator_id)
                for indicator_id in sorted(matched)
            )
        if complete_until is not None:
            return HitCollection(
                hits=hits, complete_until=complete_until, resume=next_resume
            )
        return hits

    def _read_alerts(
        self, since: datetime, first_end: datetime | None = None
    ) -> tuple[list[dict[str, Any]], datetime | None, datetime | None]:
        """Read the alerts created since a date, by time windows.

        The alerts API has no ordering, so a read is never continued by offset: a
        window whose read reaches `MAX_HIT_ALERTS` is halved and its halves are read,
        oldest first, so the alerts read are complete up to a known date. When the
        requests run out before the first window is read, the end of that window is
        returned and the next read halves it further. A `MIN_HIT_WINDOW` window
        still capped cannot be split: at `since`, its alerts are a lower bound and
        the next read starts after it; later in the read, the read stops at its start.

        :param first_end: End of the first window to read (see `collect_hits`).
        :return: The alerts; `None` when every window was read, otherwise the date
            until which the alerts are complete; and, when that date is `since`, the
            end of the first window still to read, if any.
        """
        now = self._clock()
        windows = [(since, now)]
        if first_end is not None and since < first_end < now:
            windows = [(first_end, now), (since, first_end)]
        alerts: list[dict[str, Any]] = []
        reads = 0
        while windows:
            start, end = windows.pop()
            if reads >= MAX_HIT_WINDOW_READS:
                return alerts, start, end if start <= since else None
            window_alerts = self._api.list_alerts(start, MAX_HIT_ALERTS, until=end)
            reads += 1
            if len(window_alerts) < MAX_HIT_ALERTS:
                alerts.extend(window_alerts)
                continue
            if end - start <= MIN_HIT_WINDOW:
                if start <= since:
                    return alerts + window_alerts, since, None
                return alerts, start, None
            middle = start + (end - start) / 2
            windows.extend([(middle, end), (start, middle)])
        return alerts, None, None


def build_deployment_assurance(
    connector: "MicrosoftDefenderIntelConnector",
) -> DeploymentAssurance:
    """Build the deployment write-back of the connector, reconciliation and hits included.

    :param connector: The connector (settings `deployment`, `hits` and `security_platform`).
    :return: The deployment write-back, a no-op when `DEPLOYMENT_REPORTING_ENABLED` is false.
    """
    return DeploymentAssurance.from_settings(
        connector.helper,
        connector.config,
        adapter=MicrosoftDefenderDeploymentAdapter(connector),
    )
