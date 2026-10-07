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
from http import HTTPStatus
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import requests
from connectors_sdk import (
    DeploymentAssurance,
    DeploymentVendorAdapter,
    HitCollection,
    IndicatorDeployment,
    VendorHit,
    VendorIndicator,
)
from connectors_sdk.connectors.stream.deployment import (
    deployment_failure_reason,
    extract_pattern_values,
    normalize_value,
    parse_datetime,
    parse_expiry,
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
"""Maximum length of the Defender response appended to a logged error."""

PLATFORM_NAME = "Microsoft Defender"
"""Name of the security platform in the deployment failure reasons."""

PUSH_ACTION = "indicator submission"
"""What Defender is asked to do when an indicator is pushed."""

EVIDENCE_VALUE_FIELDS = ("sha1", "sha256", "md5", "ipAddress", "url")
"""Evidence fields compared with the indicator values (`domainName` is an account domain)."""

PATTERN_VALUE_TYPES = frozenset(IOC_TYPES) - set(FILE_HASH_TYPES_MAPPER.values())
"""Observable types pushed with their own value, one Defender indicator each."""


def describe_error(error: BaseException) -> str:
    """Describe a Defender API error for the logs.

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


def failure_reason(error: BaseException) -> str:
    """Return the reason OpenCTI shows for an indicator Defender did not take.

    :param error: The error raised while pushing the indicator.
    :return: One short sentence naming Microsoft Defender and the cause; the Defender
        response is left to the logs (`describe_error`).
    """
    if not isinstance(error, DefenderApiHandlerError):
        return str(error) or type(error).__name__
    cause = error.__cause__
    status_code: int | None
    if isinstance(cause, requests.exceptions.RetryError):
        # The retries of the throttled requests ran out.
        status_code = HTTPStatus.TOO_MANY_REQUESTS
    elif isinstance(
        cause, (requests.exceptions.ConnectionError, requests.exceptions.Timeout)
    ):
        status_code = None
    else:
        response = getattr(cause, "response", None)
        status_code = getattr(response, "status_code", None)
        if not isinstance(status_code, int):
            # Defender answered with a payload the connector cannot use.
            status_code = HTTPStatus.OK
    return deployment_failure_reason(PLATFORM_NAME, PUSH_ACTION, status_code)


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


def _is_live(indicator: dict[str, Any], now: datetime) -> bool:
    """Tell whether a Defender indicator has not expired yet (Defender keeps expired ones).

    :raises DefenderDeploymentError: On an unreadable `expirationTime`, which would
        otherwise read as no expiry and confirm an expired indicator.
    """
    try:
        expiration = parse_expiry(indicator.get("expirationTime"))
    except ValueError as err:
        raise DefenderDeploymentError(
            "A Microsoft Defender indicator carries an unreadable expirationTime"
        ) from err
    return expiration is None or expiration > now


def _belongs_to(indicator: dict[str, Any], deployment: IndicatorDeployment) -> bool:
    """Tell whether the read-back would match a Defender indicator to a deployment.

    It carries the OpenCTI id of the indicator, its Defender id is the one reported
    for the deployment, or it carries no OpenCTI id (matched by value). A Defender
    indicator pushed for another OpenCTI indicator holding the same value is not.
    """
    opencti_id = normalize_value(
        indicator.get("externalId") or indicator.get("externalID")
    )
    if opencti_id is None or opencti_id in deployment.identifiers:
        return True
    defender_id = normalize_value(indicator.get("id"))
    return defender_id is not None and defender_id == normalize_value(
        deployment.external_id
    )


def _defender_values(deployment: IndicatorDeployment) -> tuple[set[str], set[str]]:
    """Return the normalized values the connector pushes to Defender for an indicator.

    Only the IP addresses, domains, host names and URLs of a STIX pattern, and the
    MD5, SHA-1 and SHA-256 hashes of its files, reach Defender: the other values of
    the pattern never have a Defender indicator.

    :param deployment: The deployment.
    :return: The values pushed with their own Defender indicator, and the file hashes.
    """
    values: set[str] = set()
    file_hashes: set[str] = set()
    if deployment.pattern_type not in (None, "stix"):
        return values, file_hashes
    for pattern_value in extract_pattern_values(deployment.pattern):
        value = normalize_value(pattern_value.value)
        if not value:
            continue
        algorithm = pattern_value.hash_algorithm
        if algorithm is not None:
            if algorithm.lower() in FILE_HASH_TYPES_MAPPER:
                file_hashes.add(value)
        elif pattern_value.object_type in PATTERN_VALUE_TYPES:
            values.add(value)
    return values, file_hashes


def _floor_second(value: datetime) -> datetime:
    """Return a date without its fraction of a second."""
    return value.replace(microsecond=0)


def _ceil_second(value: datetime) -> datetime:
    """Return a date rounded up to the next whole second."""
    floored = _floor_second(value)
    return floored if floored == value else floored + timedelta(seconds=1)


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

    # The read-back pages `$skip` offsets of a collection whose order Defender does
    # not document (no `$orderby`): an absence is confirmed by an exact lookup.
    confirms_absence = True

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
                opencti_id = indicator.get("externalId") or indicator.get("externalID")
                yield VendorIndicator(
                    indicator_id=str(opencti_id) if opencti_id else None,
                    external_id=str(defender_id),
                    value=indicator.get("indicatorValue"),
                    raw={"id": defender_id},
                    active=_is_live(indicator, now),
                )

    def confirm_absent(self, deployment: IndicatorDeployment) -> bool:
        """Look the values the connector pushes for a deployment up on Defender, one
        by one.

        An indicator the paged read-back missed (rows moving between two offset
        pages) is found by its exact value, so it is never reported removed. The
        other values of the pattern never have a Defender indicator of the
        connector: they are not looked up, and a pattern holding none of the pushed
        values is absent. Only the Defender indicators the read-back would match to
        the deployment count:
        one pushed for another OpenCTI indicator holding the same value does not,
        so a withdrawal or a deletion in Defender is still reported. An expired
        indicator does not count either, as in the read-back: Defender computes
        its expiry from the indicator update, not from its OpenCTI validity.

        :param deployment: The deployment missing from the read-back.
        :return: False when a live Defender indicator of the deployment holds one of the values.
        :raises DefenderDeploymentError: On any API error.
        """
        now = self._clock()
        values, file_hashes = _defender_values(deployment)
        with _readable_errors():
            for value in sorted(values | file_hashes):
                for indicator in self._api.find_indicators(value) or []:
                    if (
                        indicator.get("application") == APPLICATION_NAME
                        and _belongs_to(indicator, deployment)
                        and _is_live(indicator, now)
                    ):
                        return False
        return True

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
        are covered when one of their hashes is on Defender. A STIX pattern without
        any value Defender takes is never complete: its Defender indicators are left
        from an earlier pattern. A pattern the adapter cannot read (missing or not
        STIX) trusts its Defender indicators.

        :param deployment: The deployment.
        :param vendor_matches: Its Defender indicators.
        :return: False when an observable has no Defender indicator.
        """
        if not deployment.pattern or deployment.pattern_type not in (None, "stix"):
            return True
        vendor_values = {
            normalized
            for vendor_indicator in vendor_matches
            if (normalized := normalize_value(vendor_indicator.value))
        }
        values, file_hashes = _defender_values(deployment)
        return (
            bool(values or file_hashes)
            and values <= vendor_values
            and (not file_hashes or not file_hashes.isdisjoint(vendor_values))
        )

    def push_indicator(self, stix_indicator: dict[str, Any]) -> str | None:
        """Push an indicator again, with the stream create path.

        :return: The id of the first Defender indicator created.
        :raises DefenderDeploymentError: When Defender rejects the indicator, with the
            reason OpenCTI shows (the Defender response is logged).
        :raises ValueError: When no observable of the indicator can be pushed.
        """
        try:
            defender_ids = self._connector.push_indicator(stix_indicator)
        except DefenderApiHandlerError as err:
            self._connector.helper.connector_logger.warning(
                "Indicator not pushed again to Microsoft Defender",
                meta={"error": describe_error(err)},
            )
            raise DefenderDeploymentError(failure_reason(err)) from err
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
        a value shared by several indicators credits each of them. Only the values
        the connector pushes to Defender match: a value of the pattern Defender never
        holds (such as a network traffic address or an artifact hash) credits no hit.

        :param resume: End of the first window to read, when the previous read ran
            out of requests while still halving the windows starting at `since`.
        :raises DefenderDeploymentError: When the alerts cannot be listed.
        """
        by_value: dict[str, list[IndicatorDeployment]] = {}
        for deployment in deployments:
            values, file_hashes = _defender_values(deployment)
            for value in values | file_hashes:
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
        the next read starts at its end; later in the read, the read stops at its
        start. The alerts filter has a one-second precision, so the windows end
        and are split on whole seconds: no alert falls between a window read and
        the date returned after it.

        :param first_end: End of the first window to read (see `collect_hits`).
        :return: The alerts; `None` when every window was read, otherwise the date
            until which the alerts are complete; and, when that date is `since`, the
            end of the first window still to read, if any.
        """
        now = _ceil_second(self._clock())
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
            middle = _floor_second(start + (end - start) / 2)
            if end - start <= MIN_HIT_WINDOW or middle <= start:
                if start <= since:
                    return alerts + window_alerts, end, None
                return alerts, start, None
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
