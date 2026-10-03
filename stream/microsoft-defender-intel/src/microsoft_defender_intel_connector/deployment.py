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

from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from connectors_sdk import (
    DeploymentAssurance,
    DeploymentVendorAdapter,
    IndicatorDeployment,
    VendorHit,
    VendorIndicator,
)
from connectors_sdk.connectors.stream.deployment import normalize_value, parse_datetime
from microsoft_defender_intel_connector.api_handler import (
    APPLICATION_NAME,
    MAX_PAGE_SIZE,
    DefenderApiHandler,
    DefenderApiHandlerError,
)

if TYPE_CHECKING:
    from microsoft_defender_intel_connector.connector import (
        MicrosoftDefenderIntelConnector,
    )

MAX_HIT_ALERTS = MAX_PAGE_SIZE
"""Maximum number of alerts read by one hit collection."""

MAX_ERROR_DETAIL_LENGTH = 500
"""Maximum length of the Defender response appended to a deployment error."""

EVIDENCE_VALUE_FIELDS = ("sha1", "sha256", "md5", "ipAddress", "url")
"""Evidence fields compared with the indicator values (`domainName` is an account domain)."""


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
    """Return the normalized observable values of the evidence of an alert."""
    values: set[str] = set()
    for evidence in alert.get("evidence") or []:
        if not isinstance(evidence, dict):
            continue
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

    def __init__(self, connector: "MicrosoftDefenderIntelConnector") -> None:
        """Initialize the adapter.

        :param connector: The connector, whose API handler and create path are used.
        """
        self._connector = connector

    @property
    def _api(self) -> DefenderApiHandler:
        return self._connector.api

    def list_vendor_indicators(self) -> Iterator[VendorIndicator]:
        """Read back the active Defender indicators created by the connector.

        Indicators whose `expirationTime` is in the past are not live.

        :raises DefenderDeploymentError: On any API error (never a partial listing).
        """
        now = datetime.now(UTC)
        with _readable_errors():
            for indicator in self._api.iter_application_indicators(APPLICATION_NAME):
                defender_id = indicator.get("id")
                if defender_id is None:
                    continue
                expiration = parse_datetime(indicator.get("expirationTime"))
                if expiration is not None and expiration <= now:
                    continue
                opencti_id = indicator.get("externalId") or indicator.get("externalID")
                yield VendorIndicator(
                    indicator_id=str(opencti_id) if opencti_id else None,
                    external_id=str(defender_id),
                    value=indicator.get("indicatorValue"),
                    raw={"id": defender_id},
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
        self, deployments: Sequence[IndicatorDeployment], since: datetime
    ) -> Iterable[VendorHit]:
        """Read the Defender alerts whose evidence matches deployed indicators.

        Each alert counts one hit per matching indicator, at the alert creation time.

        :raises DefenderDeploymentError: When the alerts cannot be listed.
        """
        by_value: dict[str, IndicatorDeployment] = {}
        for deployment in deployments:
            for value in deployment.values:
                by_value.setdefault(value, deployment)
        if not by_value:
            return []
        with _readable_errors():
            alerts = self._api.list_alerts(since, MAX_HIT_ALERTS)
        hits: list[VendorHit] = []
        for alert in alerts:
            timestamp = parse_datetime(
                alert.get("alertCreationTime") or alert.get("firstEventTime")
            )
            if timestamp is None or timestamp < since:
                continue
            matched = {
                by_value[value].indicator_id
                for value in _evidence_values(alert)
                if value in by_value
            }
            hits.extend(
                VendorHit(timestamp=timestamp, indicator_id=indicator_id)
                for indicator_id in sorted(matched)
            )
        return hits


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
