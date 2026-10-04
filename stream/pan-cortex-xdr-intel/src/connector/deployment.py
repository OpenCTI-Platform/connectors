"""Deployment write-back (dissemination assurance) of the Cortex XDR Intel connector.

The `CortexXdrDeploymentAdapter` gives the connectors SDK reconciliation access to
Palo Alto Cortex XDR:

- read-back: the IOCs of the tenant (`indicators/get`, paginated), matched with the
  deployments by `rule_id` and by value (Cortex XDR does not store the OpenCTI id); an
  indicator is only `active` when Cortex XDR holds an IOC for each of its values, and
  is upserted again otherwise;
- removal: deletion of each IOC of the indicator, except the ones another live
  indicator shares;
- re-push: the stream upsert path;
- hits: the IOC alerts (`alert_source` "XDR IOC") whose events carry the value of a
  deployed indicator.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from connectors_sdk import (
    ApiClientError,
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
)
from cortex_xdr_client import CortexXdrApiError

if TYPE_CHECKING:
    from connector.connector import Connector
    from connector.models import CortexXdrIoc
    from cortex_xdr_client import CortexXdrClient

MAX_HIT_ALERTS = 10_000
"""Maximum number of IOC alerts read by one hit collection."""

PUSHED_OBSERVABLE_TYPES = frozenset({"domain-name", "ipv4-addr", "email-addr", "url"})
"""STIX observable types whose `value` the connector pushes as an IOC (besides hashes)."""

MAX_ERROR_DETAIL_LENGTH = 500
"""Maximum length of the Cortex XDR response appended to a logged error."""

PLATFORM_NAME = "Cortex XDR"
"""Name of the security platform in the deployment failure reasons."""

PUSH_ACTION = "IOC upsert"
"""What Cortex XDR is asked to do when an indicator is pushed."""

EVENT_VALUE_FIELDS = (
    "action_remote_ip",
    "action_local_ip",
    "action_external_hostname",
    "dst_action_external_hostname",
    "dns_query_name",
    "fw_url_domain",
    "fw_email_sender",
    "fw_email_recipient",
    "action_file_md5",
    "action_file_sha256",
    "action_file_macro_sha256",
    "action_process_image_md5",
    "action_process_image_sha256",
    "actor_process_image_md5",
    "actor_process_image_sha256",
    "causality_actor_process_image_md5",
    "causality_actor_process_image_sha256",
    "os_actor_process_image_sha256",
)
"""Alert and event fields compared with the values of the deployed indicators."""


def describe_error(error: BaseException) -> str:
    """Describe a Cortex XDR error in full, for the connector logs.

    :param error: The error raised by the client or the connector.
    :return: The message, followed by the HTTP status and the Cortex XDR response body.
    """
    message = str(error) or type(error).__name__
    cause = error.__cause__
    if isinstance(cause, ApiClientError):
        message = f"{message}: {cause}"
        if cause.status_code is not None:
            message = f"{message} (HTTP {cause.status_code})"
        body = cause.response_body
        if body:
            detail = body if isinstance(body, str) else json.dumps(body, default=str)
            message = f"{message} - {detail[:MAX_ERROR_DETAIL_LENGTH]}"
    elif cause is not None:
        message = f"{message}: {cause}"
    return message


def failure_reason(error: BaseException) -> str:
    """Return the reason OpenCTI shows for an indicator Cortex XDR did not take.

    :param error: The error raised by the client or the connector.
    :return: One short sentence naming Cortex XDR and the cause; the Cortex XDR
        response is left to the logs (`describe_error`).
    """
    cause = error.__cause__
    if isinstance(cause, ApiClientError):
        return deployment_failure_reason(PLATFORM_NAME, PUSH_ACTION, cause.status_code)
    if isinstance(error, CortexXdrApiError):
        # Raised by the client on a successful response it cannot read.
        return deployment_failure_reason(PLATFORM_NAME, PUSH_ACTION, 200)
    if isinstance(error, OSError):
        # Transport errors of `requests` (connection, timeout) are OSErrors.
        return deployment_failure_reason(PLATFORM_NAME, PUSH_ACTION)
    return str(error) or type(error).__name__


def rule_ids_of(response: Any, xdr_iocs: Sequence[CortexXdrIoc]) -> list[str]:
    """Return the `rule_id`s of upserted IOCs.

    :param response: The `insert_iocs` response (`added_objects` / `updated_objects`).
    :param xdr_iocs: The IOCs sent, carrying the `rule_id` of the existing ones.
    :return: The ids returned by Cortex XDR, else the ids resolved before the upsert.
    """
    rule_ids: list[str] = []
    if isinstance(response, Mapping):
        for key in ("added_objects", "updated_objects"):
            for item in response.get(key) or []:
                if isinstance(item, Mapping) and item.get("id") is not None:
                    rule_ids.append(str(item["id"]))
    if not rule_ids:
        rule_ids = [str(ioc.rule_id) for ioc in xdr_iocs if ioc.rule_id is not None]
    return rule_ids


class CortexXdrDeploymentError(Exception):
    """A Cortex XDR error raised to the reconciliation, with a readable message."""


@contextmanager
def _readable_errors() -> Iterator[None]:
    """Re-raise client errors with their HTTP status and response body."""
    try:
        yield
    except CortexXdrApiError as err:
        raise CortexXdrDeploymentError(describe_error(err)) from err


def _timestamp(value: Any) -> datetime | None:
    """Convert a Cortex XDR timestamp in milliseconds to a UTC datetime."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    try:
        return datetime.fromtimestamp(value / 1000, UTC)
    except (OverflowError, OSError, ValueError):
        return None


def _candidate_values(item: Mapping[str, Any]) -> set[str]:
    """Return the normalized values of the matching fields of an alert or event."""
    values: set[str] = set()
    for field_name in EVENT_VALUE_FIELDS:
        raw = item.get(field_name)
        for raw_value in raw if isinstance(raw, list) else [raw]:
            if not isinstance(raw_value, str) or not (
                normalized := normalize_value(raw_value)
            ):
                continue
            values.add(normalized)
            if "://" in normalized:
                # Domain indicators match the host of a URL value.
                host = urlsplit(normalized).hostname
                if host:
                    values.add(host)
    return values


def _alert_values(alert: Mapping[str, Any]) -> set[str]:
    """Return the normalized observable values of an alert and of its events."""
    values = _candidate_values(alert)
    for event in alert.get("events") or []:
        if isinstance(event, Mapping):
            values |= _candidate_values(event)
    return values


class CortexXdrDeploymentAdapter(DeploymentVendorAdapter):
    """Vendor operations of the deployment reconciliation for Cortex XDR."""

    def __init__(self, connector: Connector) -> None:
        """Initialize the adapter.

        :param connector: The connector, whose client and upsert path are used.
        """
        self._connector = connector

    @property
    def _client(self) -> CortexXdrClient:
        return self._connector.client

    def list_vendor_indicators(self) -> Iterator[VendorIndicator]:
        """Read back the IOCs of the tenant.

        IOCs whose `expiration_date` is in the past are retained by Cortex XDR but no
        longer enforced: they are listed inactive, so that a withdrawal deletes them
        and they never confirm a deployment.

        :raises CortexXdrDeploymentError: On any API error, or an IOC without value
            (never a partial listing).
        """
        now = datetime.now(UTC)
        with _readable_errors():
            for ioc in self._client.iter_iocs():
                value = ioc.get("indicator")
                if not isinstance(value, str) or not value:
                    raise CortexXdrDeploymentError(
                        "Cortex XDR listed an IOC without value, "
                        "the read-back is incomplete"
                    )
                expiration = _timestamp(ioc.get("expiration_date"))
                rule_id = ioc.get("rule_id")
                yield VendorIndicator(
                    external_id=str(rule_id) if rule_id is not None else None,
                    value=value,
                    raw={"indicator": value, "type": ioc.get("type")},
                    active=expiration is None or expiration > now,
                )

    def expected_values(self, deployment: IndicatorDeployment) -> frozenset[str] | None:
        """Return the normalized values pushed for an indicator, one Cortex XDR IOC each.

        Cortex XDR does not store the OpenCTI id: the reconciliation matches every IOC
        holding one of these values, removes each of them on withdrawal and only
        confirms the indicator `active` when Cortex XDR holds all of them (it is
        upserted again otherwise).

        :param deployment: A deployment of the platform.
        :return: The hashes, domain names, IPv4 addresses, email addresses and URLs of
            the pattern, or None when it has none.
        """
        values = frozenset(
            normalized
            for pattern_value in extract_pattern_values(deployment.pattern)
            if (
                pattern_value.hash_algorithm is not None
                or (
                    pattern_value.object_type in PUSHED_OBSERVABLE_TYPES
                    and pattern_value.object_path == "value"
                )
            )
            and (normalized := normalize_value(pattern_value.value))
        )
        return values or None

    def remove_vendor_indicator(
        self, vendor_indicator: VendorIndicator, deployment: IndicatorDeployment
    ) -> None:
        """Delete an IOC from Cortex XDR (withdrawal, revocation or expiry).

        The reconciliation calls it for each IOC of the indicator (a file indicator has
        one IOC per hash), except the IOCs another live indicator shares.

        :raises CortexXdrDeploymentError: When Cortex XDR refuses the deletion.
        """
        value = vendor_indicator.raw.get("indicator") or vendor_indicator.value
        with _readable_errors():
            self._client.delete_iocs(
                [{"field": "indicator", "operator": "IN", "value": [value]}]
            )

    def push_indicator(self, stix_indicator: dict[str, Any]) -> str | None:
        """Push an indicator again, with the stream upsert path.

        :return: The `rule_id` of the first Cortex XDR IOC, if known.
        :raises CortexXdrDeploymentError: When Cortex XDR rejects the indicator or
            cannot be reached, with the reason OpenCTI shows (the Cortex XDR
            response is logged).
        :raises ValueError: When no observable of the indicator can be pushed.
        """
        try:
            return self._connector.push_indicator(stix_indicator)
        except (CortexXdrApiError, OSError) as err:
            self._connector.helper.connector_logger.warning(
                "[DEPLOYMENT] Cortex XDR did not take an indicator pushed again.",
                {
                    "indicator_id": stix_indicator.get("id"),
                    "error": describe_error(err),
                },
            )
            raise CortexXdrDeploymentError(failure_reason(err)) from err

    def collect_hits(
        self, deployments: Sequence[IndicatorDeployment], since: datetime
    ) -> Iterable[VendorHit] | HitCollection:
        """Read the IOC alerts whose events match deployed indicators.

        Each alert counts one hit per matching indicator, at its creation time
        (`local_insert_ts`, the detection time when Cortex XDR gives none), so the
        query window, the continuation and the hit dates share one axis. Alerts are
        read by creation time, oldest first: when `MAX_HIT_ALERTS` alerts were read,
        the collection is complete until the creation time of the newest alert read
        and the next run resumes there.

        :raises CortexXdrDeploymentError: When the alerts cannot be listed, or an
            alert has no creation or detection time (the window is read again).
        """
        by_value: dict[str, list[IndicatorDeployment]] = {}
        for deployment in deployments:
            for value in deployment.values:
                by_value.setdefault(value, []).append(deployment)
        if not by_value:
            return []
        with _readable_errors():
            alerts = self._client.get_ioc_alerts(since, MAX_HIT_ALERTS)
        hits: list[VendorHit] = []
        newest_created = since
        for alert in alerts:
            timestamp = _timestamp(alert.get("local_insert_ts")) or _timestamp(
                alert.get("detection_timestamp")
            )
            if timestamp is None:
                raise CortexXdrDeploymentError(
                    "Cortex XDR listed an IOC alert without creation time, "
                    "the hit read is incomplete"
                )
            newest_created = max(newest_created, timestamp)
            if timestamp < since:
                continue
            matched = {
                deployment.indicator_id
                for value in _alert_values(alert)
                for deployment in by_value.get(value, ())
            }
            hits.extend(
                VendorHit(timestamp=timestamp, indicator_id=indicator_id)
                for indicator_id in sorted(matched)
            )
        if len(alerts) >= MAX_HIT_ALERTS:
            return HitCollection(hits=hits, complete_until=newest_created)
        return hits


def build_deployment_assurance(connector: Connector) -> DeploymentAssurance:
    """Build the deployment write-back of the connector, reconciliation and hits included.

    :param connector: The connector (settings `deployment`, `hits` and `security_platform`).
    :return: The deployment write-back, a no-op when `DEPLOYMENT_REPORTING_ENABLED` is false.
    """
    return DeploymentAssurance.from_settings(
        connector.helper,
        connector.settings,
        adapter=CortexXdrDeploymentAdapter(connector),
    )
