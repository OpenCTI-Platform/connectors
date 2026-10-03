"""Deployment write-back (dissemination assurance) of the Cortex XDR Intel connector.

The `CortexXdrDeploymentAdapter` gives the connectors SDK reconciliation access to
Palo Alto Cortex XDR:

- read-back: the IOCs of the tenant (`indicators/get`, paginated), matched with the
  deployments by value (Cortex XDR does not store the OpenCTI id);
- removal: deletion of the IOCs carrying the values of the indicator;
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
    IndicatorDeployment,
    VendorHit,
    VendorIndicator,
)
from connectors_sdk.connectors.stream.deployment import (
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

MAX_ERROR_DETAIL_LENGTH = 500
"""Maximum length of the Cortex XDR response appended to a deployment error."""

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
    """Describe a Cortex XDR error for logs and the deployment error message.

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
        """Read back the IOCs of the tenant that are still valid.

        IOCs whose `expiration_date` is in the past are not live.

        :raises CortexXdrDeploymentError: On any API error (never a partial listing).
        """
        now = datetime.now(UTC)
        with _readable_errors():
            for ioc in self._client.iter_iocs():
                value = ioc.get("indicator")
                if not isinstance(value, str) or not value:
                    continue
                expiration = _timestamp(ioc.get("expiration_date"))
                if expiration is not None and expiration <= now:
                    continue
                rule_id = ioc.get("rule_id")
                yield VendorIndicator(
                    external_id=str(rule_id) if rule_id is not None else None,
                    value=value,
                    raw={"indicator": value, "type": ioc.get("type")},
                )

    def remove_vendor_indicator(
        self, vendor_indicator: VendorIndicator, deployment: IndicatorDeployment
    ) -> None:
        """Delete the IOCs of an indicator from Cortex XDR (withdrawal, revocation or expiry).

        Every value of the indicator pattern is deleted (a file indicator has one IOC
        per hash), with the value read back from Cortex XDR.

        :raises CortexXdrDeploymentError: When Cortex XDR refuses the deletion.
        """
        values = [vendor_indicator.raw.get("indicator") or vendor_indicator.value]
        values.extend(
            pattern_value.value
            for pattern_value in extract_pattern_values(deployment.pattern)
        )
        unique_values = list(dict.fromkeys(value for value in values if value))
        with _readable_errors():
            self._client.delete_iocs(
                [{"field": "indicator", "operator": "IN", "value": unique_values}]
            )

    def push_indicator(self, stix_indicator: dict[str, Any]) -> str | None:
        """Push an indicator again, with the stream upsert path.

        :return: The `rule_id` of the first Cortex XDR IOC, if known.
        :raises CortexXdrDeploymentError: When Cortex XDR rejects the indicator.
        :raises ValueError: When no observable of the indicator can be pushed.
        """
        with _readable_errors():
            return self._connector.push_indicator(stix_indicator)

    def collect_hits(
        self, deployments: Sequence[IndicatorDeployment], since: datetime
    ) -> Iterable[VendorHit]:
        """Read the IOC alerts whose events match deployed indicators.

        Each alert counts one hit per matching indicator, at its detection time.

        :raises CortexXdrDeploymentError: When the alerts cannot be listed.
        """
        by_value: dict[str, list[IndicatorDeployment]] = {}
        for deployment in deployments:
            for value in deployment.values:
                by_value.setdefault(value, []).append(deployment)
        if not by_value:
            return []
        with _readable_errors():
            alerts = self._client.get_ioc_alerts(since, MAX_HIT_ALERTS)
        if len(alerts) >= MAX_HIT_ALERTS:
            self._connector.helper.connector_logger.warning(
                "[DEPLOYMENT] More IOC alerts than read by one hit collection, "
                "the oldest ones are not counted.",
                {"limit": MAX_HIT_ALERTS},
            )
        hits: list[VendorHit] = []
        for alert in alerts:
            timestamp = _timestamp(alert.get("detection_timestamp")) or _timestamp(
                alert.get("local_insert_ts")
            )
            if timestamp is None or timestamp < since:
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
