"""Deployment write-back of the CrowdStrike Endpoint Security connector.

The adapter lets the connectors SDK reconcile the deployment status of the indicators
pushed to CrowdStrike Falcon (IOC Management) and report the detections they raised.
"""

from collections.abc import Callable, Iterable, Iterator, Sequence
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from connectors_sdk import (
    DeploymentAssurance,
    DeploymentVendorAdapter,
    HitCollection,
    IndicatorDeployment,
    VendorHit,
    VendorIndicator,
)
from connectors_sdk.connectors.stream.deployment import normalize_value, parse_datetime
from crowdstrike_services import (
    IOC_SOURCE,
    TO_DELETE_TAG,
    CrowdstrikeApiError,
    CrowdstrikeClient,
    IocOperationStatus,
    alert_id,
)

if TYPE_CHECKING:
    from crowdstrike_connector.connector import CrowdstrikeConnector
    from crowdstrike_connector.settings import CrowdstrikeEndpointSecurityConfig

DEFAULT_MAX_ALERTS = 10_000
"""Maximum number of alerts read by one hit collection."""


class CrowdstrikeDeploymentAdapter(DeploymentVendorAdapter):
    """Vendor operations of the deployment reconciliation for CrowdStrike Falcon.

    - Read-back: the IOCs created by the connector's API client (``created_by``) with
      the connector's source (``OpenCTI IOC``), excluding expired IOCs and the IOCs
      withdrawn by the connector (tagged ``TO_DELETE`` and no longer detecting).
    - Removal: permanent deletion when ``CROWDSTRIKE_PERMANENT_DELETE`` is true,
      otherwise the IOC is kept but stops detecting (action ``no_action``).
    - Re-push: the stream create path.
    - Hits: Falcon alerts whose IOC value matches a deployed indicator.
    """

    def __init__(
        self,
        client: CrowdstrikeClient,
        config: "CrowdstrikeEndpointSecurityConfig",
        *,
        max_alerts: int = DEFAULT_MAX_ALERTS,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Initialize the adapter.

        Args:
            client: The CrowdStrike client of the connector.
            config: The ``crowdstrike`` configuration namespace.
            max_alerts: Maximum number of alerts read by one hit collection.
            clock: Current time provider (injectable for tests).
        """
        self._client = client
        self._config = config
        self._max_alerts = max_alerts
        self._clock = clock or (lambda: datetime.now(UTC))

    def list_vendor_indicators(self) -> Iterator[VendorIndicator]:
        """Read back the live IOCs managed by the connector.

        Yields:
            One vendor indicator per live IOC (IOC id and value).

        Raises:
            CrowdstrikeApiError: On any CrowdStrike error.
        """
        now = self._clock()
        for ioc in self._client.iter_connector_iocs():
            if not self._is_live(ioc, now):
                continue
            yield VendorIndicator(
                external_id=str(ioc["id"]),
                value=ioc.get("value"),
                raw=ioc,
            )

    @staticmethod
    def _is_live(ioc: dict[str, Any], now: datetime) -> bool:
        """Tell whether an IOC read back from CrowdStrike is live and ours."""
        if not ioc.get("id") or ioc.get("source") != IOC_SOURCE:
            return False
        if ioc.get("deleted") is True or ioc.get("expired") is True:
            return False
        expiration = parse_datetime(ioc.get("expiration"))
        if expiration is not None and expiration <= now:
            return False
        withdrawn = TO_DELETE_TAG in (ioc.get("tags") or [])
        return not (withdrawn and ioc.get("action") == "no_action")

    def remove_vendor_indicator(
        self, vendor_indicator: VendorIndicator, deployment: IndicatorDeployment
    ) -> None:
        """Withdraw an IOC from CrowdStrike.

        Args:
            vendor_indicator: The IOC, as listed.
            deployment: The deployment requesting the removal.

        Raises:
            CrowdstrikeApiError: When CrowdStrike refuses the operation.
        """
        if self._config.permanent_delete:
            self._client.delete_ioc(str(vendor_indicator.external_id))
        else:
            self._client.deactivate_ioc(dict(vendor_indicator.raw))

    def push_indicator(self, stix_indicator: dict[str, Any]) -> str | None:
        """Push an indicator again through the stream create path.

        Args:
            stix_indicator: The indicator in the stream event shape.

        Returns:
            The CrowdStrike IOC id.

        Raises:
            ValueError: When the indicator type is not supported by CrowdStrike.
            CrowdstrikeApiError: When CrowdStrike rejects the push.
        """
        result = self._client.create_indicator(stix_indicator, "create")
        if result.is_live:
            return result.ioc_id
        if result.status == IocOperationStatus.SKIPPED:
            raise ValueError("The indicator type is not supported by CrowdStrike")
        raise CrowdstrikeApiError(result.error or f"IOC push {result.status}")

    def collect_hits(
        self,
        deployments: Sequence[IndicatorDeployment],
        since: datetime,
        *,
        resume: frozenset[str] | None = None,
    ) -> Iterable[VendorHit] | HitCollection:
        """Read the Falcon alerts raised by deployed indicators since a date.

        An alert counts as one hit of every deployed indicator whose value is the
        alert IOC value (``ioc_value``, ``ioc_values`` or ``ioc_context``), at the
        alert creation time: the listing is filtered and ordered by it, so the
        reading cursor and the hit times never diverge.

        Args:
            deployments: The live deployments.
            since: Only alerts created after this date are read.
            resume: Ids of the alerts already read at ``since``, when the previous
                read was capped there.

        Returns:
            The hits. When ``max_alerts`` alerts were read (oldest first), the
            collection is complete until the newest alert read; when none of them
            is after ``since``, the next read skips the alerts already read there.
        """
        by_value: dict[str, list[IndicatorDeployment]] = {}
        for deployment in deployments:
            for value in deployment.values:
                by_value.setdefault(value, []).append(deployment)
        if not by_value:
            return []
        already_read = resume or frozenset()
        read_at_start: set[str] = set(already_read)
        hits: list[VendorHit] = []
        read = 0
        newest: datetime = since
        for alert in self._client.iter_alerts(
            since, self._max_alerts, exclude_ids=already_read
        ):
            read += 1
            timestamp = parse_datetime(
                alert.get("created_timestamp") or alert.get("timestamp")
            )
            if timestamp is None or timestamp <= since:
                identifier = alert_id(alert)
                if identifier:
                    read_at_start.add(identifier)
            if timestamp is None or timestamp < since:
                continue
            newest = max(newest, timestamp)
            matched = {
                deployment.indicator_id
                for value in self._alert_values(alert)
                for deployment in by_value.get(value, ())
            }
            hits.extend(
                VendorHit(timestamp=timestamp, indicator_id=indicator_id)
                for indicator_id in sorted(matched)
            )
        if read >= self._max_alerts:
            if newest <= since:
                return HitCollection(
                    hits=hits, complete_until=since, resume=frozenset(read_at_start)
                )
            return HitCollection(hits=hits, complete_until=newest)
        return hits

    @staticmethod
    def _alert_values(alert: dict[str, Any]) -> set[str]:
        """Return the normalized IOC values carried by an alert."""
        raw_values: list[Any] = [alert.get("ioc_value")]
        raw_values.extend(alert.get("ioc_values") or [])
        for context in alert.get("ioc_context") or []:
            if isinstance(context, dict):
                raw_values.append(context.get("ioc_value"))
        return {
            normalized
            for raw_value in raw_values
            if isinstance(raw_value, str) and (normalized := normalize_value(raw_value))
        }


def build_deployment_assurance(
    connector: "CrowdstrikeConnector",
) -> DeploymentAssurance:
    """Build the deployment write-back of the connector, reconciliation and hits included.

    Args:
        connector: The connector (settings ``deployment``, ``hits`` and
            ``security_platform``, CrowdStrike client).

    Returns:
        The deployment write-back, a no-op when ``DEPLOYMENT_REPORTING_ENABLED`` is false.
    """
    return DeploymentAssurance.from_settings(
        connector.helper,
        connector.config,
        adapter=CrowdstrikeDeploymentAdapter(
            connector.client, connector.config.crowdstrike
        ),
    )
