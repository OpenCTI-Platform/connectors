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
        """Read back the IOCs managed by the connector.

        Expired IOCs and IOCs the connector deactivated stay in CrowdStrike: they
        are listed as inactive, for a withdrawal to delete or deactivate them.

        Yields:
            One vendor indicator per IOC (IOC id and value).

        Raises:
            CrowdstrikeApiError: On any CrowdStrike error.
        """
        now = self._clock()
        for ioc in self._client.iter_connector_iocs():
            if not ioc.get("id"):
                # Never skipped: its deployment would look absent.
                raise CrowdstrikeApiError("An IOC of the read-back carries no id")
            if not self._is_retained(ioc):
                continue
            yield VendorIndicator(
                external_id=str(ioc["id"]),
                value=ioc.get("value"),
                raw=ioc,
                active=self._is_live(ioc, now),
            )

    @staticmethod
    def _is_retained(ioc: dict[str, Any]) -> bool:
        """Tell whether an IOC read back from CrowdStrike is ours and not deleted."""
        return (
            bool(ioc.get("id"))
            and ioc.get("source") == IOC_SOURCE
            and ioc.get("deleted") is not True
        )

    @staticmethod
    def _is_live(ioc: dict[str, Any], now: datetime) -> bool:
        """Tell whether an IOC read back from CrowdStrike is live and ours."""
        if not CrowdstrikeDeploymentAdapter._is_retained(ioc):
            return False
        if ioc.get("expired") is True:
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

        An alert counts as one hit of every deployed indicator whose pushed IOC value
        is an alert IOC value (``ioc_value``, ``ioc_values`` or ``ioc_context``), at the
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
            if value := self._pushed_value(deployment):
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
            if timestamp is None:
                # Never skipped: the hit cursor would move past its IOC matches.
                raise CrowdstrikeApiError(
                    "An alert of the hit read carries no creation time"
                )
            if timestamp <= since:
                identifier = alert_id(alert)
                if identifier:
                    read_at_start.add(identifier)
            if timestamp < since:
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

    def expected_values(self, deployment: IndicatorDeployment) -> frozenset[str]:
        """Return the IOC value the connector pushes for a deployment (see
        ``_pushed_value``).

        CrowdStrike IOCs carry no OpenCTI id: declaring the one pushed value keeps the
        reconciliation from confirming or withdrawing a composite indicator through an
        IOC of another value of its pattern, which this connector never pushed for it.

        Args:
            deployment: A deployment of the platform.

        Returns:
            The pushed value, or no value when the connector pushes nothing for the
            pattern.
        """
        value = self._pushed_value(deployment)
        return frozenset({value}) if value else frozenset()

    @staticmethod
    def _pushed_value(deployment: IndicatorDeployment) -> str | None:
        """Return the normalized IOC value the stream pushed for a deployment.

        CrowdStrike holds one IOC per indicator, the first value of its pattern
        (``CrowdstrikeClient._extract_indicator_value``): the other values of a
        composite pattern were never pushed and raise no hit.
        """
        if deployment.pattern_type not in (None, "stix") or not deployment.pattern:
            return None
        try:
            value = CrowdstrikeClient._extract_indicator_value(deployment.pattern)
        except IndexError:
            return None
        return normalize_value(value) or None

    @staticmethod
    def _alert_values(alert: dict[str, Any]) -> set[str]:
        """Return the normalized IOC values carried by an alert.

        Raises:
            CrowdstrikeApiError: When ``ioc_values`` or ``ioc_context`` is not a list,
                or an IOC context is not an object: skipped, its matches would be
                lost as the hit cursor moves past the alert.
        """
        ioc_values = alert.get("ioc_values") or []
        ioc_context = alert.get("ioc_context") or []
        if not isinstance(ioc_values, list) or not isinstance(ioc_context, list):
            raise CrowdstrikeApiError("An alert of the hit read carries malformed IOCs")
        raw_values: list[Any] = [alert.get("ioc_value"), *ioc_values]
        for context in ioc_context:
            if not isinstance(context, dict):
                raise CrowdstrikeApiError(
                    "An alert of the hit read carries an IOC context that is not an "
                    "object"
                )
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
