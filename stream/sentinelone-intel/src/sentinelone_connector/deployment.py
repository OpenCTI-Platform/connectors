"""Deployment write-back (dissemination assurance) of the SentinelOne Intel connector.

The `SentinelOneDeploymentAdapter` gives the connectors SDK reconciliation access to
the SentinelOne Threat Intelligence IOCs:

- read-back: the IOCs of the scope of the connector (account or site,
  `threat-intelligence/iocs`, paginated with `cursor`), matched with the deployments
  by their external id when it is the STIX id of the indicator, else by value; the
  expired IOCs SentinelOne retains are listed inactive;
- removal: deletion of the IOCs whose external id is the STIX id of the indicator
  (IOCs created by other sources are left in place);
- re-push: the stream create path.

A scope naming a group cannot be listed (the listing is scoped by account and site
only): the `SentinelOnePushAdapter` then only pushes the pending deployments again.

SentinelOne exposes no match count of the Threat Intelligence IOCs, so no hit is
reported.
"""

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from connectors_sdk import (
    DeploymentAssurance,
    DeploymentPushAdapter,
    DeploymentVendorAdapter,
    IndicatorDeployment,
    VendorIndicator,
)
from connectors_sdk.connectors.stream.deployment import normalize_value, parse_datetime
from sentinelone_connector.connector import STIX_INDICATOR_PREFIX, failure_reason
from sentinelone_services import SentinelOneApiError

if TYPE_CHECKING:
    from sentinelone_connector.connector import SentinelOneIntelConnector


class SentinelOneDeploymentError(Exception):
    """A read-back or removal refused by the reconciliation, with a readable message."""


def _valid_until(ioc: dict[str, Any]) -> datetime | None:
    """Return the expiry of an IOC, `None` when it has none.

    :raises SentinelOneDeploymentError: On a `validUntil` that is not an ISO 8601
        date, which would otherwise read as no expiry and confirm an expired IOC.
    """
    raw = ioc.get("validUntil")
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return None
    valid_until = parse_datetime(raw) if isinstance(raw, str) else None
    if valid_until is None:
        raise SentinelOneDeploymentError(
            "SentinelOne listed an IOC with an unreadable validUntil, "
            "the read-back is incomplete"
        )
    return valid_until


class SentinelOneDeploymentAdapter(DeploymentVendorAdapter):
    """Vendor operations of the deployment reconciliation for SentinelOne."""

    def __init__(self, connector: "SentinelOneIntelConnector") -> None:
        """Initialize the adapter.

        :param connector: The connector, whose client and create path are used.
        """
        self._connector = connector

    def list_vendor_indicators(self) -> Iterator[VendorIndicator]:
        """Read back the IOCs of the scope of the connector.

        IOCs whose `validUntil` is in the past are retained by SentinelOne but no
        longer enforced: they are listed inactive, so that a withdrawal removes them
        and they never confirm a deployment.

        :raises SentinelOneApiError: On any API error (never a partial listing).
        :raises SentinelOneDeploymentError: On an IOC without `uuid` or value, which
            would otherwise read as absent, or with an unreadable `validUntil`.
        """
        now = datetime.now(UTC)
        for ioc in self._connector.client.iter_iocs():
            uuid = ioc.get("uuid")
            value = ioc.get("value")
            if (
                not isinstance(uuid, str)
                or not uuid
                or not isinstance(value, str)
                or not value
            ):
                raise SentinelOneDeploymentError(
                    "SentinelOne listed an IOC without uuid or value, "
                    "the read-back is incomplete"
                )
            valid_until = _valid_until(ioc)
            external_id = ioc.get("externalId")
            opencti_id = (
                external_id
                if isinstance(external_id, str)
                and external_id.startswith(STIX_INDICATOR_PREFIX)
                else None
            )
            yield VendorIndicator(
                indicator_id=opencti_id,
                external_id=str(uuid),
                value=value,
                raw={"uuid": str(uuid), "externalId": external_id},
                active=valid_until is None or valid_until > now,
            )

    def remove_vendor_indicator(
        self, vendor_indicator: VendorIndicator, deployment: IndicatorDeployment
    ) -> None:
        """Delete an IOC created from the indicator (withdrawal, revocation or expiry).

        :raises SentinelOneDeploymentError: When the IOC does not carry the STIX id of
            the indicator (created by another source, left in place).
        :raises SentinelOneApiError: When SentinelOne refuses the deletion.
        """
        uuid = vendor_indicator.raw.get("uuid") or vendor_indicator.external_id
        external_id = normalize_value(vendor_indicator.raw.get("externalId"))
        if external_id is None or external_id not in deployment.identifiers:
            raise SentinelOneDeploymentError(
                f"The SentinelOne IOC {uuid} was not created from this indicator "
                "(its external id is not the STIX id of the indicator), it is left in place"
            )
        self._connector.client.delete_iocs([str(uuid)])

    def push_indicator(self, stix_indicator: dict[str, Any]) -> str | None:
        """Push an indicator again, with the stream create path (see `_push_again`)."""
        return _push_again(self._connector, stix_indicator)


class SentinelOnePushAdapter(DeploymentPushAdapter):
    """Re-push of the pending deployments, for a scope naming a group.

    The Threat Intelligence IOCs listing is scoped by account and site only, so the
    IOCs of a group cannot be read back apart from those of the other groups of its
    site or account: the deployments come from the pushes and deletions of the
    stream, and the reconciliation pushes the `pending` ones again.
    """

    def __init__(self, connector: "SentinelOneIntelConnector") -> None:
        """Initialize the adapter.

        :param connector: The connector, whose create path is used.
        """
        self._connector = connector

    def push_indicator(self, stix_indicator: dict[str, Any]) -> str | None:
        """Push an indicator again, with the stream create path (see `_push_again`)."""
        return _push_again(self._connector, stix_indicator)


def _push_again(
    connector: "SentinelOneIntelConnector", stix_indicator: dict[str, Any]
) -> str | None:
    """Push an indicator again, with the stream create path.

    :return: The `uuid` of the first IOC created, if returned by SentinelOne.
    :raises SentinelOneDeploymentError: When SentinelOne rejects the indicator or
        cannot be reached, with the reason OpenCTI shows (the SentinelOne response
        is logged).
    :raises ValueError: When the pattern of the indicator is not supported.
    """
    try:
        return connector.push_indicator(stix_indicator)
    except SentinelOneApiError as err:
        connector.helper.connector_logger.warning(
            "[DEPLOYMENT] SentinelOne did not take an indicator pushed again.",
            meta={"indicator_id": stix_indicator.get("id"), "error": str(err)},
        )
        raise SentinelOneDeploymentError(failure_reason(err)) from err


def build_deployment_assurance(
    connector: "SentinelOneIntelConnector",
) -> DeploymentAssurance:
    """Build the deployment write-back of the connector, reconciliation included.

    With a group in the scope, the reconciliation pushes the pending deployments
    again without reading the IOCs back (see `SentinelOnePushAdapter`).

    :param connector: The connector (settings `deployment` and `security_platform`).
    :return: The deployment write-back, a no-op when `DEPLOYMENT_REPORTING_ENABLED` is false.
    """
    adapter: DeploymentPushAdapter
    if connector.client.lists_scope:
        adapter = SentinelOneDeploymentAdapter(connector)
    else:
        connector.helper.connector_logger.info(
            "[DEPLOYMENT] The scope names a SentinelOne group, whose IOCs the Threat "
            "Intelligence IOCs API cannot list: deployments are reported from the "
            "pushes and deletions of the stream, without read-back.",
            meta={"group_id": connector.client.config.group_id},
        )
        adapter = SentinelOnePushAdapter(connector)
    return DeploymentAssurance.from_settings(
        connector.helper,
        connector.config,
        adapter=adapter,
    )
