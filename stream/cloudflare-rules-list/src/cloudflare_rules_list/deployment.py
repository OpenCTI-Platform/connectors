"""Deployment write-back (dissemination assurance) of the Cloudflare Rules List connector.

The `CloudflareDeploymentAdapter` gives the connectors SDK reconciliation access to
the Cloudflare Rules List:

- read-back: the items of the list (`rules/lists/{id}/items`, cursor pagination),
  one per IP address, matched with the deployments by the OpenCTI id of their
  comment (`OpenCTI: <id>`) and the indicators of the snapshot holding the address,
  by item id, then by IP address;
- removal: deletion of the list item when it belongs to the indicator (items of
  other objects are left in place) and no other object of the snapshot holds the
  address (the snapshot without the indicator is uploaded instead), and of the
  indicator from the snapshot;
- re-push: the indicator is added to the snapshot, which is uploaded.

Hits are not reported: they are the firewall events of the rules referencing the
list, which the connector does not manage.
"""

from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

from cloudflare_rules_list.client import CloudflareAPIError
from cloudflare_rules_list.connector import COMMENT_PREFIX, failure_reason
from connectors_sdk import (
    DeploymentAssurance,
    DeploymentVendorAdapter,
    IndicatorDeployment,
    VendorIndicator,
)
from connectors_sdk.connectors.stream.deployment import normalize_value

if TYPE_CHECKING:
    from cloudflare_rules_list.connector import Connector

STIX_INDICATOR_PREFIX = "indicator--"


def comment_id(item: dict[str, Any]) -> str | None:
    """Return the OpenCTI id written in the comment of a list item, if any."""
    comment = item.get("comment")
    if not isinstance(comment, str) or not comment.startswith(COMMENT_PREFIX):
        return None
    return comment[len(COMMENT_PREFIX) :].strip() or None


class CloudflareDeploymentError(Exception):
    """A read-back or removal refused by the reconciliation, with a readable message."""


class CloudflareDeploymentAdapter(DeploymentVendorAdapter):
    """Vendor operations of the deployment reconciliation for Cloudflare Rules Lists."""

    def __init__(self, connector: "Connector") -> None:
        """Initialize the adapter.

        :param connector: The connector, whose client and snapshot are used.
        """
        self._connector = connector

    def list_vendor_indicators(self) -> Iterator[VendorIndicator]:
        """Read back the IP address items of the list.

        An item identifies the STIX indicator of its comment and, since the list
        holds an IP address once, every indicator of the last uploaded snapshot
        holding that address: one vendor indicator is returned for each. Other items
        (observables, or comments carrying an internal id) are matched by IP address.

        Once the whole list is read, the indicators uploaded with an address the
        list no longer holds (item deleted outside the connector, reported
        `removed`) are forgotten, so that the upload restoring the item reports
        them `deployed` again.

        :raises CloudflareAPIError: On any API error (never a partial listing).
        :raises CloudflareDeploymentError: On an item without IP address or id,
            which would otherwise read as absent.
        """
        connector = self._connector
        listed: set[str] = set()
        uploads = connector.uploads
        for item in connector.client.iter_list_items(connector.list_id):
            ip = item.get("ip")
            item_id = item.get("id")
            if not isinstance(ip, str) or not ip or item_id is None:
                raise CloudflareDeploymentError(
                    "Cloudflare listed a list item without IP address or id, "
                    "the read-back is incomplete"
                )
            listed.add(ip)
            opencti_id = comment_id(item)
            indicator_ids = list(
                dict.fromkeys(
                    (
                        [opencti_id]
                        if opencti_id and opencti_id.startswith(STIX_INDICATOR_PREFIX)
                        else []
                    )
                    + connector.indicators_of(ip)
                )
            )
            if not indicator_ids:
                yield VendorIndicator(
                    external_id=str(item_id),
                    value=ip,
                    raw={
                        "item_id": str(item_id),
                        "opencti_id": opencti_id,
                        "uploads": uploads,
                    },
                )
            for indicator_id in indicator_ids:
                yield VendorIndicator(
                    indicator_id=indicator_id,
                    external_id=str(item_id),
                    value=ip,
                    raw={
                        "item_id": str(item_id),
                        "opencti_id": indicator_id,
                        "uploads": uploads,
                    },
                )
        connector.forget_absent(listed)

    def remove_vendor_indicator(
        self, vendor_indicator: VendorIndicator, deployment: IndicatorDeployment
    ) -> None:
        """Withdraw the list item of an indicator (withdrawal, revocation or expiry).

        The item is deleted, or kept for another object of the snapshot holding the
        same IP address.

        :raises CloudflareDeploymentError: When the item does not belong to the
            indicator (item of another object, left in place).
        :raises CloudflareAPIError: When Cloudflare refuses the deletion or the snapshot.
        """
        item_id = vendor_indicator.raw.get("item_id") or vendor_indicator.external_id
        opencti_id = normalize_value(vendor_indicator.raw.get("opencti_id"))
        if opencti_id is None or opencti_id not in deployment.identifiers:
            raise CloudflareDeploymentError(
                f"The Cloudflare list item {item_id} does not belong to this indicator "
                "(its comment carries another OpenCTI id), it is left in place"
            )
        self._connector.withdraw_item(
            str(item_id),
            vendor_indicator.value or "",
            deployment.identifiers,
            vendor_indicator.raw.get("uploads"),
        )

    def forget_indicator(self, deployment: IndicatorDeployment) -> None:
        """Drop an indicator withdrawn while absent from the list from the snapshot,
        so that the next upload does not restore its item."""
        self._connector.forget_indicator(deployment.identifiers)

    def push_indicator(self, stix_indicator: dict[str, Any]) -> str | None:
        """Add an indicator to the snapshot and upload it.

        :return: None: the bulk replace returns no item id.
        :raises CloudflareDeploymentError: When Cloudflare refuses the snapshot or
            cannot be reached, with the reason OpenCTI shows (the Cloudflare
            response is logged).
        :raises ValueError: When the indicator has no IPv4 pattern.
        """
        try:
            self._connector.push_indicator(stix_indicator)
        except CloudflareAPIError as err:
            self._connector.logger.warning(
                "[DEPLOYMENT] Cloudflare did not take an indicator pushed again.",
                {"indicator_id": stix_indicator.get("id"), "error": str(err)},
            )
            raise CloudflareDeploymentError(failure_reason(err)) from err
        return None


def build_deployment_assurance(connector: "Connector") -> DeploymentAssurance:
    """Build the deployment write-back of the connector, reconciliation included.

    :param connector: The connector (settings `deployment` and `security_platform`).
    :return: The deployment write-back, a no-op when `DEPLOYMENT_REPORTING_ENABLED` is false.
    """
    return DeploymentAssurance.from_settings(
        connector.helper,
        connector.config,
        adapter=CloudflareDeploymentAdapter(connector),
    )
