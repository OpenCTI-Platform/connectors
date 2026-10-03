"""Deployment write-back (dissemination assurance) of the Cloudflare Rules List connector.

The `CloudflareDeploymentAdapter` gives the connectors SDK reconciliation access to
the Cloudflare Rules List:

- read-back: the items of the list (`rules/lists/{id}/items`, cursor pagination),
  matched with the deployments by the OpenCTI id of their comment
  (`OpenCTI: <id>`), by item id, then by IP address;
- removal: deletion of the list item, when its comment carries an id of the
  indicator (items of other objects are left in place), and of the indicator from
  the snapshot;
- re-push: the indicator is added to the snapshot, which is uploaded.

Hits are not reported: they are the firewall events of the rules referencing the
list, which the connector does not manage.
"""

from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

from cloudflare_rules_list.connector import COMMENT_PREFIX
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
    """A removal refused by the reconciliation, with a readable message."""


class CloudflareDeploymentAdapter(DeploymentVendorAdapter):
    """Vendor operations of the deployment reconciliation for Cloudflare Rules Lists."""

    def __init__(self, connector: "Connector") -> None:
        """Initialize the adapter.

        :param connector: The connector, whose client and snapshot are used.
        """
        self._connector = connector

    def list_vendor_indicators(self) -> Iterator[VendorIndicator]:
        """Read back the IP address items of the list.

        Only comments carrying a STIX indicator id identify an indicator: the
        internal ids written by the full sync cannot be told apart from observable
        ids, so those items are matched by IP address.

        :raises CloudflareAPIError: On any API error (never a partial listing).
        """
        connector = self._connector
        for item in connector.client.iter_list_items(connector.list_id):
            ip = item.get("ip")
            item_id = item.get("id")
            if not isinstance(ip, str) or not ip or item_id is None:
                continue
            opencti_id = comment_id(item)
            yield VendorIndicator(
                indicator_id=(
                    opencti_id
                    if opencti_id and opencti_id.startswith(STIX_INDICATOR_PREFIX)
                    else None
                ),
                external_id=str(item_id),
                value=ip,
                raw={"item_id": str(item_id), "opencti_id": opencti_id},
            )

    def remove_vendor_indicator(
        self, vendor_indicator: VendorIndicator, deployment: IndicatorDeployment
    ) -> None:
        """Delete the list item of an indicator (withdrawal, revocation or expiry).

        :raises CloudflareDeploymentError: When the item comment does not carry an id
            of the indicator (item of another object, left in place).
        :raises CloudflareAPIError: When Cloudflare refuses the deletion.
        """
        item_id = vendor_indicator.raw.get("item_id") or vendor_indicator.external_id
        opencti_id = normalize_value(vendor_indicator.raw.get("opencti_id"))
        if opencti_id is None or opencti_id not in deployment.identifiers:
            raise CloudflareDeploymentError(
                f"The Cloudflare list item {item_id} does not belong to this indicator "
                "(its comment carries another OpenCTI id), it is left in place"
            )
        self._connector.withdraw_item(str(item_id), deployment.identifiers)

    def push_indicator(self, stix_indicator: dict[str, Any]) -> str | None:
        """Add an indicator to the snapshot and upload it.

        :return: None: the bulk replace returns no item id.
        :raises CloudflareAPIError: When Cloudflare refuses the snapshot.
        :raises ValueError: When the indicator has no IPv4 pattern.
        """
        self._connector.push_indicator(stix_indicator)
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
