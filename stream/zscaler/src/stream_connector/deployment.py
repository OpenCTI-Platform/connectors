"""Deployment write-back (dissemination assurance) of the Zscaler connector.

The `ZscalerDeploymentAdapter` gives the connectors SDK reconciliation access to the
Zscaler Internet Access blacklist URL category:

- read-back: the domains of the category (`urlCategories/{id}`), matched with the
  deployments by value (the category does not store the OpenCTI id);
- removal: `REMOVE_FROM_LIST` of the domain, then activation; the reconciliation never
  asks to remove a domain that a deployment staying on Zscaler shares;
- re-push: the stream create path (`ADD_TO_LIST`, then activation).

The ZIA API exposes no hit of a URL category (web logs go through Nanolog Streaming
Service feeds), so no hit is reported.
"""

from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

from connectors_sdk import (
    DeploymentAssurance,
    DeploymentVendorAdapter,
    IndicatorDeployment,
    VendorIndicator,
)

if TYPE_CHECKING:
    from stream_connector.connector import ZscalerConnector
    from stream_connector.settings import ConnectorSettings


class ZscalerDeploymentAdapter(DeploymentVendorAdapter):
    """Vendor operations of the deployment reconciliation for Zscaler."""

    def __init__(self, connector: "ZscalerConnector") -> None:
        """Initialize the adapter.

        :param connector: The connector, whose blacklist operations are used.
        """
        self._connector = connector

    def list_vendor_indicators(self) -> Iterator[VendorIndicator]:
        """Read back the domains of the blacklist URL category.

        :raises ZscalerApiError: On any API error (never a partial listing).
        """
        for domain in self._connector.list_blocked_domains():
            yield VendorIndicator(value=domain, raw={"domain": domain})

    def remove_vendor_indicator(
        self, vendor_indicator: VendorIndicator, deployment: IndicatorDeployment
    ) -> None:
        """Remove a domain from the blacklist (withdrawal, revocation or expiry).

        The reconciliation only calls it when no deployment staying on Zscaler shares
        the domain, and calls it once per domain even when several deployments leave
        together, so no other indicator is looked up here.

        :raises ZscalerApiError: When Zscaler refuses the change.
        """
        domain = vendor_indicator.raw.get("domain") or vendor_indicator.value
        self._connector.send_to_zscaler(domain, "delete")

    def push_indicator(self, stix_indicator: dict[str, Any]) -> str | None:
        """Add the domain of an indicator to the blacklist again.

        :return: None: the category does not give a per-domain id.
        :raises ZscalerApiError: When Zscaler refuses the change.
        :raises ValueError: When the pattern is not a valid domain-name pattern.
        """
        self._connector.push_indicator(stix_indicator)
        return None


def build_deployment_assurance(
    connector: "ZscalerConnector", settings: "ConnectorSettings"
) -> DeploymentAssurance:
    """Build the deployment write-back of the connector, reconciliation included.

    :param connector: The connector.
    :param settings: The connector settings (`deployment` and `security_platform`).
    :return: The deployment write-back, a no-op when `DEPLOYMENT_REPORTING_ENABLED` is false.
    """
    return DeploymentAssurance.from_settings(
        connector.helper,
        settings,
        adapter=ZscalerDeploymentAdapter(connector),
    )
