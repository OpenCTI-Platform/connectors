"""Deployment write-back (dissemination assurance) of the Elastic Security Intel connector.

The `ElasticDeploymentAdapter` gives the connectors SDK reconciliation access to
the threat intel index of Elastic Security:

- read-back: the indicator documents of the connector (`opencti_doc_id`), with the
  OpenCTI id kept in their `stix` copy; documents past `valid_until` are not live;
- removal: the stream delete path (threat intel document and SIEM rule);
- re-push: the stream create path.

Hits are not read back: Elastic records indicator matches as alerts of the
detection rules, which this connector does not query.
"""

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from connectors_sdk import (
    DeploymentAssurance,
    DeploymentAssuranceOptions,
    DeploymentVendorAdapter,
    IndicatorDeployment,
    VendorIndicator,
)
from connectors_sdk.connectors.stream.deployment import parse_expiry
from elastic_security_intel_connector.api_handler import ElasticApiHandlerError
from pycti import OpenCTIConnectorHelper

if TYPE_CHECKING:
    from elastic_security_intel_connector.connector import (
        ElasticSecurityIntelConnector,
    )

SECURITY_PLATFORM_NAME = "Elastic Security"
SECURITY_PLATFORM_TYPE = "SIEM"

PUSH_FAILED_MESSAGE = (
    "Elastic Security did not accept the indicator, see the connector logs"
)
REMOVE_FAILED_MESSAGE = (
    "Elastic Security did not remove the indicator, see the connector logs"
)


class ElasticDeploymentError(Exception):
    """An Elastic Security error raised to the reconciliation, with a readable message."""


def describe_error(error: BaseException) -> str:
    """Describe an Elastic API error for logs and the deployment error message.

    :param error: The error raised by the API handler.
    :return: The message of the error.
    """
    if isinstance(error, ElasticApiHandlerError):
        return str(error.msg)
    return str(error) or type(error).__name__


class ElasticDeploymentAdapter(DeploymentVendorAdapter):
    """Vendor operations of the deployment reconciliation for Elastic Security."""

    def __init__(self, connector: "ElasticSecurityIntelConnector") -> None:
        """Initialize the adapter.

        :param connector: The connector, whose API handler is used.
        """
        self._connector = connector

    def list_vendor_indicators(self) -> Iterator[VendorIndicator]:
        """Read back the indicator documents written by the connector.

        Each document is matched by the OpenCTI id of its stored STIX object. Expired
        documents stay in the index, so they are listed too, inactive and without
        that id, for the reconciliation to delete them: they only match a known
        deployment by document id, and never confirm or backfill it as active.

        :raises ElasticDeploymentError: On any Elasticsearch error (never a partial
            listing), or a document with an unreadable `valid_until`.
        """
        now = datetime.now(UTC)
        try:
            for document in self._connector.api.iter_connector_documents():
                stix = document.get("stix")
                if not isinstance(stix, dict):
                    # Never skipped: its deployment would look absent.
                    raise ElasticDeploymentError(
                        "A document of the connector carries no STIX object"
                    )
                if stix.get("type") != "indicator":
                    continue
                try:
                    valid_until = parse_expiry(
                        ((document.get("threat") or {}).get("indicator") or {}).get(
                            "valid_until"
                        )
                    )
                except ValueError as err:
                    # Read as no expiry, it would confirm an expired document.
                    raise ElasticDeploymentError(
                        "A document of the connector carries an unreadable valid_until"
                    ) from err
                expired = valid_until is not None and valid_until <= now
                opencti_id = OpenCTIConnectorHelper.get_attribute_in_extension(
                    "id", stix
                )
                yield VendorIndicator(
                    indicator_id=(
                        str(opencti_id) if opencti_id and not expired else None
                    ),
                    external_id=document.get("opencti_doc_id"),
                    value=None,
                    raw={"stix": stix},
                    active=not expired,
                    # A failed update keeps the previous document: it never confirms
                    # the current pattern of the indicator.
                    pattern=stix.get("pattern"),
                )
        except ElasticApiHandlerError as err:
            raise ElasticDeploymentError(describe_error(err)) from err

    def remove_vendor_indicator(
        self, vendor_indicator: VendorIndicator, deployment: IndicatorDeployment
    ) -> None:
        """Remove an indicator from Elastic Security (withdrawal, revocation or expiry).

        :raises ElasticDeploymentError: When Elastic Security did not remove it.
        """
        if not self._connector.api.process_indicator(
            vendor_indicator.raw["stix"], "delete"
        ):
            raise ElasticDeploymentError(REMOVE_FAILED_MESSAGE)

    def push_indicator(self, stix_indicator: dict[str, Any]) -> str | None:
        """Push an indicator again, with the stream create path.

        :return: The opencti_doc_id of the document.
        :raises ElasticDeploymentError: When Elastic Security did not accept it.
        """
        if not self._connector.api.process_indicator(stix_indicator, "create"):
            raise ElasticDeploymentError(PUSH_FAILED_MESSAGE)
        return self._connector.api.document_id(stix_indicator)


def build_deployment_assurance(
    connector: "ElasticSecurityIntelConnector",
) -> DeploymentAssurance:
    """Build the deployment write-back of the connector, reconciliation included.

    Options come from the environment, then from `config.yml` (`deployment`,
    `security_platform` sections), then the defaults.

    :param connector: The connector.
    :return: The deployment write-back, a no-op when `DEPLOYMENT_REPORTING_ENABLED` is false.
    """
    options = DeploymentAssuranceOptions.from_legacy_config(
        connector.config.load,
        default_platform_name=SECURITY_PLATFORM_NAME,
        default_platform_type=SECURITY_PLATFORM_TYPE,
        hits_supported=False,
    )
    return DeploymentAssurance.from_options(
        connector.helper, options, adapter=ElasticDeploymentAdapter(connector)
    )
