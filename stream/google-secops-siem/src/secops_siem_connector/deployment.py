"""Deployment write-back (dissemination assurance) of the Google SecOps SIEM connector.

Google SecOps cannot list nor delete the UDM entities imported by the connector (the
`entities` API only imports and gets them by name), so the
`SecOpsDeploymentAdapter` is a push adapter of the connectors SDK:

- re-push: the stream ingest path, for the `pending` deployments (analyst retry);
- hits: the IoC matches of the instance (`legacySearchEnterpriseWideIoCs`) whose
  artifact (domain, destination IP address, MD5, SHA-1 or SHA-256 hash) is the value
  of a deployed indicator.

Presence, absence and withdrawal are not reconciled: an imported entity stays live in
Google SecOps until the end of its validity interval (the indicator `valid_until`).
"""

from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from connectors_sdk import (
    DeploymentAssurance,
    DeploymentPushAdapter,
    IndicatorDeployment,
    VendorHit,
)
from connectors_sdk.connectors.stream.deployment import normalize_value, parse_datetime

if TYPE_CHECKING:
    from secops_siem_connector.connector import SecOpsSIEMConnector

MAX_HIT_MATCHES = 10_000
"""Maximum number of IoC matches read by one hit collection."""

ARTIFACT_VALUE_FIELDS = (
    "domain",
    "destinationIpAddress",
    "hashMd5",
    "hashSha1",
    "hashSha256",
)
"""Fields of an IoC match artifact compared with the values of the deployed indicators."""


def _match_values(match: Mapping[str, Any]) -> set[str]:
    """Return the normalized artifact values of an IoC match."""
    candidates: list[Any] = []
    artifact = match.get("artifactIndicator")
    if isinstance(artifact, Mapping):
        candidates.extend(
            artifact.get(field_name) for field_name in ARTIFACT_VALUE_FIELDS
        )
    field_and_value = match.get("fieldAndValue")
    if isinstance(field_and_value, Mapping):
        candidates.append(field_and_value.get("value"))
    return {
        normalized
        for candidate in candidates
        if isinstance(candidate, str) and (normalized := normalize_value(candidate))
    }


class SecOpsDeploymentAdapter(DeploymentPushAdapter):
    """Vendor operations of the deployment reconciliation for Google SecOps."""

    def __init__(self, connector: "SecOpsSIEMConnector") -> None:
        """Initialize the adapter.

        :param connector: The connector, whose API client and ingest path are used.
        """
        self._connector = connector

    def push_indicator(self, stix_indicator: dict[str, Any]) -> str | None:
        """Ingest an indicator again, with the stream ingest path.

        :return: The STIX id of the indicator (`product_entity_id` of its entities).
        :raises SecOpsApiError: When Google SecOps rejects the entities.
        :raises ValueError: When no observable of the indicator can be ingested.
        """
        return self._connector.push_indicator(stix_indicator)

    def collect_hits(
        self, deployments: Sequence[IndicatorDeployment], since: datetime
    ) -> Iterable[VendorHit]:
        """Read the IoC matches whose artifact is the value of a deployed indicator.

        A match counts one hit per matching indicator, at the time Google SecOps last saw
        the artifact in the environment (hits already reported are filtered by the SDK).

        :raises SecOpsApiError: When the IoC matches cannot be listed.
        """
        by_value: dict[str, list[IndicatorDeployment]] = {}
        for deployment in deployments:
            for value in deployment.values:
                by_value.setdefault(value, []).append(deployment)
        if not by_value:
            return []
        matches, more_available = self._connector.api_client.list_ioc_matches(
            since, datetime.now(UTC), MAX_HIT_MATCHES
        )
        if more_available:
            self._connector.helper.connector_logger.warning(
                "[DEPLOYMENT] More IoC matches than read by one hit collection, "
                "the oldest ones are not counted.",
                {"limit": MAX_HIT_MATCHES},
            )
        hits: list[VendorHit] = []
        for match in matches:
            timestamp = parse_datetime(match.get("lastSeenTimestamp"))
            if timestamp is None or timestamp < since:
                continue
            matched = {
                deployment.indicator_id
                for value in _match_values(match)
                for deployment in by_value.get(value, ())
            }
            hits.extend(
                VendorHit(timestamp=timestamp, indicator_id=indicator_id)
                for indicator_id in sorted(matched)
            )
        return hits


def build_deployment_assurance(connector: "SecOpsSIEMConnector") -> DeploymentAssurance:
    """Build the deployment write-back of the connector, re-push and hits included.

    :param connector: The connector (settings `deployment`, `hits` and `security_platform`).
    :return: The deployment write-back, a no-op when `DEPLOYMENT_REPORTING_ENABLED` is false.
    """
    return DeploymentAssurance.from_settings(
        connector.helper,
        connector.config,
        adapter=SecOpsDeploymentAdapter(connector),
    )
