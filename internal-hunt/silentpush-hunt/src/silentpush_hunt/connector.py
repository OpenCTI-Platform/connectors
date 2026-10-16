"""Silent Push hunt connector: tracks infrastructure fingerprints on Silent Push web scans."""

from collections.abc import Callable

from connectors_sdk import InfrastructureHuntConnector
from connectors_sdk.connectors.internal_hunt import (
    Fingerprint,
    HostSearchResult,
    HuntTimeWindow,
    RunDeadline,
    quote_value,
    within_window,
)
from silentpush_hunt.client import SilentPushClient
from silentpush_hunt.settings import ConnectorSettings


def _equals(field: str) -> Callable[[Fingerprint], str]:
    """Build an exact match on an SPQL field."""
    return lambda fingerprint: f"{field} = {quote_value(fingerprint.value)}"


FINGERPRINT_MATCHES: dict[str, Callable[[Fingerprint], str]] = {
    "jarm": _equals("jarm"),
    "certificate_sha256": _equals("ssl.SHA256"),
    "http_title": _equals("htmltitle"),
    "http_body_sha256": _equals("html_body_sha256"),
    "http_server": _equals("header.server"),
}
"""Silent Push Query Language (SPQL) match of each fingerprint kind on web scans."""

DOCUMENTATION_URL = "https://docs.opencti.io/latest/usage/hunt-connectors/#silent-push"

REQUIRED_PERMISSIONS = (
    (
        "API key of a subscription that includes the web scan data API",
        "Search the web scans (SPQL) on JARM, certificate SHA-256, HTTP title, body hash and "
        "Server header; every request counts against the API calls of the subscription.",
    ),
)
"""Least-privilege permissions of the account of the connector, as (name, purpose)."""

ACCESS_DENIED_HINTS = {
    401: "Silent Push refused the API key: check SILENTPUSH_HUNT_API_KEY",
    403: "the Silent Push subscription of the key needs the web scan data API",
}
"""What a refused account lacks, by HTTP status."""


class SilentPushHuntConnector(InfrastructureHuntConnector):
    """Hunt connector tracking infrastructure fingerprints on Silent Push web scans."""

    service_name = "Silent Push"
    fingerprint_matches = FINGERPRINT_MATCHES
    fingerprint_join = " OR "
    required_permissions = REQUIRED_PERMISSIONS
    documentation_url = DOCUMENTATION_URL

    def __init__(self, settings: ConnectorSettings) -> None:
        """Initialize the connector (the helper is created by ``start()``).

        Args:
            settings: The connector settings.
        """
        super().__init__(settings)
        self.silentpush_config = settings.silentpush_hunt
        self.create_certificates = self.silentpush_config.create_certificates
        self.client: SilentPushClient | None = None

    def post_init(self) -> None:
        """Create the web scan data client."""
        config = self.silentpush_config
        self.client = SilentPushClient(
            str(config.api_url), config.api_key.get_secret_value().strip()
        )
        self.client.access_denied_hints = dict(ACCESS_DENIED_HINTS)

    def search(
        self,
        query: str,
        time_window: HuntTimeWindow,
        limit: int,
        deadline: RunDeadline,
    ) -> HostSearchResult:
        """Run an SPQL query and keep the hosts last scanned within the run window.

        Silent Push searches its current view of the web scans, without time bounds.

        Args:
            query: SPQL query.
            time_window: Time window of the run.
            limit: Maximum number of scans read.
            deadline: Run deadline.

        Returns:
            The hosts found.
        """
        if self.client is None:
            raise RuntimeError("The Silent Push client is created by start().")
        return within_window(self.client.search(query, limit, deadline), time_window)
