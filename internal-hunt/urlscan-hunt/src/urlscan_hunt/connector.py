"""urlscan.io hunt connector: tracks infrastructure fingerprints on urlscan.io scans."""

from collections.abc import Callable
from datetime import timezone

from connectors_sdk import InfrastructureHuntConnector
from connectors_sdk.connectors.internal_hunt import (
    Fingerprint,
    HostSearchResult,
    HuntTimeWindow,
    RunDeadline,
    quote_value,
    within_window,
)
from urlscan_hunt.client import UrlscanClient
from urlscan_hunt.settings import ConnectorSettings


def _phrase(field: str) -> Callable[[Fingerprint], str]:
    """Build a phrase match on a search field."""
    return lambda fingerprint: f"{field}:{quote_value(fingerprint.value)}"


FINGERPRINT_MATCHES: dict[str, Callable[[Fingerprint], str]] = {
    "http_title": _phrase("page.title"),
    "http_server": _phrase("page.server"),
    "certificate_issuer": _phrase("page.tlsIssuer"),
    "http_body_sha256": lambda fingerprint: f"hash:{fingerprint.value.lower()}",
    "asn": lambda fingerprint: f"page.asn:AS{fingerprint.asn}",
}
"""urlscan.io search query match of each fingerprint kind on scans."""

DOCUMENTATION_URL = "https://docs.opencti.io/latest/usage/hunt-connectors/#urlscan"

REQUIRED_PERMISSIONS = (
    (
        "API key with search access",
        "Search the scans of the run window on HTTP title, Server header, TLS issuer, body hash "
        "and ASN; every search counts against the per-minute, per-hour and per-day search quotas "
        "of the plan.",
    ),
)
"""Least-privilege permissions of the account of the connector, as (name, purpose)."""

ACCESS_DENIED_HINTS = {
    401: "urlscan.io refused the API key: check URLSCAN_HUNT_API_KEY",
    403: "the urlscan.io plan of the key needs search access",
}
"""What a refused account lacks, by HTTP status."""


class UrlscanHuntConnector(InfrastructureHuntConnector):
    """Hunt connector tracking infrastructure fingerprints on urlscan.io scans."""

    service_name = "urlscan.io"
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
        self.urlscan_config = settings.urlscan_hunt
        self.client: UrlscanClient | None = None

    def post_init(self) -> None:
        """Create the search client."""
        config = self.urlscan_config
        self.client = UrlscanClient(
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
        """Search the scans of the days of the run window and keep those within it.

        Args:
            query: urlscan.io search query.
            time_window: Time window of the run.
            limit: Maximum number of scans read.
            deadline: Run deadline.

        Returns:
            The hosts found.
        """
        if self.client is None:
            raise RuntimeError("The urlscan.io client is created by start().")
        start = time_window.start.astimezone(timezone.utc).date()
        end = time_window.end.astimezone(timezone.utc).date()
        result = self.client.search(query, start, end, limit, deadline)
        return within_window(result, time_window)
