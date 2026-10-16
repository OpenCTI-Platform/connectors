"""Censys Platform hunt connector: tracks infrastructure fingerprints on Censys."""

from collections.abc import Callable

from censys_hunt.client import CensysClient
from censys_hunt.settings import ConnectorSettings
from connectors_sdk import InfrastructureHuntConnector
from connectors_sdk.connectors.internal_hunt import (
    Fingerprint,
    HostSearchResult,
    HuntTimeWindow,
    RunDeadline,
    quote_value,
    within_window,
)


def _equals(field: str) -> Callable[[Fingerprint], str]:
    """Build an exact match on a CenQL field."""
    return lambda fingerprint: f"{field} = {quote_value(fingerprint.value)}"


FINGERPRINT_MATCHES: dict[str, Callable[[Fingerprint], str]] = {
    "jarm": _equals("host.services.jarm.fingerprint"),
    "ja4x": _equals("host.services.cert.parsed.ja4x"),
    "ja4s": _equals("host.services.tls.ja4s"),
    "certificate_sha256": _equals("host.services.cert.fingerprint_sha256"),
    "certificate_subject": _equals("host.services.cert.parsed.subject_dn"),
    "certificate_issuer": _equals("host.services.cert.parsed.issuer_dn"),
    "http_title": _equals("host.services.endpoints.http.html_title"),
    "http_body_sha256": _equals("host.services.endpoints.http.body_hash_sha256"),
    "http_server": lambda fingerprint: (
        "host.services.endpoints.http.headers: "
        f'(key = "Server" and value = {quote_value(fingerprint.value)})'
    ),
    "banner_sha256": _equals("host.services.banner_hash_sha256"),
    "asn": lambda fingerprint: f'host.autonomous_system.asn = "{fingerprint.asn}"',
}
"""Censys Query Language (CenQL) match of each fingerprint kind on hosts."""

DOCUMENTATION_URL = "https://docs.opencti.io/latest/usage/hunt-connectors/#censys"

REQUIRED_PERMISSIONS = (
    (
        "Personal access token of a user with the API Access role",
        "Search the hosts and web properties of the Censys Platform global search (CenQL); "
        "free accounts cannot search.",
    ),
    (
        "Organization ID (paid plans)",
        "The organization whose credits the searches use: 1 credit per search, plus 1 per page "
        "of 100 hits past the first.",
    ),
)
"""Least-privilege permissions of the account of the connector, as (name, purpose)."""

ACCESS_DENIED_HINTS = {
    401: "Censys refused the personal access token: check CENSYS_HUNT_TOKEN, and that it is not expired or revoked",
    403: "the user needs the API Access role on a plan that includes the global search (free accounts cannot search), and a paid plan needs CENSYS_HUNT_ORGANIZATION_ID",
}
"""What a refused account lacks, by HTTP status."""


class CensysHuntConnector(InfrastructureHuntConnector):
    """Hunt connector tracking infrastructure fingerprints on the Censys Platform."""

    service_name = "Censys Platform"
    fingerprint_matches = FINGERPRINT_MATCHES
    fingerprint_join = " or "
    required_permissions = REQUIRED_PERMISSIONS
    documentation_url = DOCUMENTATION_URL

    def __init__(self, settings: ConnectorSettings) -> None:
        """Initialize the connector (the helper is created by ``start()``).

        Args:
            settings: The connector settings.
        """
        super().__init__(settings)
        self.censys_config = settings.censys_hunt
        self.create_certificates = self.censys_config.create_certificates
        self.client: CensysClient | None = None

    def post_init(self) -> None:
        """Create the global search client."""
        config = self.censys_config
        self.client = CensysClient(
            str(config.api_url),
            config.token.get_secret_value().strip(),
            (config.organization_id or "").strip() or None,
        )
        self.client.access_denied_hints = dict(ACCESS_DENIED_HINTS)

    def search(
        self,
        query: str,
        time_window: HuntTimeWindow,
        limit: int,
        deadline: RunDeadline,
    ) -> HostSearchResult:
        """Run a CenQL query and keep the hosts last scanned within the run window.

        Censys searches its current view of the internet, without time bounds.

        Args:
            query: CenQL query.
            time_window: Time window of the run.
            limit: Maximum number of hits read.
            deadline: Run deadline.

        Returns:
            The hosts found.
        """
        if self.client is None:
            raise RuntimeError("The Censys client is created by start().")
        return within_window(self.client.search(query, limit, deadline), time_window)
