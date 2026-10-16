"""Shodan hunt connector: tracks infrastructure fingerprints on Shodan."""

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
from shodan_hunt.client import ShodanClient
from shodan_hunt.settings import ConnectorSettings


def common_name(value: str) -> str:
    """Return the common name of a distinguished name (the value itself without one).

    Args:
        value: Distinguished name (``CN=Evil, O=Org``) or common name.

    Returns:
        The common name.
    """
    for part in value.split(","):
        name, separator, text = part.strip().partition("=")
        if separator and name.strip().upper() == "CN" and text.strip():
            return text.strip()
    return value


def _filter(name: str) -> Callable[[Fingerprint], str]:
    """Build a match on a search filter."""
    return lambda fingerprint: f"{name}:{quote_value(fingerprint.value)}"


def _name_filter(name: str) -> Callable[[Fingerprint], str]:
    """Build a match on the common name of a distinguished name."""
    return lambda fingerprint: f"{name}:{quote_value(common_name(fingerprint.value))}"


FINGERPRINT_MATCHES: dict[str, Callable[[Fingerprint], str]] = {
    "jarm": _filter("ssl.jarm"),
    "certificate_sha256": _filter("ssl.cert.fingerprint"),
    "certificate_subject": _name_filter("ssl.cert.subject.cn"),
    "certificate_issuer": _name_filter("ssl.cert.issuer.cn"),
    "http_title": _filter("http.title"),
    "asn": lambda fingerprint: f"asn:AS{fingerprint.asn}",
}
"""Shodan search filter of each fingerprint kind (one search per fingerprint)."""

DOCUMENTATION_URL = "https://docs.opencti.io/latest/usage/hunt-connectors/#shodan"

REQUIRED_PERMISSIONS = (
    (
        "API key of a plan with query credits",
        "Search the banners on JARM, certificate fingerprint, subject and issuer, HTTP title and "
        "ASN; every search uses 1 query credit, plus 1 per page of 100 banners past the first.",
    ),
)
"""Least-privilege permissions of the account of the connector, as (name, purpose)."""

ACCESS_DENIED_HINTS = {
    401: "Shodan refused the API key: check SHODAN_HUNT_API_KEY",
    403: "the Shodan plan of the key needs query credits for filtered searches",
}
"""What a refused account lacks, by HTTP status."""


class ShodanHuntConnector(InfrastructureHuntConnector):
    """Hunt connector tracking infrastructure fingerprints on Shodan."""

    service_name = "Shodan"
    fingerprint_matches = FINGERPRINT_MATCHES
    fingerprint_join = None
    required_permissions = REQUIRED_PERMISSIONS
    documentation_url = DOCUMENTATION_URL

    def __init__(self, settings: ConnectorSettings) -> None:
        """Initialize the connector (the helper is created by ``start()``).

        Args:
            settings: The connector settings.
        """
        super().__init__(settings)
        self.shodan_config = settings.shodan_hunt
        self.create_certificates = self.shodan_config.create_certificates
        self.client: ShodanClient | None = None

    def post_init(self) -> None:
        """Create the host search client."""
        config = self.shodan_config
        self.client = ShodanClient(
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
        """Run a Shodan query and keep the hosts last scanned within the run window.

        Shodan searches the latest banner of every service, without time bounds.

        Args:
            query: Shodan search query.
            time_window: Time window of the run.
            limit: Maximum number of banners read.
            deadline: Run deadline.

        Returns:
            The hosts found.
        """
        if self.client is None:
            raise RuntimeError("The Shodan client is created by start().")
        return within_window(self.client.search(query, limit, deadline), time_window)
