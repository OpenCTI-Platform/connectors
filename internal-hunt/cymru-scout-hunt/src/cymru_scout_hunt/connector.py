"""Team Cymru Scout hunt connector: tracks infrastructure fingerprints on Team Cymru Scout."""

from collections.abc import Callable
from dataclasses import replace
from datetime import date, datetime, timedelta, timezone

from connectors_sdk import InfrastructureHuntConnector
from connectors_sdk.connectors.internal_hunt import (
    Fingerprint,
    HostSearchResult,
    HuntTimeWindow,
    RunDeadline,
    quote_value,
)
from cymru_scout_hunt.client import ScoutClient
from cymru_scout_hunt.settings import ConnectorSettings

MAX_AGE_DAYS = 89
"""Oldest day Scout searches, counted back from today (90 days of history)."""

MAX_RANGE_DAYS = 29
"""Longest search range after its first day (30 days at a time)."""


def _selector(name: str) -> Callable[[Fingerprint], str]:
    """Build a selector match."""
    return lambda fingerprint: f"{name} = {quote_value(fingerprint.value)}"


def _name_selector(name: str) -> Callable[[Fingerprint], str]:
    """Build a match on a distinguished name, whose commas Scout reads escaped."""

    def _match(fingerprint: Fingerprint) -> str:
        value = quote_value(fingerprint.value).replace(",", "\\,")
        return f"{name} = {value}"

    return _match


FINGERPRINT_MATCHES: dict[str, Callable[[Fingerprint], str]] = {
    "jarm": _selector("fingerprints.hash"),
    "ja4x": _selector("fingerprints.hash"),
    "certificate_sha256": _selector("x509.sha256"),
    "certificate_subject": _name_selector("x509.subject"),
    "certificate_issuer": _name_selector("x509.issuer"),
}
"""Scout query selector of each fingerprint kind (one search per fingerprint)."""

DOCUMENTATION_URL = (
    "https://docs.opencti.io/latest/usage/hunt-connectors/#team-cymru-scout"
)

REQUIRED_PERMISSIONS = (
    (
        "API key of an account with search queries",
        "Search the IP addresses of the last 90 days on JARM, JA4X and X.509 certificates; "
        "every search uses one query of the monthly balance of the account.",
    ),
)
"""Least-privilege permissions of the account of the connector, as (name, purpose)."""

ACCESS_DENIED_HINTS = {
    401: "Team Cymru Scout refused the API key: check CYMRU_SCOUT_HUNT_API_KEY",
    403: "the Team Cymru Scout account of the key needs search queries",
}
"""What a refused account lacks, by HTTP status."""


def scout_window(window: HuntTimeWindow, today: date) -> tuple[date, date] | None:
    """Clamp a run window to the days Team Cymru Scout searches.

    Scout searches the last 90 days, at most 30 days at a time: the most
    recent part of the window is kept.

    Args:
        window: Time window of the run.
        today: Current UTC date.

    Returns:
        The first and last days to search, or ``None`` when the window is too old.
    """
    end = min(window.end.astimezone(timezone.utc).date(), today)
    start = max(
        window.start.astimezone(timezone.utc).date(),
        today - timedelta(days=MAX_AGE_DAYS),
        end - timedelta(days=MAX_RANGE_DAYS),
    )
    return (start, end) if start <= end else None


def _today() -> date:
    """Return the current UTC date."""
    return datetime.now(timezone.utc).date()


class CymruScoutHuntConnector(InfrastructureHuntConnector):
    """Hunt connector tracking infrastructure fingerprints on Team Cymru Scout."""

    service_name = "Team Cymru Scout"
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
        self.scout_config = settings.cymru_scout_hunt
        self.client: ScoutClient | None = None

    def post_init(self) -> None:
        """Create the search client."""
        config = self.scout_config
        self.client = ScoutClient(
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
        """Search the IP addresses of the days of the run window Scout holds.

        Scout dates its observations by the day only (``last_seen`` is a
        day): the days searched are the finest bound, and filtering them with
        the times of the run would drop the hosts observed on its first day.

        Args:
            query: Scout query.
            time_window: Time window of the run.
            limit: Maximum number of IP addresses read.
            deadline: Run deadline.

        Returns:
            The hosts found.
        """
        if self.client is None:
            raise RuntimeError("The Team Cymru Scout client is created by start().")
        dates = scout_window(time_window, _today())
        if dates is None:
            self.logger.info(
                "[HUNT] Run window older than the Team Cymru Scout history, search skipped",
                {"start": time_window.start.isoformat()},
            )
            # Nothing of the window was searched: no host found proves nothing
            return HostSearchResult([], more=True, requests=0)
        result = self.client.search(query, dates[0], dates[1], limit, deadline)
        # Days cut from the start of the window (older than the Scout history or beyond its
        # search range) were not searched; days after today hold no observation yet
        if dates[0] > time_window.start.astimezone(timezone.utc).date():
            return replace(result, more=True)
        return result
