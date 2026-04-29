"""Map Chronicle alert outcomes to a Hostname observable."""

from typing import Any

from connectors_sdk.models import Hostname

from google_secops_siem_incidents.mappers._utils import find_outcome
from google_secops_siem_incidents.models.rule_alert_response import Outcome


def map_hostname(
    outcomes: list[Outcome],
    *,
    author: Any,
    tlp_marking: Any,
) -> Hostname | None:
    """Extract a Hostname observable from the principal_hostname alert outcome.

    Args:
        outcomes: List of alert outcomes to inspect.
        author: STIX author identity object.
        tlp_marking: TLP marking definition object.

    Returns:
        Hostname observable, or None if the outcome is absent.
    """
    outcome = find_outcome(outcomes, "principal_hostname")
    if outcome is None or not outcome.string_val:
        return None
    return Hostname(
        value=outcome.string_val,
        author=author,
        markings=[tlp_marking],
    )
