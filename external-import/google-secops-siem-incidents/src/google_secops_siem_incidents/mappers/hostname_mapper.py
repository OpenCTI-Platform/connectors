"""Map alert outcomes to Hostname observables."""

from typing import Any

from connectors_sdk.models import Hostname
from google_secops_siem_incidents.mappers._utils import find_all_outcomes
from google_secops_siem_incidents.models.rule_alert_response import Outcome


def map_hostname(
    outcomes: list[Outcome],
    *,
    author: Any,
    tlp_marking: Any,
) -> list[Hostname]:
    """Extract Hostname observables from all principal_hostname alert outcomes.

    Args:
        outcomes: List of alert outcomes to inspect.
        author: STIX author identity object.
        tlp_marking: TLP marking definition object.

    Returns:
        List of Hostname observables (may be empty).
    """
    result = []
    for outcome in find_all_outcomes(outcomes, "principal_hostname"):
        if outcome.string_val:
            result.append(
                Hostname(
                    value=outcome.string_val,
                    author=author,
                    markings=[tlp_marking],
                )
            )
    return result
