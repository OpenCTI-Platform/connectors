"""Shared utilities for mappers."""

from google_secops_siem_incidents.models.rule_alert_response import Outcome


def find_outcome(outcomes: list[Outcome], name: str) -> Outcome | None:
    """Return the first outcome matching name, or None.

    Args:
        outcomes: List of alert outcomes to search.
        name: Outcome name to match.

    Returns:
        Matching Outcome, or None if not found.
    """
    for o in outcomes:
        if o.name == name:
            return o
    return None


def find_all_outcomes(outcomes: list[Outcome], name: str) -> list[Outcome]:
    """Return all outcomes matching name.

    Args:
        outcomes: List of alert outcomes to search.
        name: Outcome name to match.

    Returns:
        List of matching Outcome objects (may be empty).
    """
    return [o for o in outcomes if o.name == name]
