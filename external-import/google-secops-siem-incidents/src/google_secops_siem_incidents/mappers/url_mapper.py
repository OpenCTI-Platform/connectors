"""Map Chronicle alert outcomes to URL observables."""

from typing import Any

from connectors_sdk.models import URL
from google_secops_siem_incidents.mappers._utils import find_outcome
from google_secops_siem_incidents.models.rule_alert_response import Outcome


def map_urls(
    outcomes: list[Outcome],
    *,
    author: Any,
    tlp_marking: Any,
) -> list[URL]:
    """Extract deduplicated URL observables from target outcomes.

    Args:
        outcomes: List of alert outcomes to inspect.
        author: STIX author identity object.
        tlp_marking: TLP marking definition object.

    Returns:
        Deduplicated list of URL observables.
    """
    target_url_outcome = find_outcome(outcomes, "target_url")

    target_url_ids = (
        target_url_outcome.string_seq.string_vals
        if target_url_outcome and target_url_outcome.string_seq
        else []
    )

    unique_ids = list(
        dict.fromkeys(uid for uid in target_url_ids if uid and uid.strip())
    )

    return [
        URL(
            value=uid,
            author=author,
            markings=[tlp_marking],
        )
        for uid in unique_ids
    ]
