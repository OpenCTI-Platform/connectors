"""Map Chronicle alert outcomes to EmailAddress observables."""

from typing import Any

from connectors_sdk.models import EmailAddress
from google_secops_siem_incidents.mappers._utils import find_outcome
from google_secops_siem_incidents.models.rule_alert_response import Outcome


def map_email_addresses(
    outcomes: list[Outcome],
    *,
    author: Any,
    tlp_marking: Any,
) -> list[EmailAddress]:
    """Extract deduplicated EmailAddress observables from principal and target user outcomes.

    Args:
        outcomes: List of alert outcomes to inspect.
        author: STIX author identity object.
        tlp_marking: TLP marking definition object.

    Returns:
        Deduplicated list of EmailAddress observables.
    """
    principal_user_email_outcome = find_outcome(
        outcomes, "principal_user_email_addresses"
    )
    target_user_email_outcome = find_outcome(outcomes, "target_user_email_addresses")

    principal_ids = (
        principal_user_email_outcome.string_seq.string_vals
        if principal_user_email_outcome and principal_user_email_outcome.string_seq
        else []
    )

    target_ids = (
        target_user_email_outcome.string_seq.string_vals
        if target_user_email_outcome and target_user_email_outcome.string_seq
        else []
    )

    unique_ids = list(
        dict.fromkeys(uid for uid in principal_ids + target_ids if uid and uid.strip())
    )

    return [
        EmailAddress(
            value=uid,
            author=author,
            markings=[tlp_marking],
        )
        for uid in unique_ids
    ]
