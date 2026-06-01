"""Map alert outcomes to UserAccount observables."""

from typing import Any

from connectors_sdk.models import UserAccount
from connectors_sdk.models.enums import AccountType
from google_secops_siem_incidents.mappers._utils import find_all_outcomes
from google_secops_siem_incidents.models.rule_alert_response import Outcome


def _infer_account_type(uid: str) -> AccountType:
    """Infer AccountType from the shape of the user identifier string.

    Args:
        uid: User identifier string.

    Returns:
        Inferred AccountType enum value.
    """
    if "\\" in uid:
        return AccountType.WINDOWS_DOMAIN
    if "@" in uid:
        return AccountType.LDAP
    return AccountType.UNIX


def map_user_accounts(
    outcomes: list[Outcome],
    *,
    author: Any,
    tlp_marking: Any,
) -> list[UserAccount]:
    """Extract deduplicated UserAccount observables from all principal and target user outcomes.

    Args:
        outcomes: List of alert outcomes to inspect.
        author: STIX author identity object.
        tlp_marking: TLP marking definition object.

    Returns:
        Deduplicated list of UserAccount observables.
    """
    all_ids: list[str] = []
    for outcome in find_all_outcomes(
        outcomes, "principal_user_userid"
    ) + find_all_outcomes(outcomes, "target_user_userid"):
        if outcome.string_seq:
            all_ids.extend(outcome.string_seq.string_vals)

    unique_ids = list(dict.fromkeys(uid for uid in all_ids if uid and uid.strip()))

    return [
        UserAccount(
            user_id=uid,
            account_login=uid,
            account_type=_infer_account_type(uid),
            author=author,
            markings=[tlp_marking],
        )
        for uid in unique_ids
    ]
