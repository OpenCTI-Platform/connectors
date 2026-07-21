"""Map Chronicle alert outcomes to Attack Pattern entities."""

from typing import Any

from connectors_sdk.models import AttackPattern
from google_secops_siem_incidents.mappers._utils import find_outcome
from google_secops_siem_incidents.models.rule_alert_response import Outcome


def map_attack_patterns(
    outcomes: list[Outcome],
    *,
    author: Any,
    tlp_marking: Any,
) -> list[AttackPattern]:
    """Extract Attack Pattern from alert outcomes.

    Args:
        outcomes: List of alert outcomes to inspect.
        author: STIX author identity object.
        tlp_marking: TLP marking definition object.

    Returns:
        List of Attack Patterns (may be empty).
    """
    result = []
    attack_pattern_outcome = find_outcome(outcomes, "mitre_attack_technique_id")
    if attack_pattern_outcome is None:
        return []
    if (
        attack_pattern_outcome.string_seq is None
        and attack_pattern_outcome.string_val is None
    ):
        return []

    if attack_pattern_outcome.string_val:
        attack_pattern = attack_pattern_outcome.string_val
        result.append(
            AttackPattern(
                name=attack_pattern,
                mitre_id=attack_pattern,
                author=author,
                markings=[tlp_marking],
            )
        )

    if attack_pattern_outcome.string_seq:
        for attack_pattern in attack_pattern_outcome.string_seq.string_vals:
            result.append(
                AttackPattern(
                    name=attack_pattern,
                    mitre_id=attack_pattern,
                    author=author,
                    markings=[tlp_marking],
                )
            )
    return result
