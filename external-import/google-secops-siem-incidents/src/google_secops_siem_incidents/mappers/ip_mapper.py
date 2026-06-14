"""Map alert outcomes to IPv4 or IPv6 address observables."""

from typing import Any

from connectors_sdk.models import IPV4Address, IPV6Address
from google_secops_siem_incidents.mappers._utils import find_all_outcomes, find_outcome
from google_secops_siem_incidents.models.rule_alert_response import Outcome


def map_ip_addresses(
    outcomes: list[Outcome],
    *,
    author: Any,
    tlp_marking: Any,
) -> list[IPV4Address | IPV6Address]:
    """Extract IPv4 or IPv6 address observables from all principal_ip alert outcomes.

    Args:
        outcomes: List of alert outcomes to inspect.
        author: STIX author identity object.
        tlp_marking: TLP marking definition object.

    Returns:
        List of IPv4 or IPv6 address observables (may be empty).
    """
    ip_outcomes = find_all_outcomes(outcomes, "principal_ip")
    if not ip_outcomes:
        return []

    ipv6_outcome = find_outcome(outcomes, "SourceIsIpv6")
    is_ipv6 = ipv6_outcome is not None and ipv6_outcome.string_val == "true"

    result = []
    for ip_outcome in ip_outcomes:
        if ip_outcome.string_seq is None:
            continue
        for ip in ip_outcome.string_seq.string_vals:
            if not ip or not ip.strip():
                continue
            if is_ipv6:
                result.append(
                    IPV6Address(value=ip, author=author, markings=[tlp_marking])
                )
            else:
                result.append(
                    IPV4Address(value=ip, author=author, markings=[tlp_marking])
                )
    return result
