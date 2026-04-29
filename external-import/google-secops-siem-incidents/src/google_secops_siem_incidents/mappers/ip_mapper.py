"""Map Chronicle alert outcomes to IPv4 or IPv6 address observables."""

from typing import Any

from connectors_sdk.models import IPV4Address, IPV6Address

from google_secops_siem_incidents.mappers._utils import find_outcome
from google_secops_siem_incidents.models.rule_alert_response import Outcome


def map_ip_addresses(
    outcomes: list[Outcome],
    *,
    author: Any,
    tlp_marking: Any,
) -> list[IPV4Address | IPV6Address]:
    """Extract IPv4 or IPv6 address observables from the principal_ip alert outcome.

    Args:
        outcomes: List of alert outcomes to inspect.
        author: STIX author identity object.
        tlp_marking: TLP marking definition object.

    Returns:
        List of IPv4 or IPv6 address observables (may be empty).
    """
    ip_outcome = find_outcome(outcomes, "principal_ip")
    if ip_outcome is None or ip_outcome.string_seq is None:
        return []

    ips = ip_outcome.string_seq.string_vals
    if not ips:
        return []

    ipv6_outcome = find_outcome(outcomes, "SourceIsIpv6")
    is_ipv6 = ipv6_outcome is not None and ipv6_outcome.string_val == "true"

    result = []
    for ip in ips:
        if not ip or not ip.strip():
            continue
        if is_ipv6:
            result.append(IPV6Address(value=ip, author=author, markings=[tlp_marking]))
        else:
            result.append(IPV4Address(value=ip, author=author, markings=[tlp_marking]))
    return result
