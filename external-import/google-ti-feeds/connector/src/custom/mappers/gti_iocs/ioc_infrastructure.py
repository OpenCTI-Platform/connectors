"""Infrastructure relationships embedded in IOC delta entries (GTI_INDICATOR_INFRASTRUCTURE).

Each rule maps a relationship list of a delta entry to observables linked to the
IOC observable. Items are GTI descriptors: their ID is the value (domain, IP,
SHA-256), or for resolutions the IP followed by the domain.
"""

import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, get_args

RelatedType = Literal["domain", "ip", "file"]

# GTI_INDICATOR_INFRASTRUCTURE values. As a `Literal`, the allowed values are
# declared in the config schema (`items.enum`), like the other list options.
# See: https://github.com/OpenCTI-Platform/connectors/issues/8098
InfrastructureCategory = Literal[
    "resolutions",
    "subdomains",
    "siblings",
    "downloaded",
    "communicating",
    "contacted",
    "serving_ip",
    "embedded",
    "referrer",
]
ALLOWED_INFRASTRUCTURE_CATEGORIES = list(get_args(InfrastructureCategory))

SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass(frozen=True)
class InfrastructureRule:
    """How a relationship list of a delta entry becomes linked observables."""

    category: InfrastructureCategory  # GTI_INDICATOR_INFRASTRUCTURE value
    ioc_type: str  # GTI type of the delta entry
    field: str  # relationship list of the delta entry
    related_type: RelatedType
    relationship_type: Literal["resolves-to", "related-to"]
    ioc_is_source: bool  # False: the related observable is the source
    reason: str  # "{ioc}" and "{related}" are replaced by the observable values


INFRASTRUCTURE_RULES = (
    InfrastructureRule(
        category="resolutions",
        ioc_type="domain",
        field="resolutions",
        related_type="ip",
        relationship_type="resolves-to",
        ioc_is_source=True,
        reason="GTI lists a DNS resolution of the domain {ioc} to {related}.",
    ),
    InfrastructureRule(
        category="resolutions",
        ioc_type="ip_address",
        field="resolutions",
        related_type="domain",
        relationship_type="resolves-to",
        ioc_is_source=False,
        reason="GTI lists a DNS resolution of the domain {related} to {ioc}.",
    ),
    InfrastructureRule(
        category="subdomains",
        ioc_type="domain",
        field="subdomains",
        related_type="domain",
        relationship_type="related-to",
        ioc_is_source=True,
        reason="GTI lists {related} as a subdomain of {ioc}.",
    ),
    InfrastructureRule(
        category="siblings",
        ioc_type="domain",
        field="siblings",
        related_type="domain",
        relationship_type="related-to",
        ioc_is_source=True,
        reason="GTI lists {related} as a sibling domain of {ioc}.",
    ),
    InfrastructureRule(
        category="downloaded",
        ioc_type="domain",
        field="downloaded_files",
        related_type="file",
        relationship_type="related-to",
        ioc_is_source=True,
        reason="GTI lists the file {related} as downloaded from {ioc}.",
    ),
    InfrastructureRule(
        category="downloaded",
        ioc_type="ip_address",
        field="downloaded_files",
        related_type="file",
        relationship_type="related-to",
        ioc_is_source=True,
        reason="GTI lists the file {related} as downloaded from {ioc}.",
    ),
    InfrastructureRule(
        category="communicating",
        ioc_type="domain",
        field="communicating_files",
        related_type="file",
        relationship_type="related-to",
        ioc_is_source=False,
        reason="GTI lists the file {related} as communicating with {ioc}.",
    ),
    InfrastructureRule(
        category="communicating",
        ioc_type="ip_address",
        field="communicating_files",
        related_type="file",
        relationship_type="related-to",
        ioc_is_source=False,
        reason="GTI lists the file {related} as communicating with {ioc}.",
    ),
    InfrastructureRule(
        category="contacted",
        ioc_type="file",
        field="contacted_domains",
        related_type="domain",
        relationship_type="related-to",
        ioc_is_source=True,
        reason="GTI lists {related} as contacted by the file {ioc}.",
    ),
    InfrastructureRule(
        category="contacted",
        ioc_type="file",
        field="contacted_ips",
        related_type="ip",
        relationship_type="related-to",
        ioc_is_source=True,
        reason="GTI lists {related} as contacted by the file {ioc}.",
    ),
    InfrastructureRule(
        category="serving_ip",
        ioc_type="url",
        field="last_serving_ip_address",
        related_type="ip",
        relationship_type="related-to",
        ioc_is_source=True,
        reason="GTI lists {related} as the last IP address serving the URL {ioc}.",
    ),
    InfrastructureRule(
        category="embedded",
        ioc_type="file",
        field="embedded_domains",
        related_type="domain",
        relationship_type="related-to",
        ioc_is_source=True,
        reason="GTI lists {related} as embedded in the file {ioc}.",
    ),
    InfrastructureRule(
        category="embedded",
        ioc_type="file",
        field="embedded_ips",
        related_type="ip",
        relationship_type="related-to",
        ioc_is_source=True,
        reason="GTI lists {related} as embedded in the file {ioc}.",
    ),
    InfrastructureRule(
        category="referrer",
        ioc_type="domain",
        field="referrer_files",
        related_type="file",
        relationship_type="related-to",
        ioc_is_source=False,
        reason="GTI lists the file {related} as containing a reference to {ioc}.",
    ),
    InfrastructureRule(
        category="referrer",
        ioc_type="ip_address",
        field="referrer_files",
        related_type="file",
        relationship_type="related-to",
        ioc_is_source=False,
        reason="GTI lists the file {related} as containing a reference to {ioc}.",
    ),
)


def is_ip(value: str) -> bool:
    """Return whether the value is an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def is_domain(value: str) -> bool:
    """Return whether the value looks like a domain name: dotted, not an IP."""
    return "." in value and " " not in value and not is_ip(value)


def is_sha256(value: str) -> bool:
    """Return whether the value is a SHA-256 hex digest."""
    return bool(SHA256_PATTERN.match(value))


VALIDATORS: dict[str, Callable[[str], bool]] = {
    "ip": is_ip,
    "domain": is_domain,
    "file": is_sha256,
}


def related_value(rule: InfrastructureRule, ioc_value: str, item_id: str) -> str | None:
    """Return the value of the related observable of a descriptor, or None if invalid.

    Resolution IDs are the IP followed by the domain: the IOC part is removed.
    """
    value = item_id
    if rule.field == "resolutions":
        if rule.ioc_type == "domain" and item_id.endswith(ioc_value):
            value = item_id[: -len(ioc_value)]
        elif rule.ioc_type == "ip_address" and item_id.startswith(ioc_value):
            value = item_id[len(ioc_value) :]
        else:
            return None
    return value if value and VALIDATORS[rule.related_type](value) else None
