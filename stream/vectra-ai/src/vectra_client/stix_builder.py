"""
Helpers to turn OpenCTI STIX 2.1 indicators into the STIX 1.2 documents
expected by the Vectra AI threat feed import API.

Vectra threat feeds only ingest network indicators, namely IP addresses
(IPv4/IPv6), domain names and URLs. File hashes and other observable types
are intentionally not supported and are filtered out upstream.
"""

import re
import uuid
from typing import Optional
from xml.sax.saxutils import escape, quoteattr

# Map of supported STIX 2.1 single-observable patterns -> capture the value.
SUPPORTED_STIX_PATTERNS: dict[str, "re.Pattern[str]"] = {
    "ipv4-addr": re.compile(r"^\s*\[ipv4-addr:value\s*=\s*'([^']+)'\s*\]\s*$"),
    "ipv6-addr": re.compile(r"^\s*\[ipv6-addr:value\s*=\s*'([^']+)'\s*\]\s*$"),
    "domain-name": re.compile(r"^\s*\[domain-name:value\s*=\s*'([^']+)'\s*\]\s*$"),
    "url": re.compile(r"^\s*\[url:value\s*=\s*'([^']+)'\s*\]\s*$"),
}

# STIX 1.2 / CybOX namespaces used by the generated documents.
_NAMESPACES = (
    'xmlns:stix="http://stix.mitre.org/stix-1" '
    'xmlns:indicator="http://stix.mitre.org/Indicator-2" '
    'xmlns:cybox="http://cybox.mitre.org/cybox-2" '
    'xmlns:AddressObj="http://cybox.mitre.org/objects#AddressObject-2" '
    'xmlns:DomainNameObj="http://cybox.mitre.org/objects#DomainNameObject-1" '
    'xmlns:URIObj="http://cybox.mitre.org/objects#URIObject-2" '
    'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
)


def extract_indicator(pattern: str) -> Optional[tuple[str, str]]:
    """
    Return the (observable_type, value) of a supported single-observable STIX
    pattern, or None when the pattern is not supported by Vectra.

    :param pattern: A STIX 2.1 pattern string.
    :return: A tuple (observable_type, value) or None.
    """
    if not pattern:
        return None
    for observable_type, regex in SUPPORTED_STIX_PATTERNS.items():
        match = regex.match(pattern)
        if match:
            return observable_type, match.group(1)
    return None


def is_supported_pattern(pattern: str) -> bool:
    """Whether the given STIX pattern maps to an observable Vectra can ingest."""
    return extract_indicator(pattern) is not None


def _properties_xml(observable_type: str, value: str) -> str:
    escaped = escape(value)
    if observable_type in ("ipv4-addr", "ipv6-addr"):
        return (
            '<cybox:Properties xsi:type="AddressObj:AddressObjectType" '
            f"category={quoteattr(observable_type)}>"
            f"<AddressObj:Address_Value>{escaped}</AddressObj:Address_Value>"
            "</cybox:Properties>"
        )
    if observable_type == "domain-name":
        return (
            '<cybox:Properties xsi:type="DomainNameObj:DomainNameObjectType" type="FQDN">'
            f"<DomainNameObj:Value>{escaped}</DomainNameObj:Value>"
            "</cybox:Properties>"
        )
    if observable_type == "url":
        return (
            '<cybox:Properties xsi:type="URIObj:URIObjectType" type="URL">'
            f"<URIObj:Value>{escaped}</URIObj:Value>"
            "</cybox:Properties>"
        )
    raise ValueError(f"Unsupported observable type: {observable_type}")


def _build_indicator_xml(observable_type: str, value: str) -> str:
    indicator_id = quoteattr(f"opencti:Indicator-{uuid.uuid4()}")
    observable_id = quoteattr(f"opencti:Observable-{uuid.uuid4()}")
    object_id = quoteattr(f"opencti:Object-{uuid.uuid4()}")
    title = escape(f"{observable_type} {value}")
    properties = _properties_xml(observable_type, value)
    return (
        f'<stix:Indicator xsi:type="indicator:IndicatorType" id={indicator_id}>'
        f"<indicator:Title>{title}</indicator:Title>"
        f"<indicator:Observable id={observable_id}>"
        f"<cybox:Object id={object_id}>"
        f"{properties}"
        "</cybox:Object>"
        "</indicator:Observable>"
        "</stix:Indicator>"
    )


def build_stix_package(indicators: list[tuple[str, str]]) -> str:
    """
    Build a STIX 1.2 package XML document for the given indicators.

    :param indicators: A list of (observable_type, value) tuples.
    :return: A STIX 1.2 XML document as a string.
    """
    package_id = quoteattr(f"opencti:Package-{uuid.uuid4()}")
    body = "".join(
        _build_indicator_xml(observable_type, value)
        for observable_type, value in indicators
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<stix:STIX_Package {_NAMESPACES} id={package_id} version="1.2">'
        f"<stix:Indicators>{body}</stix:Indicators>"
        "</stix:STIX_Package>"
    )
