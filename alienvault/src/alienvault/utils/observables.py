# -*- coding: utf-8 -*-
"""OpenCTI AlienVault observable utilities module."""

from typing import Any, List, Mapping, Optional

from stix2 import (  # type: ignore
    CustomObservable,
    DomainName,
    EmailAddress,
    File,
    IPv4Address,
    IPv6Address,
    MarkingDefinition,
    Mutex,
    URL,
)
from stix2.properties import ListProperty, ReferenceProperty, StringProperty  # type: ignore # noqa: E501

from alienvault.utils.constants import (
    DEFAULT_X_OPENCTI_SCORE,
    X_OPENCTI_LABELS,
    X_OPENCTI_SCORE,
)


def _get_default_custom_properties(
    labels: Optional[List[str]] = None,
) -> Mapping[str, Any]:
    # XXX: Causes an unexpected property (x_opencti_score) error
    # when creating a Bundle without allow_custom=True flag.
    return {X_OPENCTI_LABELS: labels, X_OPENCTI_SCORE: DEFAULT_X_OPENCTI_SCORE}


def create_observable_ipv4_address(
    value: str,
    labels: List[str],
    object_markings: List[MarkingDefinition],
) -> IPv4Address:
    """Create an observable representing an IPv4 address."""
    return IPv4Address(
        value=value,
        object_marking_refs=object_markings,
        custom_properties=_get_default_custom_properties(labels),
    )


def create_observable_ipv6_address(
    value: str,
    labels: List[str],
    object_markings: List[MarkingDefinition],
) -> IPv6Address:
    """Create an observable representing an IPv6 address."""
    return IPv6Address(
        value=value,
        object_marking_refs=object_markings,
        custom_properties=_get_default_custom_properties(labels),
    )


def create_observable_domain_name(
    value: str,
    labels: List[str],
    object_markings: List[MarkingDefinition],
) -> DomainName:
    """Create an observable representing a domain name."""
    return DomainName(
        value=value,
        object_marking_refs=object_markings,
        custom_properties=_get_default_custom_properties(labels),
    )


@CustomObservable(
    "x-opencti-hostname",
    [
        ("value", StringProperty(required=True)),
        ("spec_version", StringProperty(fixed="2.1")),
        (
            "object_marking_refs",
            ListProperty(
                ReferenceProperty(valid_types="marking-definition", spec_version="2.1")
            ),
        ),
    ],
    ["value"],
)
class Hostname:
    """Hostname observable."""

    pass


def create_observable_hostname(
    value: str,
    labels: List[str],
    object_markings: List[MarkingDefinition],
) -> Hostname:
    """Create an observable representing a hostname."""
    return Hostname(
        value=value,
        object_marking_refs=object_markings,
        custom_properties=_get_default_custom_properties(labels),
    )  # type: ignore


def create_observable_email_address(
    value: str,
    labels: List[str],
    object_markings: List[MarkingDefinition],
) -> EmailAddress:
    """Create an observable representing an email address."""
    return EmailAddress(
        value=value,
        object_marking_refs=object_markings,
        custom_properties=_get_default_custom_properties(labels),
    )


def create_observable_url(
    value: str, labels: List[str], object_markings: List[MarkingDefinition]
) -> URL:
    """Create an observable representing an URL."""
    return URL(
        value=value,
        object_marking_refs=object_markings,
        custom_properties=_get_default_custom_properties(labels),
    )


def _create_observable_file(
    hashes: Optional[Mapping[str, str]] = None,
    name: Optional[str] = None,
    labels: Optional[List[str]] = None,
    object_markings: Optional[List[MarkingDefinition]] = None,
) -> File:
    return File(
        hashes=hashes,
        name=name,
        object_marking_refs=object_markings,
        custom_properties=_get_default_custom_properties(labels),
    )


def create_observable_file_md5(
    value: str, labels: List[str], object_markings: List[MarkingDefinition]
) -> File:
    """Create an observable representing a MD5 hash of a file."""
    return _create_observable_file(
        hashes={"MD5": value}, labels=labels, object_markings=object_markings
    )


def create_observable_file_sha1(
    value: str, labels: List[str], object_markings: List[MarkingDefinition]
) -> File:
    """Create an observable representing a SHA-1 hash of a file."""
    return _create_observable_file(
        hashes={"SHA-1": value}, labels=labels, object_markings=object_markings
    )


def create_observable_file_sha256(
    value: str, labels: List[str], object_markings: List[MarkingDefinition]
) -> File:
    """Create an observable representing a SHA-256 hash of a file."""
    return _create_observable_file(
        hashes={"SHA-256": value}, labels=labels, object_markings=object_markings
    )


def create_observable_file_name(
    name: str, labels: List[str], object_markings: List[MarkingDefinition]
) -> File:
    """Create an observable representing a file name."""
    return _create_observable_file(
        name=name, labels=labels, object_markings=object_markings
    )


def create_observable_mutex(
    name: str, labels: List[str], object_markings: List[MarkingDefinition]
) -> Mutex:
    """Create an observable representing a mutex."""
    return Mutex(
        name=name,
        object_marking_refs=object_markings,
        custom_properties=_get_default_custom_properties(labels),
    )


@CustomObservable(
    "x-opencti-cryptocurrency-wallet",
    [
        ("value", StringProperty(required=True)),
        ("spec_version", StringProperty(fixed="2.1")),
        (
            "object_marking_refs",
            ListProperty(
                ReferenceProperty(valid_types="marking-definition", spec_version="2.1")
            ),
        ),
    ],
    ["value"],
)
class CryptocurrencyWallet:
    """Cryptocurrency wallet observable."""

    pass


def create_observable_cryptocurrency_wallet(
    value: str, labels: List[str], object_markings: List[MarkingDefinition]
) -> CryptocurrencyWallet:
    """Create an observable representing a cryptocurrency wallet."""
    return CryptocurrencyWallet(
        value=value,
        object_marking_refs=object_markings,
        custom_properties=_get_default_custom_properties(labels),
    )  # type: ignore
