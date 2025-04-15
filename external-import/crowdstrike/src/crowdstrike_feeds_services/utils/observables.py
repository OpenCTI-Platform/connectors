# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike observable utilities module."""

from typing import Any, List, Mapping, NamedTuple, Optional

from pycti import (
    CustomObservableCryptocurrencyWallet,
    CustomObservableHostname,
    CustomObservableUserAgent,
)
from stix2 import DomainName  # type: ignore
from stix2 import (
    URL,
    EmailAddress,
    EmailMessage,
    File,
    Identity,
    IPv4Address,
    IPv6Address,
    MarkingDefinition,
    Mutex,
    Process,
    X509Certificate,
)

from .constants import X_OPENCTI_CREATED_BY_REF, X_OPENCTI_LABELS, X_OPENCTI_SCORE


def _get_default_custom_properties(
    created_by: Optional[Identity] = None,
    labels: Optional[List[str]] = None,
    score: Optional[int] = None,
) -> Mapping[str, Any]:
    # XXX: Causes an unexpected property (x_opencti_score) error
    # when creating a Bundle without allow_custom=True flag.
    custom_properties = {
        X_OPENCTI_LABELS: labels,
        X_OPENCTI_SCORE: score,
    }

    if created_by is not None:
        custom_properties[X_OPENCTI_CREATED_BY_REF] = created_by["id"]

    return custom_properties


class ObservableProperties(NamedTuple):
    """Observable properties."""

    value: str
    created_by: Identity
    labels: List[str]
    score: int
    object_markings: List[MarkingDefinition]


def _get_custom_properties(properties: ObservableProperties) -> Mapping[str, Any]:
    return _get_default_custom_properties(
        created_by=properties.created_by,
        labels=properties.labels,
        score=properties.score,
    )


def create_observable_ipv4_address(properties: ObservableProperties) -> IPv4Address:
    """Create an observable representing an IPv4 address."""
    return IPv4Address(
        value=properties.value,
        object_marking_refs=properties.object_markings,
        custom_properties=_get_custom_properties(properties),
    )


def create_observable_ipv6_address(properties: ObservableProperties) -> IPv6Address:
    """Create an observable representing an IPv6 address."""
    return IPv6Address(
        value=properties.value,
        object_marking_refs=properties.object_markings,
        custom_properties=_get_custom_properties(properties),
    )


def create_observable_domain_name(properties: ObservableProperties) -> DomainName:
    """Create an observable representing a domain name."""
    return DomainName(
        value=properties.value,
        object_marking_refs=properties.object_markings,
        custom_properties=_get_custom_properties(properties),
    )


def create_observable_hostname(
    properties: ObservableProperties,
) -> CustomObservableHostname:
    """Create an observable representing a hostname."""
    return CustomObservableHostname(
        value=properties.value,
        object_marking_refs=properties.object_markings,
        custom_properties=_get_custom_properties(properties),
    )  # type: ignore


def create_observable_email_address(properties: ObservableProperties) -> EmailAddress:
    """Create an observable representing an email address."""
    return EmailAddress(
        value=properties.value,
        object_marking_refs=properties.object_markings,
        custom_properties=_get_custom_properties(properties),
    )


def create_observable_url(properties: ObservableProperties) -> URL:
    """Create an observable representing an URL."""
    return URL(
        value=properties.value,
        object_marking_refs=properties.object_markings,
        custom_properties=_get_custom_properties(properties),
    )


def _create_observable_file(
    properties: ObservableProperties,
    hashes: Optional[Mapping[str, str]] = None,
    name: Optional[str] = None,
) -> File:
    return File(
        hashes=hashes,
        name=name,
        object_marking_refs=properties.object_markings,
        custom_properties=_get_custom_properties(properties),
    )


def create_observable_file_md5(properties: ObservableProperties) -> File:
    """Create an observable representing a MD5 hash of a file."""
    return _create_observable_file(
        properties,
        hashes={"MD5": properties.value},
    )


def create_observable_file_sha1(properties: ObservableProperties) -> File:
    """Create an observable representing a SHA-1 hash of a file."""
    return _create_observable_file(
        properties,
        hashes={"SHA-1": properties.value},
    )


def create_observable_file_sha256(properties: ObservableProperties) -> File:
    """Create an observable representing a SHA-256 hash of a file."""
    return _create_observable_file(
        properties,
        hashes={"SHA-256": properties.value},
    )


def create_observable_file_name(properties: ObservableProperties) -> File:
    """Create an observable representing a file name."""
    return _create_observable_file(
        properties,
        name=properties.value,
    )


def create_observable_mutex(properties: ObservableProperties) -> Mutex:
    """Create an observable representing a mutex."""
    return Mutex(
        name=properties.value,
        object_marking_refs=properties.object_markings,
        custom_properties=_get_custom_properties(properties),
    )


def create_observable_cryptocurrency_wallet(
    properties: ObservableProperties,
) -> CustomObservableCryptocurrencyWallet:
    """Create an observable representing a cryptocurrency wallet."""
    return CustomObservableCryptocurrencyWallet(
        value=properties.value,
        object_marking_refs=properties.object_markings,
        custom_properties=_get_custom_properties(properties),
    )  # type: ignore


def create_observable_windows_service_name(properties: ObservableProperties) -> Process:
    """Create an observable representing a Windows service name."""
    # The Process does not have ID Contributing Properties.
    # Specification says to use UUIDv4 but for OpenCTI we will use random identifier.
    return Process(
        object_marking_refs=properties.object_markings,
        extensions={"windows-service-ext": {"service_name": properties.value}},
        custom_properties=_get_custom_properties(properties),
    )


def _create_observable_x509_certificate(
    properties: ObservableProperties,
    serial_number: Optional[str] = None,
    subject: Optional[str] = None,
) -> X509Certificate:
    return X509Certificate(
        serial_number=serial_number,
        subject=subject,
        object_marking_refs=properties.object_markings,
        custom_properties=_get_custom_properties(properties),
    )


def create_observable_x509_certificate_serial_number(
    properties: ObservableProperties,
) -> X509Certificate:
    """Create an observable representing a X509 certificate serial number."""
    return _create_observable_x509_certificate(
        properties,
        serial_number=properties.value,
    )


def create_observable_x509_certificate_subject(
    properties: ObservableProperties,
) -> X509Certificate:
    """Create an observable representing a X509 certificate subject."""
    return _create_observable_x509_certificate(
        properties,
        subject=properties.value,
    )


def create_observable_user_agent(
    properties: ObservableProperties,
) -> CustomObservableUserAgent:
    """Create an observable representing an user-agent."""
    return CustomObservableUserAgent(
        value=properties.value,
        object_marking_refs=properties.object_markings,
        custom_properties=_get_custom_properties(properties),
    )  # type: ignore


def create_observable_email_message_subject(
    properties: ObservableProperties,
) -> EmailMessage:
    """Create an observable representing an email message subject."""
    return EmailMessage(
        is_multipart=False,
        subject=properties.value,
        object_marking_refs=properties.object_markings,
        custom_properties=_get_custom_properties(properties),
    )
