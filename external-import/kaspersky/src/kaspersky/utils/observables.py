"""Kaspersky observable utilities module."""

from typing import Any, List, Mapping, NamedTuple, Optional, Union

from kaspersky.utils.common import (
    DEFAULT_X_OPENCTI_SCORE,
    X_OPENCTI_CREATED_BY_REF,
    X_OPENCTI_DESCRIPTION,
    X_OPENCTI_LABELS,
    X_OPENCTI_SCORE,
    is_ip_address,
    is_ipv4_address,
)
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


class ObservableProperties(NamedTuple):
    """Observable properties."""

    value: str
    created_by: Identity
    labels: List[str]
    object_markings: List[MarkingDefinition]
    description: Optional[str] = None


def _get_custom_properties(properties: ObservableProperties) -> Mapping[str, Any]:
    created_by = properties.created_by
    labels = properties.labels
    description = properties.description

    # XXX: Causes an unexpected property (x_opencti_score) error
    # when creating a Bundle without allow_custom=True flag.
    custom_properties = {
        X_OPENCTI_LABELS: labels,
        X_OPENCTI_SCORE: DEFAULT_X_OPENCTI_SCORE,
    }

    if created_by is not None:
        custom_properties[X_OPENCTI_CREATED_BY_REF] = created_by["id"]

    if description is not None and description:
        custom_properties[X_OPENCTI_DESCRIPTION] = description

    return custom_properties


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


def create_observable_ip_address(
    properties: ObservableProperties,
) -> Union[IPv4Address, IPv6Address]:
    """Create an observable representing an IPv4 address or an IPv6 address."""
    value = properties.value

    if is_ipv4_address(value):
        return create_observable_ipv4_address(properties)
    else:
        return create_observable_ipv6_address(properties)


def create_observable_network_activity(
    properties: ObservableProperties,
) -> Union[IPv4Address, IPv6Address, DomainName]:
    """Create an observable representing a network activity."""
    value = properties.value

    if is_ip_address(value):
        return create_observable_ip_address(properties)
    else:
        return create_observable_domain_name(properties)


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
    hashes: Optional[Mapping[str, str]] = None,
    name: Optional[str] = None,
    object_markings: Optional[List[MarkingDefinition]] = None,
    custom_properties: Optional[Mapping[str, Any]] = None,
) -> File:
    if custom_properties is None:
        custom_properties = {}

    return File(
        hashes=hashes,
        name=name,
        object_marking_refs=object_markings,
        custom_properties=custom_properties,
    )


def create_observable_file_md5(properties: ObservableProperties) -> File:
    """Create an observable representing a MD5 hash of a file."""
    return _create_observable_file(
        hashes={"MD5": properties.value},
        object_markings=properties.object_markings,
        custom_properties=_get_custom_properties(properties),
    )


def create_observable_file_sha1(properties: ObservableProperties) -> File:
    """Create an observable representing a SHA-1 hash of a file."""
    return _create_observable_file(
        hashes={"SHA-1": properties.value},
        object_markings=properties.object_markings,
        custom_properties=_get_custom_properties(properties),
    )


def create_observable_file_sha256(properties: ObservableProperties) -> File:
    """Create an observable representing a SHA-256 hash of a file."""
    return _create_observable_file(
        hashes={"SHA-256": properties.value},
        object_markings=properties.object_markings,
        custom_properties=_get_custom_properties(properties),
    )


def create_observable_file_name(properties: ObservableProperties) -> File:
    """Create an observable representing a file name."""
    return _create_observable_file(
        name=properties.value,
        object_markings=properties.object_markings,
        custom_properties=_get_custom_properties(properties),
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


def _create_observable_process(
    extensions: Optional[Mapping[str, Any]] = None,
    object_markings: Optional[List[MarkingDefinition]] = None,
    custom_properties: Optional[Mapping[str, Any]] = None,
) -> Process:
    if custom_properties is None:
        custom_properties = {}

    return Process(
        extensions=extensions,
        object_marking_refs=object_markings,
        custom_properties=custom_properties,
    )


def _create_observable_windows_service_ext(
    property_name: str,
    properties: ObservableProperties,
) -> Process:
    extensions = {"windows-service-ext": {property_name: properties.value}}

    return Process(
        extensions=extensions,
        object_marking_refs=properties.object_markings,
        custom_properties=_get_custom_properties(properties),
    )


def create_observable_windows_service_name(properties: ObservableProperties) -> Process:
    """Create an observable representing a Windows service name."""
    return _create_observable_windows_service_ext("service_name", properties)


def create_observable_windows_service_display_name(
    properties: ObservableProperties,
) -> Process:
    """Create an observable representing a Windows service display name."""
    return _create_observable_windows_service_ext("display_name", properties)


def _create_observable_x509_certificate(
    serial_number: Optional[str] = None,
    issuer: Optional[str] = None,
    subject: Optional[str] = None,
    object_markings: Optional[List[MarkingDefinition]] = None,
    custom_properties: Optional[Mapping[str, Any]] = None,
) -> X509Certificate:
    if custom_properties is None:
        custom_properties = {}

    return X509Certificate(
        serial_number=serial_number,
        issuer=issuer,
        subject=subject,
        object_marking_refs=object_markings,
        custom_properties=custom_properties,
    )


def create_observable_x509_certificate_serial_number(
    properties: ObservableProperties,
) -> X509Certificate:
    """Create an observable representing a X509 certificate serial number."""
    return _create_observable_x509_certificate(
        serial_number=properties.value,
        object_markings=properties.object_markings,
        custom_properties=_get_custom_properties(properties),
    )


def create_observable_x509_certificate_subject(
    properties: ObservableProperties,
) -> X509Certificate:
    """Create an observable representing a X509 certificate subject."""
    return _create_observable_x509_certificate(
        subject=properties.value,
        object_markings=properties.object_markings,
        custom_properties=_get_custom_properties(properties),
    )


def create_observable_x509_certificate_issuer(
    properties: ObservableProperties,
) -> X509Certificate:
    """Create an observable representing a X509 certificate issuer."""
    return _create_observable_x509_certificate(
        issuer=properties.value,
        object_markings=properties.object_markings,
        custom_properties=_get_custom_properties(properties),
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
