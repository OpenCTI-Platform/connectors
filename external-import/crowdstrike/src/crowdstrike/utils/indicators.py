# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike indicator utilities module."""

from typing import List, NamedTuple

from stix2 import ObjectPath  # type: ignore
from stix2 import EqualityComparisonExpression, ObservationExpression, StringConstant

_OBJECT_TYPE_IPV4_ADDR = "ipv4-addr"
_OBJECT_TYPE_IPV6_ADDR = "ipv6-addr"
_OBJECT_TYPE_DOMAIN_NAME = "domain-name"
_OBJECT_TYPE_HOSTNAME = "hostname"
_OBJECT_TYPE_EMAIL_ADDR = "email-addr"
_OBJECT_TYPE_EMAIL_MESSAGE = "email-message"
_OBJECT_TYPE_URL = "url"
_OBJECT_TYPE_FILE = "file"
_OBJECT_TYPE_MUTEX = "mutex"
_OBJECT_TYPE_CRYPTOCURRENCY_WALLET = "cryptocurrency-wallet"
_OBJECT_TYPE_PROCESS = "process"
_OBJECT_TYPE_X509_CERTIFICATE = "x509-certificate"
_OBJECT_TYPE_USER_AGENT = "user-agent"

_HASH_MD5 = "MD5"
_HASH_SHA1 = "SHA-1"
_HASH_SHA256 = "SHA-256"

_OBJECT_TYPE_TO_OBSERVABLE_TYPE_MAP = {
    _OBJECT_TYPE_IPV4_ADDR: "IPv4-Addr",
    _OBJECT_TYPE_IPV6_ADDR: "IPv6-Addr",
    _OBJECT_TYPE_DOMAIN_NAME: "Domain-Name",
    _OBJECT_TYPE_HOSTNAME: "Hostname",
    _OBJECT_TYPE_EMAIL_ADDR: "Email-Addr",
    _OBJECT_TYPE_EMAIL_MESSAGE: "Email-Message",
    _OBJECT_TYPE_URL: "Url",
    _OBJECT_TYPE_FILE: "StixFile",
    _OBJECT_TYPE_MUTEX: "Mutex",
    _OBJECT_TYPE_CRYPTOCURRENCY_WALLET: "Cryptocurrency-Wallet",
    _OBJECT_TYPE_PROCESS: "Process",
    _OBJECT_TYPE_X509_CERTIFICATE: "X509-Certificate",
    _OBJECT_TYPE_USER_AGENT: "User-Agent",
}


class IndicatorPattern(NamedTuple):
    """Indicator pattern."""

    pattern: str
    main_observable_type: str


def _create_equality_observation_expression_str(
    object_path: ObjectPath, value: str
) -> str:
    """Create observation expression string with pattern equality comparison expression."""  # noqa: E501
    operand = EqualityComparisonExpression(object_path, StringConstant(value))
    observation_expression = ObservationExpression(str(operand))
    return str(observation_expression)


def _create_object_path(object_type: str, property_path: List[str]) -> ObjectPath:
    """Create pattern operand object (property) path."""
    return ObjectPath(object_type, property_path)


def _create_pattern(object_type: str, property_path: List[str], value: str) -> str:
    object_path = _create_object_path(object_type, property_path)
    return _create_equality_observation_expression_str(object_path, value)


def _create_indicator_pattern(
    object_type: str, property_path: List[str], value: str
) -> IndicatorPattern:
    pattern = _create_pattern(object_type, property_path, value)
    main_observable_type = _OBJECT_TYPE_TO_OBSERVABLE_TYPE_MAP[object_type]
    return IndicatorPattern(pattern=pattern, main_observable_type=main_observable_type)


def _create_indicator_pattern_with_value(
    object_type: str, value: str
) -> IndicatorPattern:
    return _create_indicator_pattern(object_type, ["value"], value)


def create_indicator_pattern_ipv4_address(value: str) -> IndicatorPattern:
    """Create an indicator pattern for an IPv4 address."""
    return _create_indicator_pattern_with_value(_OBJECT_TYPE_IPV4_ADDR, value)


def create_indicator_pattern_ipv6_address(value: str) -> IndicatorPattern:
    """Create an indicator pattern for an IPv6 address."""
    return _create_indicator_pattern_with_value(_OBJECT_TYPE_IPV6_ADDR, value)


def create_indicator_pattern_domain_name(value: str) -> IndicatorPattern:
    """Create an indicator pattern for a domain name."""
    return _create_indicator_pattern_with_value(_OBJECT_TYPE_DOMAIN_NAME, value)


def create_indicator_pattern_hostname(value: str) -> IndicatorPattern:
    """Create an indicator pattern for a hostname."""
    return _create_indicator_pattern_with_value(_OBJECT_TYPE_HOSTNAME, value)


def create_indicator_pattern_email_address(value: str) -> IndicatorPattern:
    """Create an indicator pattern for an email address."""
    return _create_indicator_pattern_with_value(_OBJECT_TYPE_EMAIL_ADDR, value)


def create_indicator_pattern_url(value: str) -> IndicatorPattern:
    """Create an indicator pattern for an URL."""
    return _create_indicator_pattern_with_value(_OBJECT_TYPE_URL, value)


def _create_indicator_pattern_file_hashes(
    algorithm: str, value: str
) -> IndicatorPattern:
    return _create_indicator_pattern(_OBJECT_TYPE_FILE, ["hashes", algorithm], value)


def create_indicator_pattern_file_md5(value: str) -> IndicatorPattern:
    """Create an indicator pattern for a MD5 hash of a file."""
    return _create_indicator_pattern_file_hashes(_HASH_MD5, value)


def create_indicator_pattern_file_sha1(value: str) -> IndicatorPattern:
    """Create an indicator pattern for a SHA-1 hash of a file."""
    return _create_indicator_pattern_file_hashes(_HASH_SHA1, value)


def create_indicator_pattern_file_sha256(value: str) -> IndicatorPattern:
    """Create an indicator pattern for a SHA-256 hash of a file."""
    return _create_indicator_pattern_file_hashes(_HASH_SHA256, value)


def _create_indicator_pattern_with_name(
    object_type: str, name: str
) -> IndicatorPattern:
    return _create_indicator_pattern(object_type, ["name"], name)


def create_indicator_pattern_file_name(name: str) -> IndicatorPattern:
    """Create an indicator pattern for a file name."""
    return _create_indicator_pattern_with_name(_OBJECT_TYPE_FILE, name)


def create_indicator_pattern_mutex(name: str) -> IndicatorPattern:
    """Create an indicator pattern for a mutex."""
    return _create_indicator_pattern_with_name(_OBJECT_TYPE_MUTEX, name)


def create_indicator_pattern_cryptocurrency_wallet(value: str) -> IndicatorPattern:
    """Create an indicator pattern for a cryptocurrency wallet."""
    return _create_indicator_pattern_with_value(
        _OBJECT_TYPE_CRYPTOCURRENCY_WALLET, value
    )


def create_indicator_pattern_windows_service_name(name: str) -> IndicatorPattern:
    """Create an indicator pattern for a Windows service name."""
    return _create_indicator_pattern(
        _OBJECT_TYPE_PROCESS,
        ["extensions", "windows-process-ext", "service_name"],
        name,
    )


def _create_indicator_pattern_x509_certificate(
    prop: str, value: str
) -> IndicatorPattern:
    return _create_indicator_pattern(_OBJECT_TYPE_X509_CERTIFICATE, [prop], value)


def create_indicator_pattern_x509_certificate_serial_number(
    value: str,
) -> IndicatorPattern:
    """Create an indicator pattern for a X509 certificate serial number."""
    return _create_indicator_pattern_x509_certificate("serial_number", value)


def create_indicator_pattern_x509_certificate_subject(value: str) -> IndicatorPattern:
    """Create an indicator pattern for a X509 certificate subject."""
    return _create_indicator_pattern_x509_certificate("subject", value)


def create_indicator_pattern_user_agent(value: str) -> IndicatorPattern:
    """Create an indicator pattern for an user-agent."""
    return _create_indicator_pattern_with_value(_OBJECT_TYPE_USER_AGENT, value)


def create_indicator_pattern_email_message_subject(value: str) -> IndicatorPattern:
    """Create an indicator pattern for an email message subject."""
    return _create_indicator_pattern(_OBJECT_TYPE_EMAIL_MESSAGE, ["subject"], value)
