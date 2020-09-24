# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike indicator utilities module."""

from typing import List

from stix2 import (  # type: ignore
    EqualityComparisonExpression,
    ObjectPath,
    ObservationExpression,
    StringConstant,
)


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


def _create_indicator_pattern(
    object_type: str, property_path: List[str], value: str
) -> str:
    object_path = _create_object_path(object_type, property_path)
    return _create_equality_observation_expression_str(object_path, value)


def _create_indicator_pattern_with_value(object_type: str, value: str) -> str:
    return _create_indicator_pattern(object_type, ["value"], value)


def create_indicator_pattern_ipv4_address(value: str) -> str:
    """Create an indicator pattern for an IPv4 address."""
    return _create_indicator_pattern_with_value("ipv4-addr", value)


def create_indicator_pattern_ipv6_address(value: str) -> str:
    """Create an indicator pattern for an IPv6 address."""
    return _create_indicator_pattern_with_value("ipv6-addr", value)


def create_indicator_pattern_domain_name(value: str) -> str:
    """Create an indicator pattern for a domain name."""
    return _create_indicator_pattern_with_value("domain-name", value)


def create_indicator_pattern_hostname(value: str) -> str:
    """Create an indicator pattern for a hostname."""
    return _create_indicator_pattern_with_value("x-opencti-hostname", value)


def create_indicator_pattern_email_address(value: str) -> str:
    """Create an indicator pattern for an email address."""
    return _create_indicator_pattern_with_value("email-addr", value)


def create_indicator_pattern_url(value: str) -> str:
    """Create an indicator pattern for an URL."""
    return _create_indicator_pattern_with_value("url", value)


def _create_indicator_pattern_file_hashes(algorithm: str, value: str) -> str:
    return _create_indicator_pattern("file", ["hashes", algorithm], value)


def create_indicator_pattern_file_md5(value: str) -> str:
    """Create an indicator pattern for a MD5 hash of a file."""
    return _create_indicator_pattern_file_hashes("MD5", value)


def create_indicator_pattern_file_sha1(value: str) -> str:
    """Create an indicator pattern for a SHA-1 hash of a file."""
    return _create_indicator_pattern_file_hashes("SHA-1", value)


def create_indicator_pattern_file_sha256(value: str) -> str:
    """Create an indicator pattern for a SHA-256 hash of a file."""
    return _create_indicator_pattern_file_hashes("SHA-256", value)


def _create_indicator_pattern_with_name(object_type: str, name: str) -> str:
    return _create_indicator_pattern(object_type, ["name"], name)


def create_indicator_pattern_file_name(name: str) -> str:
    """Create an indicator pattern for a file name."""
    return _create_indicator_pattern_with_name("file", name)


def create_indicator_pattern_mutex(name: str) -> str:
    """Create an indicator pattern for a mutex."""
    return _create_indicator_pattern_with_name("mutex", name)


def create_indicator_pattern_cryptocurrency_wallet(value: str) -> str:
    """Create an indicator pattern for a cryptocurrency wallet."""
    return _create_indicator_pattern_with_value(
        "x-opencti-cryptocurrency-wallet", value
    )


def create_indicator_pattern_windows_service_name(name: str) -> str:
    """Create an indicator pattern for a Windows service name."""
    return _create_indicator_pattern(
        "process", ["extensions", "windows-process-ext", "service_name"], name
    )


def _create_indicator_pattern_x509_certificate(prop: str, value: str) -> str:
    return _create_indicator_pattern("x509-certificate", [prop], value)


def create_indicator_pattern_x509_certificate_serial_number(value: str) -> str:
    """Create an indicator pattern for a X509 certificate serial number."""
    return _create_indicator_pattern_x509_certificate("serial_number", value)


def create_indicator_pattern_x509_certificate_subject(value: str) -> str:
    """Create an indicator pattern for a X509 certificate subject."""
    return _create_indicator_pattern_x509_certificate("subject", value)


def create_indicator_pattern_user_agent(value: str) -> str:
    """Create an indicator pattern for an user-agent."""
    return _create_indicator_pattern_with_value("x-opencti-user-agent", value)


def create_indicator_pattern_email_message_subject(value: str) -> str:
    """Create an indicator pattern for an email message subject."""
    return _create_indicator_pattern("email-message", ["subject"], value)
