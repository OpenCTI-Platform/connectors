"""STIX2 indicator pattern factories"""

from enum import Enum
from typing import List, NamedTuple, Union

from stix2 import (EqualityComparisonExpression, ObjectPath,
                   ObservationExpression)

__all__ = [
    "create_indicator_pattern_url",
    "create_indicator_pattern_domain_name",
    "create_indicator_pattern_ipv4_address",
    "create_indicator_pattern_ipv6_address",
    "IndicatorPattern",
]


class _ObjectTypeData(NamedTuple):
    object_type: str
    main_observable_type: str
    property_path: List[str]

    def create_pattern(self, value: str) -> str:
        """Create a STIX2 compliant Indicator pattern
        :param value: Property path value
        :return: A STIX2 compliant Indicator pattern
        """
        object_path = ObjectPath(self.object_type, self.property_path)
        ece = EqualityComparisonExpression(object_path, value)
        oe = ObservationExpression(str(ece))
        return str(oe)


class _ObjectType(_ObjectTypeData, Enum):
    IPv4 = ("ipv4-addr", "IPv4-Addr", ["value"])
    IPv6 = ("ipv6-addr", "IPv6-Addr", ["value"])
    DomainName = ("domain-name", "Domain-Name", ["value"])
    Url = ("url", "Url", ["value"])


class IndicatorPattern(NamedTuple):
    """Indicator pattern."""

    pattern: str
    main_observable_type: str


def _create_indicator_pattern(
    type_data: _ObjectTypeData,
    value: Union[str, int],
) -> IndicatorPattern:
    """
    :param type_data: Object type
    :param value: Property path value
    :return: A STIX2 complaint Indicator pattern and observable type
    """
    return IndicatorPattern(
        pattern=type_data.create_pattern(value),
        main_observable_type=type_data.main_observable_type,
    )


def create_indicator_pattern_domain_name(value: str) -> IndicatorPattern:
    """Create an indicator pattern for a domain name"""
    return _create_indicator_pattern(_ObjectType.DomainName, value)


def create_indicator_pattern_ipv4_address(value: str) -> IndicatorPattern:
    """Create an indicator pattern for an IPv4 address"""
    return _create_indicator_pattern(_ObjectType.IPv4, value)


def create_indicator_pattern_ipv6_address(value: str) -> IndicatorPattern:
    """Create an indicator pattern for an IPv6 address"""
    return _create_indicator_pattern(_ObjectType.IPv6, value)


def create_indicator_pattern_url(value: str) -> IndicatorPattern:
    """Create an indicator pattern for a URL"""
    return _create_indicator_pattern(_ObjectType.Url, value)
