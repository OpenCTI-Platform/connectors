"""Offer enum for OpenCTI models."""

import warnings
from enum import StrEnum


class PermissiveEnum(StrEnum):
    """Enum that allows for missing values."""

    @classmethod
    def _missing_(cls: type["PermissiveEnum"], value: object) -> "PermissiveEnum":
        _value = str(value)
        warnings.warn(
            f"Value '{_value}' is out of {cls.__name__} defined values.",
            UserWarning,
            stacklevel=3,
        )
        # Return a dynamically created instance
        obj = str.__new__(cls, _value)
        obj._value_ = _value
        return obj


class AttackMotivation(PermissiveEnum):
    """Attack Motivation Open Vocabulary.

    See https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_dmb1khqsn650
    """

    ACCIDENTAL = "accidental"
    COERCION = "coercion"
    DOMINANCE = "dominance"
    IDEOLOGY = "ideology"
    NOTORIETY = "notoriety"
    ORGANIZATIONAL_GAIN = "organizational-gain"
    PERSONAL_GAIN = "personal-gain"
    PERSONAL_SATISFACTION = "personal-satisfaction"
    REVENGE = "revenge"
    UNPREDICTABLE = "unpredictable"


class AttackResourceLevel(PermissiveEnum):
    """Attack Resource Level Open Vocabulary.

    See https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_moarppphq8vq
    """

    INDIVIDUAL = "individual"
    CLUB = "club"
    CONTEST = "contest"
    TEAM = "team"
    ORGANIZATION = "organization"
    GOVERNMENT = "government"


class CvssSeverity(StrEnum):
    """CVSS Severity Enum.

    See https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/src/domain/vulnerability.js#L13
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "Unknown"


class IndustrySector(PermissiveEnum):
    """Industry Sector Open Vocabulary.

    See https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_oogrswk3onck
    """

    AGRICULTURE = "agriculture"
    AEROSPACE = "aerospace"
    AUTOMOTIVE = "automotive"
    CHEMICAL = "chemical"
    COMMERCIAL = "commercial"
    COMMUNICATIONS = "communications"
    CONSTRUCTION = "construction"
    DEFENSE = "defense"
    EDUCATION = "education"
    ENERGY = "energy"
    ENTERTAINMENT = "entertainment"
    FINANCIAL_SERVICES = "financial-services"

    # Government
    GOVERNMENT = "government"
    EMERGENCY_SERVICES = "emergency-services"
    GOVERNMENT_LOCAL = "government-local"
    GOVERNMENT_NATIONAL = "government-national"
    GOVERNMENT_PUBLIC_SERVICES = "government-public-services"
    GOVERNMENT_REGIONAL = "government-regional"

    HEALTHCARE = "healthcare"
    HOSPITALITY_LEISURE = "hospitality-leisure"

    # Infrastructure
    INFRASTRUCTURE = "infrastructure"
    DAMS = "dams"
    NUCLEAR = "nuclear"
    WATER = "water"

    INSURANCE = "insurance"
    MANUFACTURING = "manufacturing"
    MINING = "mining"
    NON_PROFIT = "non-profit"
    PHARMACEUTICALS = "pharmaceuticals"
    RETAIL = "retail"
    TECHNOLOGY = "technology"
    TELECOMMUNICATIONS = "telecommunications"
    TRANSPORTATION = "transportation"
    UTILITIES = "utilities"


class LocationType(StrEnum):
    """Location Type Enum.

    See https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/src/schema/stixDomainObject.ts#L47
    """

    ADMINISTRATIVE_AREA = "Administrative-Area"
    CITY = "City"
    COUNTRY = "Country"
    REGION = "Region"
    POSITION = "Position"


class Permission(PermissiveEnum):
    """Permission Open Vocabulary.

    See https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/src/modules/vocabulary/vocabulary-utils.ts#L793
    """

    USER = "user"
    ADMINISTRATOR = "administrator"


class Platform(PermissiveEnum):
    """Platform Open Vocabulary.

    See https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/src/modules/vocabulary/vocabulary-utils.ts#L797
    """

    WINDOWS = "windows"
    MACOS = "macos"
    LINUX = "linux"
    ANDROID = "android"


class Reliability(PermissiveEnum):
    """Reliability Open Vocabulary.

    See https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/src/modules/vocabulary/vocabulary-utils.ts#L866
    """

    A = "A - Completely reliable"
    B = "B - Usually reliable"
    C = "C - Fairly reliable"
    D = "D - Not usually reliable"
    E = "E - Unreliable"
    F = "F - Reliability cannot be judged"


class ReportType(PermissiveEnum):
    """Report Type Open Vocabulary.

    See https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_9lfdvxnyofxw
    """

    BREACH_ALERT = "breach_alert"
    FINTEL = "fintel"
    INFOREP = "inforep"
    INTELLIGENCE_SUMMARY = "intelligence_summary"
    INTERNAL_REPORT = "internal-report"
    MALWARE = "malware"
    SPOTREP = "spotrep"
    THREAT_REPORT = "threat-report"

