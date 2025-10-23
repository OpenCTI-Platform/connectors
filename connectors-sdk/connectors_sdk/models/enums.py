"""Offer enum for OpenCTI models."""

from __future__ import annotations

import warnings
from enum import StrEnum

__all__ = [
    "AttackMotivation",
    "AttackResourceLevel",
    "CvssSeverity",
    "HashAlgorithm",
    "ImplementationLanguage",
    "IndustrySector",
    "LocationType",
    "MalwareCapability",
    "MalwareType",
    "NoteType",
    "OrganizationType",
    "Permission",
    "Platform",
    "ProcessorArchitecture",
    "RelationshipType",
    "Reliability",
    "ReportType",
    "ThreatActorRole",
    "ThreatActorSophistication",
    "ThreatActorTypes",
    "TLPLevel",
]


class _PermissiveEnum(StrEnum):
    """Enum that allows for missing values."""

    @classmethod
    def _missing_(cls: type[_PermissiveEnum], value: object) -> _PermissiveEnum:
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


class AttackMotivation(_PermissiveEnum):
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


class AttackResourceLevel(_PermissiveEnum):
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


class HashAlgorithm(_PermissiveEnum):
    """Hash Algorithm Open Vocabulary.

    See https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_tumklw3o2gyz
    """

    MD5 = "MD5"
    SHA1 = "SHA-1"
    SHA256 = "SHA-256"
    SHA512 = "SHA-512"
    SHA3256 = "SHA3-256"
    SHA3512 = "SHA3-512"
    SSDEEP = "SSDEEP"
    TLSH = "TLSH"


class ImplementationLanguage(_PermissiveEnum):
    """Implementation Language Open Vocabulary.

    See https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_1s3o9ou3pbq
    """

    APPLESCRIPT = "applescript"
    BASH = "bash"
    C = "c"
    C_PLUS_PLUS = "c++"
    C_SHARP = "c#"
    GO = "go"
    JAVA = "java"
    JAVASCRIPT = "javascript"
    LUA = "lua"
    OBJECTIVE_C = "objective-c"
    PERL = "perl"
    PHP = "php"
    POWERSHELL = "powershell"
    PYTHON = "python"
    RUBY = "ruby"
    SCALA = "scala"
    SWIFT = "swift"
    TYPESCRIPT = "typescript"
    VISUAL_BASIC = "visual-basic"
    X86_32 = "x86-32"
    X86_64 = "x86-64"


class IndustrySector(_PermissiveEnum):
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


class MalwareCapability(_PermissiveEnum):
    """Malware Capability Open Vocabulary.

    See https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_2b6es5hl7gmc
    """

    ACCESSES_REMOTE_MACHINES = "accesses-remote-machines"
    ANTI_DEBUGGING = "anti-debugging"
    ANTI_DISASSEMBLY = "anti-disassembly"
    ANTI_EMULATION = "anti-emulation"
    ANTI_MEMORY_FORENSICS = "anti-memory-forensics"
    ANTI_SANDBOX = "anti-sandbox"
    ANTI_VM = "anti-vm"
    CAPTURES_INPUT_PERIPHERALS = "captures-input-peripherals"
    CAPTURES_OUTPUT_PERIPHERALS = "captures-output-peripherals"
    CAPTURES_SYSTEM_STATE_DATA = "captures-system-state-data"
    CLEANS_TRACES_OF_INFECTION = "cleans-traces-of-infection"
    COMMITS_FRAUD = "commits-fraud"
    COMMUNICATES_WITH_C2 = "communicates-with-c2"
    COMPROMISES_DATA_AVAILABILITY = "compromises-data-availability"
    COMPROMISES_DATA_INTEGRITY = "compromises-data-integrity"
    COMPROMISES_SYSTEM_AVAILABILITY = "compromises-system-availability"
    CONTROLS_LOCAL_MACHINE = "controls-local-machine"
    DEGRADES_SECURITY_SOFTWARE = "degrades-security-software"
    DEGRADES_SYSTEM_UPDATES = "degrades-system-updates"
    DETERMINES_C2_SERVER = "determines-c2-server"
    EMAILS_SPAM = "emails-spam"
    ESCALATES_PRIVILEGES = "escalates-privileges"
    EVADES_AV = "evades-av"
    EXFILTRATES_DATA = "exfiltrates-data"
    FINGERPRINTS_HOST = "fingerprints-host"
    HIDES_ARTIFACTS = "hides-artifacts"
    HIDES_EXECUTING_CODE = "hides-executing-code"
    INFECTS_FILES = "infects-files"
    INFECTS_REMOTE_MACHINES = "infects-remote-machines"
    INSTALLS_OTHER_COMPONENTS = "installs-other-components"
    PERSISTS_AFTER_SYSTEM_REBOOT = "persists-after-system-reboot"
    PREVENTS_ARTIFACT_ACCESS = "prevents-artifact-access"
    PREVENTS_ARTIFACT_DELETION = "prevents-artifact-deletion"
    PROBES_NETWORK_ENVIRONMENT = "probes-network-environment"
    SELF_MODIFIES = "self-modifies"
    STEALS_AUTHENTICATION_CREDENTIALS = "steals-authentication-credentials"
    VIOLATES_SYSTEM_OPERATIONAL_INTEGRITY = "violates-system-operational-integrity"


class MalwareType(_PermissiveEnum):
    """Malware Type Open Vocabulary.

    See https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_oxlc4df65spl
    """

    ADWARE = "adware"
    BACKDOOR = "backdoor"
    BOT = "bot"
    BOOTKIT = "bootkit"
    DDOS = "ddos"
    DOWNLOADER = "downloader"
    DROPPER = "dropper"
    EXPLOIT_KIT = "exploit-kit"
    KEYLOGGER = "keylogger"
    RANSOMWARE = "ransomware"
    REMOTE_ACCESS_TROJAN = "remote-access-trojan"
    RESOURCE_EXPLOITATION = "resource-exploitation"
    ROGUE_SECURITY_SOFTWARE = "rogue-security-software"
    ROOTKIT = "rootkit"
    SCREEN_CAPTURE = "screen-capture"
    SPYWARE = "spyware"
    TROJAN = "trojan"
    UNKNOWN = "unknown"
    VIRUS = "virus"
    WEBSHELL = "webshell"
    WIPER = "wiper"
    WORM = "worm"


class NoteType(_PermissiveEnum):
    """Note Type Enum.

    See https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/src/modules/vocabulary/vocabulary-utils.ts#L739
    """

    INTERNAL = "internal"
    ASSESSMENT = "assessment"
    ANALYSIS = "analysis"
    FEEDBACK = "feedback"
    EXTERNAL = "external"


class OrganizationType(_PermissiveEnum):
    """Organization Type Open Vocabulary.

    See https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/src/modules/vocabulary/vocabulary-utils.ts#L770
    """

    VENDOR = "vendor"
    PARTNER = "partner"
    CONSTITUENT = "constituent"
    CSIRT = "csirt"
    OTHER = "other"


class Permission(_PermissiveEnum):
    """Permission Open Vocabulary.

    See https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/src/modules/vocabulary/vocabulary-utils.ts#L793
    """

    USER = "user"
    ADMINISTRATOR = "administrator"


class Platform(_PermissiveEnum):
    """Platform Open Vocabulary.

    See https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/src/modules/vocabulary/vocabulary-utils.ts#L797
    """

    WINDOWS = "windows"
    MACOS = "macos"
    LINUX = "linux"
    ANDROID = "android"


class ProcessorArchitecture(_PermissiveEnum):
    """Processor Architecture Open Vocabulary.

    See https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_iup9ob79qwei
    """

    ALPHA = "alpha"
    ARM = "arm"
    IA_64 = "ia-64"
    MIPS = "mips"
    POWERPC = "powerpc"
    SPARC = "sparc"
    X86 = "x86"
    X86_64 = "x86-64"


class RelationshipType(_PermissiveEnum):
    """Relationship Type Open Vocabulary.

    See https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_e2e1szrqfoan
    """

    RELATED_TO = "related-to"
    BASED_ON = "based-on"
    DERIVED_FROM = "derived-from"
    INDICATES = "indicates"
    TARGETS = "targets"
    LOCATED_AT = "located-at"
    HAS = "has"


class Reliability(_PermissiveEnum):
    """Reliability Open Vocabulary.

    See https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/src/modules/vocabulary/vocabulary-utils.ts#L866
    """

    A = "A - Completely reliable"
    B = "B - Usually reliable"
    C = "C - Fairly reliable"
    D = "D - Not usually reliable"
    E = "E - Unreliable"
    F = "F - Reliability cannot be judged"


class ReportType(_PermissiveEnum):
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


class ThreatActorRole(_PermissiveEnum):
    """Threat Actor Role Open Vocabulary.

    See https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_u6befh8d18r
    """

    AGENT = "agent"
    DIRECTOR = "director"
    INDEPENDENT = "independent"
    INFRASTRUCTURE_ARCHITECT = "infrastructure-architect"
    INFRASTRUCTURE_OPERATOR = "infrastructure-operator"
    MALWARE_AUTHOR = "malware-author"
    SPONSOR = "sponsor"


class ThreatActorSophistication(_PermissiveEnum):
    """Threat Actor Sophistication Open Vocabulary.

    See https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_8jm676xbnggg
    """

    NONE = "none"
    MINIMAL = "minimal"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"
    INNOVATOR = "innovator"
    STRATEGIC = "strategic"


class ThreatActorTypes(_PermissiveEnum):
    """Threat Actor Types Open Vocabulary.

    See https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_tqbl8z36yoir
    """

    ACTIVIST = "activist"
    COMPETITOR = "competitor"
    CRIME_SYNDICATE = "crime-syndicate"
    CRIMINAL = "criminal"
    HACKER = "hacker"
    INSIDER_ACCIDENTAL = "insider-accidental"
    INSIDER_DISGRUNTLED = "insider-disgruntled"
    NATION_STATE = "nation-state"
    SENSATIONALIST = "sensationalist"
    SPY = "spy"
    TERRORIST = "terrorist"
    UNKNOWN = "unknown"


class TLPLevel(StrEnum):
    """TLP Level Enum.

    See https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/src/schema/identifier.js#L76
    """

    CLEAR = "clear"
    WHITE = "white"
    GREEN = "green"
    AMBER = "amber"
    AMBER_STRICT = "amber+strict"
    RED = "red"
