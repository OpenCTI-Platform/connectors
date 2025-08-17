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


class AccountType(PermissiveEnum):
    """Account Type Open Vocabulary.

    See https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_k2b7lkt45f0i
    """

    FACEBOOK = "facebook"
    LDAP = "ldap"
    NIS = "nis"
    OPENID = "openid"
    RADIUS = "radius"
    SKYPE = "skype"
    TACACS = "tacacs"
    TWITTER = "twitter"
    UNIX = "unix"
    WINDOWS_LOCAL = "windows-local"
    WINDOWS_DOMAIN = "windows-domain"


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

    See https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/src/domain/vulnerability.js#L10
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "Unknown"


class HashAlgorithm(PermissiveEnum):
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


class IdentityClass(PermissiveEnum):
    """Identity Class Open Vocaubulary.

    See https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_be1dktvcmyu
    """

    INDIVIDUAL = "individual"
    GROUP = "group"
    SYSTEM = "system"
    ORGANIZATION = "organization"
    CLASS = "class"
    UNKNOWN = "unknown"


class ImplementationLanguage(PermissiveEnum):
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


class IndicatorType(PermissiveEnum):
    """Indicator Type Open Vocabulary.

    See https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_cvhfwe3t9vuo
    """

    ANOMALOUS_ACTIVITY = "anomalous-activity"
    ANONYMIZATION = "anonymization"
    ATTRIBUTION = "attribution"
    BEGNIN = "benign"
    COMPROMISED = "compromised"
    MALICIOUS_ACTIVITY = "malicious-activity"
    UNKNOWN = "unknown"


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


class MalwareCapability(PermissiveEnum):
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


class MalwareType(PermissiveEnum):
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


class ObservableType(StrEnum):
    """Observable Type Enum.

    See https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/src/schema/stixCyberObservable.ts#L4
    """

    ABSTRACT_STIX_CYBER_OBSERVABLE = "Stix-Cyber-Observable"
    ARTIFACT = "Artifact"
    AUTONOMOUS_SYSTEM = "Autonomous-System"
    BANK_ACCOUNT = "Bank-Account"
    CREDENTIAL = "Credential"
    CRYPTOGRAPHIC_KEY = "Cryptographic-Key"
    CRYPTOGRAPHIC_WALLET = "Cryptocurrency-Wallet"
    DIRECTORY = "Directory"
    DOMAIN_NAME = "Domain-Name"
    EMAIL_ADDR = "Email-Addr"
    EMAIL_MESSAGE = "Email-Message"
    EMAIL_MIME_PART_TYPE = "Email-Mime-Part-Type"
    FILE = "StixFile"
    HOSTNAME = "Hostname"
    IPV4_ADDR = "IPv4-Addr"
    IPV6_ADDR = "IPv6-Addr"
    MAC_ADDR = "Mac-Addr"
    MEDIA_CONTENT = "Media-Content"
    MUTEX = "Mutex"
    NETWORK_TRAFFIC = "Network-Traffic"
    PAYMENT_CARD = "Payment-Card"
    PERSONA = "Persona"
    PHONE_NUMBER = "Phone-Number"
    PROCESS = "Process"
    SOFTWARE = "Software"
    TEXT = "Text"
    TRACKING_NUMBER = "Tracking-Number"
    URL = "Url"
    USER_ACCOUNT = "User-Account"
    USER_AGENT = "User-Agent"
    WINDOWS_REGISTRY_KEY = "Windows-Registry-Key"
    X509_CERTIFICATE = "X509-Certificate"


class OrganizationType(PermissiveEnum):
    """Organization Type Open Vocabulary.

    See https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/src/modules/vocabulary/vocabulary-utils.ts#L770
    """

    VENDOR = "vendor"
    PARTNER = "partner"
    CONSTITUENT = "constituent"
    CSIRT = "csirt"
    OTHER = "other"


class PatternType(PermissiveEnum):
    """Pattern Type Open Vocabulary.

    See https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_9lfdvxnyofxw
    """

    STIX = "stix"
    EQL = "eql"
    PCRE = "pcre"
    SHODAN = "shodan"
    SIGMA = "sigma"
    SNORT = "snort"
    SPL = "spl"
    SURICATA = "suricata"
    TANIUM_SIGNAL = "tanium-signal"
    YARA = "yara"


class Platform(PermissiveEnum):
    """Platform Open Vocabulary.

    See https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/src/modules/vocabulary/vocabulary-utils.ts#L797
    """

    WINDOWS = "windows"
    MACOS = "macos"
    LINUX = "linux"
    ANDROID = "android"


class ProcessorArchitecture(PermissiveEnum):
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


class Region(PermissiveEnum):
    """Region Open Vocabulary.

    See https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_i1sw27qw1v0s
    """

    AFRICA = "africa"
    EASTERN_AFRICA = "eastern-africa"
    MIDDLE_AFRICA = "middle-africa"
    NORTHERN_AFRICA = "northern-africa"
    SOUTHERN_AFRICA = "southern-africa"
    WESTERN_AFRICA = "western-africa"

    AMERICAS = "americas"
    CARIBBEAN = "caribbean"
    CENTRAL_AMERICA = "central-america"
    LATIN_AMERICA_CARIBBEAN = "latin-america-caribbean"
    NORTHERN_AMERICA = "northern-america"
    SOUTH_AMERICA = "south-america"

    ASIA = "asia"
    CENTRAL_ASIA = "central-asia"
    EASTERN_ASIA = "eastern-asia"
    SOUTHERN_ASIA = "southern-asia"
    SOUTH_EASTERN_ASIA = "south-eastern-asia"
    WESTERN_ASIA = "western-asia"

    EUROPE = "europe"
    EASTERN_EUROPE = "eastern-europe"
    NORTHERN_EUROPE = "northern-europe"
    SOUTHERN_EUROPE = "southern-europe"
    WESTERN_EUROPE = "western-europe"

    OCEANIA = "oceania"
    ANTARTICA = "antarctica"
    AUSTRALIA_NEW_ZEALAND = "australia-new-zealand"
    MELANESIA = "melanesia"
    MICRONESIA = "micronesia"
    POLYNESIA = "polynesia"


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


class TLPLevel(StrEnum):
    """TLP Level Enum.

    See https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/src/schema/identifier.js#L76
    """

    WHITE = "white"
    GREEN = "green"
    AMBER = "amber"
    AMBER_STRICT = "amber+strict"
    RED = "red"


class WindowsIntegrityLevel(StrEnum):
    """Windows Integrity Level Enum.

    See https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_n8wq1912g4ts
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    SYSTEM = "system"


class WindowsRegistryDatatype(StrEnum):
    """Windows Registry Datatype Enum.

    See https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_emk4vrhg6ccn
    """

    REG_NONE = "REG_NONE"
    REG_SZ = "REG_SZ"
    REG_EXPAND_SZ = "REG_EXPAND_SZ"
    REG_BINARY = "REG_BINARY"
    REG_DWORD = "REG_DWORD"
    REG_DWORD_BIG_ENDIAN = "REG_DWORD_BIG_ENDIAN"
    REG_DWORD_LITTLE_ENDIAN = "REG_DWORD_LITTLE_ENDIAN"
    REG_LINK = "REG_LINK"
    REG_MULTI_SZ = "REG_MULTI_SZ"
    REG_RESOURCE_LIST = "REG_RESOURCE_LIST"
    REG_FULL_RESOURCE_DESCRIPTION = "REG_FULL_RESOURCE_DESCRIPTION"
    REG_RESOURCE_REQUIREMENTS_LIST = "REG_RESOURCE_REQUIREMENTS_LIST"
    REG_QWORD = "REG_QWORD"
    REG_INVALID_TYPE = "REG_INVALID_TYPE"


class WindowsServiceStartType(StrEnum):
    """Windows Service Start Type Enum.

    See https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_91c2s0q9p4f3
    """

    SERVICE_AUTO_START = "SERVICE_AUTO_START"
    SERVICE_BOOT_START = "SERVICE_BOOT_START"
    SERVICE_DEMAND_START = "SERVICE_DEMAND_START"
    SERVICE_DISABLED = "SERVICE_DISABLED"
    SERVICE_SYSTEM_ALERT = "SERVICE_SYSTEM_ALERT"


class WindowsServiceStatus(StrEnum):
    """Windows Service Status Enum.

    See https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_t6oit3qe17hs
    """

    SERVICE_CONTINUE_PENDING = "SERVICE_CONTINUE_PENDING"
    SERVICE_PAUSE_PENDING = "SERVICE_PAUSE_PENDING"
    SERVICE_PAUSED = "SERVICE_PAUSED"
    SERVICE_RUNNING = "SERVICE_RUNNING"
    SERVICE_START_PENDING = "SERVICE_START_PENDING"
    SERVICE_STOP_PENDING = "SERVICE_STOP_PENDING"
    SERVICE_STOPPED = "SERVICE_STOPPED"


class WindowsServiceType(StrEnum):
    """Windows Service Type Enum.

    See https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_e8mzqdysuuve
    """

    SERVICE_KERNEL_DRIVER = "SERVICE_KERNEL_DRIVER"
    SERVICE_FILE_SYSTEM_DRIVER = "SERVICE_FILE_SYSTEM_DRIVER"
    SERVICE_WIN32_OWN_PROCESS = "SERVICE_WIN32_OWN_PROCESS"
    SERVICE_WIN32_SHARE_PROCESS = "SERVICE_WIN32_SHARE_PROCESS"
