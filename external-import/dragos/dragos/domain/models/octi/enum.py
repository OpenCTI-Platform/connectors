from enum import StrEnum


class AccountType(StrEnum):
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


class EncryptionAlgorithm(StrEnum):
    """Encryption Algorithm Enum.
    See https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_nfgle8k7nbo4
    """

    AES_256_GCM = "AES-256-GCM"
    ChaCha20_Poly1305 = "ChaCha20-Poly1305"
    MIME_TYPE_INDICATED = "mime-type-indicated"


class HashAlgorithm(StrEnum):
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


class IndicatorType(StrEnum):
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


class OrganizationType(StrEnum):
    """Organization Type Open Vocabulary.
    See https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/src/modules/vocabulary/vocabulary-utils.ts#L770
    """

    VENDOR = "vendor"
    PARTNER = "partner"
    CONSTITUENT = "constituent"
    CSIRT = "csirt"
    OTHER = "other"


class PatternType(StrEnum):
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


class Platform(StrEnum):
    """Platform Open Vocabulary.
    See https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/src/modules/vocabulary/vocabulary-utils.ts#L797
    """

    WINDOWS = "windows"
    MACOS = "macos"
    LINUX = "linux"
    ANDROID = "android"


class Reliability(StrEnum):
    """Reliability Open Vocabulary.
    See https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/src/modules/vocabulary/vocabulary-utils.ts#L866
    """

    A = "A - Completely reliable"
    B = "B - Usually reliable"
    C = "C - Fairly reliable"
    D = "D - Not usually reliable"
    E = "E - Unreliable"
    F = "F - Reliability cannot be judged"


class ReportType(StrEnum):
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

    WHITE = "TLP:WHITE"
    GREEN = "TLP:GREEN"
    AMBER = "TLP:AMBER"
    AMBER_STRICT = "TLP:AMBER+STRICT"
    RED = "TLP:RED"


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
