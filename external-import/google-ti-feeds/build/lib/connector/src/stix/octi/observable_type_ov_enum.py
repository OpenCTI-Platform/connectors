"""The module contains the ObservableTypeOV enum class for OpenCTI observable types."""

from enum import Enum


class ObservableTypeOV(str, Enum):
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
