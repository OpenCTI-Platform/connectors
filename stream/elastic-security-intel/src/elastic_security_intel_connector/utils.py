"""
Utility functions for the Elastic Security Intel connector
"""


def is_observable(data: dict) -> bool:
    """
    Check if the data is an observable
    :param data: STIX data
    :return: True if observable, False otherwise
    """
    return data.get("type", "").endswith("-addr") or data.get("type", "") in [
        "domain-name",
        "email-addr",
        "email-message",
        "url",
        "user-account",
        "file",
        "directory",
        "network-traffic",
        "process",
        "software",
        "mutex",
        "x509-certificate",
        "autonomous-system",
        "mac-addr",
        "windows-registry-key",
        "hostname",
        "cryptographic-key",
        "cryptocurrency-wallet",
        "text",
        "user-agent",
        "bank-account",
        "phone-number",
        "payment-card",
        "media-content",
    ]


def is_stix_indicator(data: dict) -> bool:
    """
    Check if the data is a STIX indicator
    :param data: STIX data
    :return: True if indicator, False otherwise
    """
    return data.get("type") == "indicator"


# Mapping of hash types from OpenCTI to standard names
FILE_HASH_TYPES_MAPPER = {
    "md5": "MD5",
    "sha-1": "SHA-1",
    "sha1": "SHA-1",
    "sha-256": "SHA-256",
    "sha256": "SHA-256",
    "sha-512": "SHA-512",
    "sha512": "SHA-512",
}
