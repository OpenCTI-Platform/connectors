# standard library
from enum import Enum

from zerofox.domain import (
    Botnet,
    C2Domain,
    Exploit,
    Malware,
    Phishing,
    Ransomware,
    Vulnerability,
)


class CTIEndpoint(Enum):
    """Enum class containing endpoint suffixes for CTI feeds."""

    def __new__(cls, value, factory, after_key="created_after"):
        obj = object.__new__(cls)
        obj._value_ = value
        obj.factory = factory
        obj.after_key = after_key
        return obj

    def __str__(self):
        return self.value

    Botnet = (
        "botnet",
        Botnet,
        "listed_after",
    )
    C2Domains = (
        "c2-domains",
        C2Domain,
    )
    Exploits = (
        "exploits",
        Exploit,
    )
    Malware = (
        "malware",
        Malware,
    )
    Phishing = (
        "phishing",
        Phishing,
        "scanned_after",
    )
    Ransomware = (
        "ransomware",
        Ransomware,
    )
    Vulnerabilities = (
        "vulnerabilities",
        Vulnerability,
    )
