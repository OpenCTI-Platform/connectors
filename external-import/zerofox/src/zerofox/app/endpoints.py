# standard library
from enum import Enum

from zerofox.domain.botnet import Botnet
from zerofox.domain.c2Domains import C2Domain
from zerofox.domain.exploits import Exploit
from zerofox.domain.malware import Malware
from zerofox.domain.phishing import Phishing
from zerofox.domain.ransomware import Ransomware
from zerofox.domain.vulnerabilities import Vulnerability


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

    Botnet = (
        "botnet",
        Botnet,
        "listed_after",
    )
