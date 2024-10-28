# standard library
from enum import Enum

from zerofox.domain.botnet import FoxBotnet
from zerofox.domain.c2Domains import C2Domain
from zerofox.domain.exploits import Exploit
from zerofox.domain.malware import FoxMalware
from zerofox.domain.phishing import FoxPhishing
from zerofox.domain.ransomware import FoxRansomware
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
        FoxMalware,
    )
    Phishing = (
        "phishing",
        FoxPhishing,
        "scanned_after",
    )
    Ransomware = (
        "ransomware",
        FoxRansomware,
    )
    Vulnerabilities = (
        "vulnerabilities",
        Vulnerability,
    )

    Botnet = (
        "botnet",
        FoxBotnet,
        "listed_after",
    )
