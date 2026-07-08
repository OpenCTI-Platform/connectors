"""Data-source name constants and API path prefixes.

This is a leaf module: it imports nothing from the connector package, so both the
API client and the individual source modules can depend on it without creating an
import cycle (the client must not import the source modules).
"""

BOTNETS = "botnets"
EPSS = "epss"
EXPLOITS = "exploits"
INITIAL_ACCESS = "initial-access"
IPINTEL = "ipintel"
NIST_NVD2 = "nist-nvd2"
RANSOMWARE = "ransomware"
SNORT = "snort"
SURICATA = "suricata"
THREAT_ACTORS = "threat-actors"
VULNCHECK_KEV = "vulncheck-kev"
VULNCHECK_NVD2 = "vulncheck-nvd2"

INDEX_URL_PREFIX = "/index/"
RULES_URL_PREFIX = "/rules/initial-access/"
