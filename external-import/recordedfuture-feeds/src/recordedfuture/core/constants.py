# recordedfuture/core/constants.py
from .transformer import (
    DomainSTIXTransformer,
    URLSTIXTransformer,
    C2STIXTransformer,
    VulnerabilitySTIXTransformer,
    HashSTIXTransformer,
    TorIPSTIXTransformer,
    EmergingMalwareSTIXTransformer,
    RATSTIXTransformer,
    IPSTIXTransformer,
    LowHashSTIXTransformer,
)

# Base endpoint for the Recorded Future API
RECORDED_FUTURE_API_ENDPOINT = "https://api.recordedfuture.com/v2/fusion/files"

# Default header for API requests
DEFAULT_HEADER = {
    "x-rftoken": "[API token]"  # replace [API token] with the appropriate method of fetching the token
}

# Endpoints (paths) for different threat datasets in Recorded Future
DATASET = {
    "DOMAINS_PREVENT": {
        "path": "/public/prevent/weaponized_domains.json",
        "transformer": DomainSTIXTransformer(),
        "labels": "prevent",
    },
    "DOMAINS_DETECT": {
        "path": "/public/detect/weaponized_domains.json",
        "transformer": DomainSTIXTransformer(),
        "labels": "detect",
    },
    "URLS_PREVENT": {
        "path": "/public/prevent/weaponized_urls.json",
        "transformer": URLSTIXTransformer(),
        "labels": "prevent",
    },
    "C2_IPS_DETECT": {
        "path": "/public/detect/c2_scanned_ips.json",
        "transformer": C2STIXTransformer(),
        "labels": "detect",
    },
    "C2_IPS_PREVENT": {
        "path": "/public/prevent/c2_communicating_ips.json",
        "transformer": C2STIXTransformer(),
        "labels": "prevent",
    },
    "VULNS_PATCH": {
        "path": "/public/patch/exploits_itw_vulns.json",
        "transformer": VulnerabilitySTIXTransformer(),
        "labels": "patch",
    },
    "HASHES_PREVENT": {
        "path": "/public/prevent/exploits_itw_hashes.json",
        "transformer": HashSTIXTransformer(),
        "labels": "prevent",
    },
    "TOR_IPS": {
        "path": "/public/policy/tor_ips.json",
        "transformer": TorIPSTIXTransformer(),
        "labels": "tor",
    },
    "EMERGING_MALWARE_HASHES": {
        "path": "/public/prevent/emerging_malware_hashes.json",
        "transformer": EmergingMalwareSTIXTransformer(),
        "labels": "prevent,malware",
    },
    "RAT_CONTROLLERS_IPS": {
        "path": "/public/detect/ratcontrollers_ips.json",
        "transformer": RATSTIXTransformer(),
        "labels": "detect,rat",
    },
    "FFLUX_IPS": {
        "path": "/public/detect/fflux_ips.json",
        "transformer": IPSTIXTransformer(),
        "labels": "detect,fflux",
    },
    "DDNS_IPS": {
        "path": "/public/detect/ddns_ips.json",
        "transformer": IPSTIXTransformer(),
        "labels": "detect,ddns",
    },
    "LOW_DETECT_MALWARE_HASHES": {
        "path": "/public/detect/low_detect_malware_hashes.json",
        "transformer": LowHashSTIXTransformer(),
        "labels": "detect,malware",
    },
}