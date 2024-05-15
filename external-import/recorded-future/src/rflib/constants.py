from .rf_to_stix2 import URL, Domain, FileHash, IntrusionSet, IPAddress, Malware

RISK_LIST_TYPE_MAPPER = {
    "IpAddress": {"class": IPAddress, "path": "/public/opencti/default_ip.csv"},
    "InternetDomainName": {
        "class": Domain,
        "path": "/public/opencti/default_domain.csv",
    },
    "URL": {"class": URL, "path": "/public/opencti/default_url.csv"},
    "Hash": {"class": FileHash, "path": "/public/opencti/default_hash.csv"},
}

THREAT_MAP_TYPE_MAPPER = {
    "actors": {"class": IntrusionSet},
    "malware": {"class": Malware},
}

RISK_RULES_MAPPER = [
    {"rule_score": 0, "severity": "No current evidence of risk", "risk_score": "0"},
    {"rule_score": 1, "severity": "Unusual", "risk_score": "5-24"},
    {"rule_score": 2, "severity": "Suspicious", "risk_score": "25-64"},
    {"rule_score": 3, "severity": "Malicious", "risk_score": "65-89"},
    {"rule_score": 4, "severity": "Very Malicious", "risk_score": "90-99"},
]
