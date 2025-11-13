import stix2
from pycti import MarkingDefinition

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

TLP_MAP = {
    "white": stix2.TLP_WHITE,
    "green": stix2.TLP_GREEN,
    "amber": stix2.TLP_AMBER,
    "amber+strict": stix2.MarkingDefinition(
        id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
        definition_type="statement",
        definition={"statement": "custom"},
        allow_custom=True,
        x_opencti_definition_type="TLP",
        x_opencti_definition="TLP:AMBER+STRICT",
    ),
    "red": stix2.TLP_RED,
}
