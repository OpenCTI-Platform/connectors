"""OpenCTI CrowdStrike utilities constants module."""

from typing import TypeVar

import stix2
from pycti import MarkingDefinition

T = TypeVar("T")


TLP_MARKING_DEFINITION_MAPPING = {
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

DEFAULT_TLP_MARKING_DEFINITION = stix2.MarkingDefinition(
    id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
    definition_type="statement",
    definition={"statement": "custom"},
    allow_custom=True,
    x_opencti_definition_type="TLP",
    x_opencti_definition="TLP:AMBER+STRICT",
)


X_OPENCTI_LOCATION_TYPE = "x_opencti_location_type"
X_OPENCTI_ALIASES = "x_opencti_aliases"
X_OPENCTI_REPORT_STATUS = "x_opencti_report_status"
X_OPENCTI_FILES = "x_opencti_files"
X_OPENCTI_SCORE = "x_opencti_score"
X_OPENCTI_LABELS = "x_opencti_labels"
X_OPENCTI_CREATED_BY_REF = "x_opencti_created_by_ref"
X_OPENCTI_MAIN_OBSERVABLE_TYPE = "x_opencti_main_observable_type"

DEFAULT_X_OPENCTI_SCORE = 50

CS_KILL_CHAIN_TO_LOCKHEED_MARTIN_CYBER_KILL_CHAIN = {
    "Reconnaissance": "reconnaissance",
    "Weaponization": "weaponization",
    "Delivery": "delivery",
    "Exploitation": "exploitation",
    "Installation": "installation",
    "C2": "command-and-control",
    "ActionOnObjectives": "action-on-objectives",
}

CS_CAPABILITY_TO_MALWARE_TYPE = {
    "adware": "adware",
    "antiforensics": "anti-forensics",
    "atmmalware": "atm-malware",
    "backdoor": "backdoor",
    "bankingstealer": "banking-stealer",
    "botnet": "botnet",
    "clickfraud": "click-fraud",
    "cryptocurrencytheft": "cryptocurrency-theft",
    "credentialharvesting": "credential-harvesting",
    "denialofservice": "denial-of-service",
    "deploymentframework": "deployment-framework",
    "disabledefensivetooling": "disable-defensive-tooling",
    "downloader": "downloader",
    "dropper": "dropper",
    "exploit": "exploit",
    "exploitkit": "exploit-kit",
    "fileinfector": "file-infector",
    "formjacking": "form-jacking",
    "informationstealer": "information-stealer",
    "keylogger": "keylogger",
    "loader": "loader",
    "mineware": "mineware",
    "minewarewebbrowserbased": "mineware-web-browser-based",
    "mobilemalware": "mobile-malware",
    "networkscanner": "network-scanner",
    "pointofsale": "point-of-sale",
    "potentiallyunwantedprogram": "potentially-unwanted-program",
    "proxy": "proxy",
    "ransomware": "ransomware",
    "rat": "remote-access-trojan",
    "rootkit": "rootkit",
    "sabotageoperationaltechnology": "sabotage-operational-technology",
    "spambot": "spambot",
    "webshell": "webshell",
    "worm": "worm",
    "wiper": "wiper",
}
