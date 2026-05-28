from dateutil.parser import parse
from stix2 import TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE

EPOCH_DATETIME = parse("1970-01-01T00:00:00Z")

FILE_INDICATOR_TYPES = ["filename", "filepath", "hash"]

IP_INDICATOR_TYPES = ["ip_src", "ip_dst", "ip_both"]

INCIDENT_PRIORITIES_BY_LEVEL = {
    "critical": "P1",
    "high": "P2",
    "medium": "P3",
    "low": "P4",
}

MARKING_DEFINITIONS_BY_NAME = {
    "TLP:CLEAR": TLP_WHITE,
    "TLP:GREEN": TLP_GREEN,
    "TLP:AMBER": TLP_AMBER,
    "TLP:RED": TLP_RED,
}
