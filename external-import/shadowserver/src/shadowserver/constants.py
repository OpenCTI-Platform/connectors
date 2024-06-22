from stix2 import TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE, Identity, MarkingDefinition

BASE_URL = "https://transform.shadowserver.org/api2/"
TIMEOUT = 500

REQUEST_DATE_FORMAT = "%Y-%m-%d"

LIMIT = 1000

TLP_MAP = {
    "TLP:CLEAR": TLP_WHITE,
    "TLP:WHITE": TLP_WHITE,
    "TLP:GREEN": TLP_GREEN,
    "TLP:AMBER": TLP_AMBER,
    "TLP:RED": TLP_RED,
}
