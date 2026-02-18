import pycti
import stix2
from stix2 import TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE

BASE_URL = "https://transform.shadowserver.org/api2/"
DOWNLOAD_URL = "https://dl.shadowserver.org/"
TIMEOUT = 500

REQUEST_DATE_FORMAT = "%Y-%m-%d"

LIMIT = 1000

# Max report download size (bytes) to avoid unbounded memory use and reduce
# exposure to native-code issues (e.g. SSL/HTTP stack) on very large responses.
CHUNK_SIZE = 65536
MAX_REPORT_SIZE = 500 * 1024 * 1024  # 500 MiB

TLP_MAP = {
    "TLP:CLEAR": TLP_WHITE,
    "TLP:WHITE": TLP_WHITE,
    "TLP:GREEN": TLP_GREEN,
    "TLP:AMBER": TLP_AMBER,
    "TLP:AMBER+STRICT": stix2.MarkingDefinition(
        id=pycti.MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
        definition_type="statement",
        definition={"statement": "custom"},
        custom_properties={
            "x_opencti_definition_type": "TLP",
            "x_opencti_definition": "TLP:AMBER+STRICT",
        },
    ),
    "TLP:RED": TLP_RED,
}

SEVERITY_MAP = {"info": 4, "low": 3, "medium": 2, "high": 1, "critical": 0}
