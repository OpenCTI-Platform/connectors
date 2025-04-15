import stix2
from stix2 import MarkingDefinition

LAST_RUN: str = "last_run"
LAST_VERSION: str = "last_version"

URLS_MAPPING: dict[str, str] = {
    "default_api_url": "https://malpedia.caad.fkie.fraunhofer.de/api/",
    "base_url_actor": "https://malpedia.caad.fkie.fraunhofer.de/actor/",
}

TLP_MAPPING: dict[str, MarkingDefinition] = {
    "TLP:CLEAR": stix2.TLP_WHITE,
    "TLP:WHITE": stix2.TLP_WHITE,
    "TLP:GREEN": stix2.TLP_GREEN,
    "TLP:AMBER": stix2.TLP_AMBER,
    "TLP:RED": stix2.TLP_RED,
    "tlp_white": stix2.TLP_WHITE,
    "tlp_green": stix2.TLP_GREEN,
    "tlp_amber": stix2.TLP_AMBER,
    "tlp_red": stix2.TLP_RED,
}
