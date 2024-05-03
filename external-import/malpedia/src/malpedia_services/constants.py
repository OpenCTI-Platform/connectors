import stix2
from stix2 import MarkingDefinition

LAST_RUN: str = "last_run"
LAST_VERSION: str = "last_version"

URLS_MAPPING: dict[str, str] = {
    "default_api_url": "https://malpedia.caad.fkie.fraunhofer.de/api/",
    "base_url_actor": "https://malpedia.caad.fkie.fraunhofer.de/actor/",
}

TLP_MAPPING: dict[str, MarkingDefinition] = {
    "tlp_white": stix2.TLP_WHITE,
    "tlp_green": stix2.TLP_GREEN,
    "tlp_amber": stix2.TLP_AMBER,
    "tlp_red": stix2.TLP_RED,
}
