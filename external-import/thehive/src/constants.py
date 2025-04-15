import stix2
from pycti import MarkingDefinition

DEFAULT_DATETIME = "%Y-%m-%d %H:%M:%S"
DEFAULT_UTC_DATETIME = "%Y-%m-%dT%H:%M:%SZ"

# Align to Traffic light protocol
# https://www.cisa.gov/news-events/news/traffic-light-protocol-tlp-definitions-and-usage
# https://www.first.org/tlp/
TLP_MAPPINGS = {
    0: stix2.TLP_WHITE,
    1: stix2.TLP_GREEN,
    2: stix2.TLP_AMBER,
    3: stix2.TLP_RED,
    4: stix2.MarkingDefinition(
        id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
        definition_type="statement",
        definition={"statement": "custom"},
        allow_custom=True,
        x_opencti_definition_type="TLP",
        x_opencti_definition="TLP:AMBER+STRICT",
        x_opencti_color="#FFC000",
    ),
}

PAP_MAPPINGS = {
    0: stix2.MarkingDefinition(
        id=MarkingDefinition.generate_id("PAP", "PAP:WHITE"),
        definition_type="statement",
        definition={"statement": "custom"},
        allow_custom=True,
        x_opencti_definition_type="PAP",
        x_opencti_definition="PAP:WHITE",
        x_opencti_color="#ffffff",
    ),
    1: stix2.MarkingDefinition(
        id=MarkingDefinition.generate_id("PAP", "PAP:GREEN"),
        definition_type="statement",
        definition={"statement": "custom"},
        allow_custom=True,
        x_opencti_definition_type="PAP",
        x_opencti_definition="PAP:GREEN",
        x_opencti_color="#33FF00",
    ),
    2: stix2.MarkingDefinition(
        id=MarkingDefinition.generate_id("PAP", "PAP:AMBER"),
        definition_type="statement",
        definition={"statement": "custom"},
        allow_custom=True,
        x_opencti_definition_type="PAP",
        x_opencti_definition="PAP:AMBER",
        x_opencti_color="#FFC000",
    ),
    3: stix2.MarkingDefinition(
        id=MarkingDefinition.generate_id("PAP", "PAP:RED"),
        definition_type="statement",
        definition={"statement": "custom"},
        allow_custom=True,
        x_opencti_definition_type="PAP",
        x_opencti_definition="PAP:RED",
        x_opencti_color="#FF2B2B",
    ),
}
