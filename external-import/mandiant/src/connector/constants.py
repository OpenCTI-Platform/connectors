# FIXME: check if these constants are available through pycti
import stix2
from pycti import MarkingDefinition

MOTIVATION_ORGANIZATIONAL_GAIN = "organizational-gain"
MOTIVATION_PERSONAL_GAIN = "personal-gain"
MOTIVATION_COERCION = "coercion"
MOTIVATION_IDEOLOGY = "ideology"
MOTIVATION_ACCIDENTAL = "personal-gain"
MOTIVATION_DOMINANCE = "dominance"
MOTIVATION_NOTORIETY = "notoriety"
MOTIVATION_PERSONAL_SATISFACTION = "personal-satisfaction"
MOTIVATION_REVENGE = "revenge"
MOTIVATION_UNPREDICTABLE = "unpredictable"

MAPPING = {
    "Military Advantage": MOTIVATION_ORGANIZATIONAL_GAIN,
    "Political Advantage": MOTIVATION_ORGANIZATIONAL_GAIN,
    "Financial Theft": MOTIVATION_ORGANIZATIONAL_GAIN,
    "Disruption": MOTIVATION_ORGANIZATIONAL_GAIN,
}

STATE_START = "start_epoch"
STATE_OFFSET = "offset"
STATE_END = "end_epoch"
STATE_LAST_RUN = "last_run"

STATEMENT_MARKINGS = [
    "marking-definition--ad2caa47-58fd-5491-8f67-255377927369",
]
BATCH_REPORT_SIZE = 10

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
