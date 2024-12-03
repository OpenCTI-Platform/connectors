# FIXME: check if these constants are available through pycti

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
