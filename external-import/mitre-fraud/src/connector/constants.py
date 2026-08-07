"""Constants for the MITRE Fight Fraud Framework (F3) connector."""

F3_KILL_CHAIN_NAME = "mitre-f3"

F3_KILL_CHAIN_PHASES = [
    {"name": "reconnaissance", "order": 0},
    {"name": "resource-development", "order": 1},
    {"name": "initial-access", "order": 2},
    {"name": "defense-evasion", "order": 3},
    {"name": "positioning", "order": 4},
    {"name": "execution", "order": 5},
    {"name": "monetization", "order": 6},
]

F3_STIX_BUNDLE_URL = "https://ctid.mitre.org/fraud/f3-stix.json"
