STATEMENT_MARKINGS = [
    "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168",
    "marking-definition--17d82bb2-eeeb-4898-bda5-3ddbcd2b799d",
]

# v18 and earlier Enterprise mapping. Kept as a first-class constant
# (rather than collapsed into ``ENTERPRISE_ATTACK_KILL_CHAIN_PHASES``)
# so an operator who pins ``MITRE_ENTERPRISE_FILE_URL`` to a pre-v19
# release still gets the correct ``x_opencti_order`` for the legacy
# ``defense-evasion`` tactic. The MITRE ATT&CK v19 release (April
# 2026) split this tactic into ``stealth`` and ``defense-impairment``
# (see :data:`ENTERPRISE_ATTACK_KILL_CHAIN_PHASES_V19` below) — older
# bundles do NOT carry either of those names, so without this
# variant ``enrich_kill_chain_phases`` would default the order to 0
# in the UI for every Defense Evasion attack-pattern across older
# bundles.
ENTERPRISE_ATTACK_KILL_CHAIN_PHASES_V18 = [
    {"name": "reconnaissance", "order": 0},
    {"name": "resource-development", "order": 1},
    {"name": "initial-access", "order": 2},
    {"name": "execution", "order": 3},
    {"name": "persistence", "order": 4},
    {"name": "privilege-escalation", "order": 5},
    {"name": "defense-evasion", "order": 6},
    {"name": "credential-access", "order": 7},
    {"name": "discovery", "order": 8},
    {"name": "lateral-movement", "order": 9},
    {"name": "collection", "order": 10},
    {"name": "command-and-control", "order": 11},
    {"name": "exfiltration", "order": 12},
    {"name": "impact", "order": 13},
]

# v19+ Enterprise mapping. The April 2026 ATT&CK v19 release split the
# legacy ``defense-evasion`` tactic into ``stealth`` (techniques where
# adversaries hide malicious activity within legitimate behaviour) and
# ``defense-impairment`` (techniques where adversaries actively
# disable / degrade / compromise security controls), and shifted every
# subsequent tactic's order up by one. ``stealth`` inherits the
# original ``TA0005`` id while ``defense-impairment`` is a new
# ``TA0112``.
ENTERPRISE_ATTACK_KILL_CHAIN_PHASES_V19 = [
    {"name": "reconnaissance", "order": 0},
    {"name": "resource-development", "order": 1},
    {"name": "initial-access", "order": 2},
    {"name": "execution", "order": 3},
    {"name": "persistence", "order": 4},
    {"name": "privilege-escalation", "order": 5},
    {"name": "stealth", "order": 6},
    {"name": "defense-impairment", "order": 7},
    {"name": "credential-access", "order": 8},
    {"name": "discovery", "order": 9},
    {"name": "lateral-movement", "order": 10},
    {"name": "collection", "order": 11},
    {"name": "command-and-control", "order": 12},
    {"name": "exfiltration", "order": 13},
    {"name": "impact", "order": 14},
]

# Default Enterprise mapping used when the bundle does not advertise
# an ``x-mitre-collection`` version (synthetic bundles, partial test
# fixtures, etc.). Default to the v19 shape because that is what the
# canonical ``enterprise-attack/enterprise-attack.json`` from MITRE's
# CTI repo currently ships; the version-aware selector in
# ``__main__.py::_build_kill_chain_order_mapping`` swaps to the v18
# variant when the bundle's ``x-mitre-collection`` major version is
# ``< 19``.
ENTERPRISE_ATTACK_KILL_CHAIN_PHASES = ENTERPRISE_ATTACK_KILL_CHAIN_PHASES_V19

MOBILE_ATTACK_KILL_CHAIN_PHASES = [
    {"name": "initial-access", "order": 0},
    {"name": "execution", "order": 1},
    {"name": "persistence", "order": 2},
    {"name": "privilege-escalation", "order": 3},
    {"name": "defense-evasion", "order": 4},
    {"name": "credential-access", "order": 5},
    {"name": "discovery", "order": 6},
    {"name": "lateral-movement", "order": 7},
    {"name": "collection", "order": 8},
    {"name": "command-and-control", "order": 9},
    {"name": "exfiltration", "order": 10},
    {"name": "impact", "order": 11},
]

ICS_ATTACK_KILL_CHAIN_PHASES = [
    {"name": "initial-access", "order": 0},
    {"name": "execution", "order": 1},
    {"name": "persistence", "order": 2},
    {"name": "privilege-escalation", "order": 3},
    {"name": "evasion", "order": 4},
    {"name": "discovery", "order": 5},
    {"name": "lateral-movement", "order": 6},
    {"name": "collection", "order": 7},
    {"name": "command-and-control", "order": 8},
    {"name": "inhibit-response-function", "order": 9},
    {"name": "impair-process-control", "order": 10},
    {"name": "impact", "order": 11},
]
