"""The module contains the ThreatActorTypeOV enum class."""

from connector.src.stix.v21.models.ovs.base_open_vocab import BaseOV


class ThreatActorTypeOV(BaseOV):
    """Threat Actor Type Enumeration."""

    ACTIVIST = "activist"
    COMPETITOR = "competitor"
    CRIME_SYNDICATE = "crime-syndicate"
    CRIMINAL = "criminal"
    HACKER = "hacker"
    INSIDER_ACCIDENTAL = "insider-accidental"
    INSIDER_DISGRUNTLED = "insider-disgruntled"
    NATION_STATE = "nation-state"
    SENSATIONALIST = "sensationalist"
    SPY = "spy"
    TERRORIST = "terrorist"
    UNKNOWN = "unknown"
