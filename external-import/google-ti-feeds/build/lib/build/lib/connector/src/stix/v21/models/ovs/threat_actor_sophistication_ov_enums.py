"""The module defines the ThreatActorSophisticationOV enum class."""

from connector.src.stix.v21.models.ovs.base_open_vocab import BaseOV


class ThreatActorSophisticationOV(BaseOV):
    """Threat Actor Sophistication Enumeration."""

    NONE = "none"
    MINIMAL = "minimal"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"
    INNOVATOR = "innovator"
    STRATEGIC = "strategic"
