"""The module contains the Threat Actor Role OV Enums."""

from enum import Enum


class ThreatActorRoleOV(str, Enum):
    """Threat Actor Role Enumeration."""

    AGENT = "agent"
    DIRECTOR = "director"
    INDEPENDENT = "independent"
    INFRASTRUCTURE_ARCHITECT = "infrastructure-architect"
    INFRASTRUCTURE_OPERATOR = "infrastructure-operator"
    MALWARE_AUTHOR = "malware-author"
    SPONSOR = "sponsor"
