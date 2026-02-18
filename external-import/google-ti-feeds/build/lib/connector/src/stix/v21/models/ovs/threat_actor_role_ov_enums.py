"""The module contains the Threat Actor Role OV Enums."""

from connector.src.stix.v21.models.ovs.base_open_vocab import BaseOV


class ThreatActorRoleOV(BaseOV):
    """Threat Actor Role Enumeration."""

    AGENT = "agent"
    DIRECTOR = "director"
    INDEPENDENT = "independent"
    INFRASTRUCTURE_ARCHITECT = "infrastructure-architect"
    INFRASTRUCTURE_OPERATOR = "infrastructure-operator"
    MALWARE_AUTHOR = "malware-author"
    SPONSOR = "sponsor"
