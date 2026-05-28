"""The module contains the InfrastructureTypeOV enum class."""

from connector.src.stix.v21.models.ovs.base_open_vocab import BaseOV


class InfrastructureTypeOV(BaseOV):
    """Infrastructure Type Enumeration."""

    AMPLIFICATION = "amplification"
    ANONYMIZATION = "anonymization"
    BOTNET = "botnet"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    HOSTING_MALWARE = "hosting-malware"
    HOSTING_TARGET_LISTS = "hosting-target-lists"
    PHISHING = "phishing"
    RECONNAISSANCE = "reconnaissance"
    STAGING = "staging"
    UNDEFINED = "undefined"
