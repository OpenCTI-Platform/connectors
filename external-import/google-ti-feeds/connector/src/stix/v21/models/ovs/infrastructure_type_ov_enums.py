"""The module contains the InfrastructureTypeOV enum class."""

from enum import Enum


class InfrastructureTypeOV(str, Enum):
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
