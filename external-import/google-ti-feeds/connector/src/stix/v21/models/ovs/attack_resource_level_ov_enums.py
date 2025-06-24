"""The module contains the AttackResourceLevelOV enum class, which is used to represent different levels of attack resources in the context of threat intelligence."""

from connector.src.stix.v21.models.ovs.base_open_vocab import BaseOV


class AttackResourceLevelOV(BaseOV):
    """Attack Resource Level OV Enum."""

    INDIVIDUAL = "individual"
    CLUB = "club"
    CONTEST = "contest"
    TEAM = "team"
    ORGANIZATION = "organization"
    GOVERNMENT = "government"
