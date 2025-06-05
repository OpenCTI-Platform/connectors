"""The module contains the AttackResourceLevelOV enum class, which is used to represent different levels of attack resources in the context of threat intelligence."""

from enum import Enum


class AttackResourceLevelOV(str, Enum):
    """Attack Resource Level OV Enum."""

    INDIVIDUAL = "individual"
    CLUB = "club"
    CONTEST = "contest"
    TEAM = "team"
    ORGANIZATION = "organization"
    GOVERNMENT = "government"
