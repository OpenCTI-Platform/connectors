"""The module contains the AttackMotivationOV enum class, which defines various attack motivations."""

from enum import Enum


class AttackMotivationOV(str, Enum):
    """Attack Motivation OV Enum."""

    ACCIDENTAL = "accidental"
    COERCION = "coercion"
    DOMINANCE = "dominance"
    IDEOLOGY = "ideology"
    NOTORIETY = "notoriety"
    ORGANIZATIONAL_GAIN = "organizational-gain"
    PERSONAL_GAIN = "personal-gain"
    PERSONAL_SATISFACTION = "personal-satisfaction"
    REVENGE = "revenge"
    UNPREDICTABLE = "unpredictable"
