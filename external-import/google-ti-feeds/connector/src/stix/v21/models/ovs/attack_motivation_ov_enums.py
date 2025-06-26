"""The module contains the AttackMotivationOV enum class, which defines various attack motivations."""

from connector.src.stix.v21.models.ovs.base_open_vocab import BaseOV


class AttackMotivationOV(BaseOV):
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
