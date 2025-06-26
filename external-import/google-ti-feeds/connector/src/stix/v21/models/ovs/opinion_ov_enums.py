"""The module contains the OpinionOV enum class, which defines the possible opinions for a given statement."""

from connector.src.stix.v21.models.ovs.base_open_vocab import BaseOV


class OpinionOV(BaseOV):
    """Opinion Enumeration."""

    STRONGLY_DISAGREE = "strongly-disagree"
    DISAGREE = "disagree"
    NEUTRAL = "neutral"
    AGREE = "agree"
    STRONGLY_AGREE = "strongly-agree"
