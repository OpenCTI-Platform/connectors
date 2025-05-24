"""The module contains the OpinionOV enum class, which defines the possible opinions for a given statement."""

from enum import Enum


class OpinionOV(str, Enum):
    """Opinion Enumeration."""

    STRONGLY_DISAGREE = "strongly-disagree"
    DISAGREE = "disagree"
    NEUTRAL = "neutral"
    AGREE = "agree"
    STRONGLY_AGREE = "strongly-agree"
