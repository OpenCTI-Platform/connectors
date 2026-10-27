"""Offer CrowdStrike providers.

Requires the ``crowdstrike`` extra (falconpy).
"""

from connectors_sdk.providers.crowdstrike.actor import (
    CrowdStrikeActorDateRangeProvider,
)

__all__ = [
    "CrowdStrikeActorDateRangeProvider",
]
