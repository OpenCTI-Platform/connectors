"""Offer WhoisFreaks converters."""

from connectors_sdk.converters.whoisfreaks.models import WhoisFreaksThreatFeedRecord
from connectors_sdk.converters.whoisfreaks.threat_feed import (
    WhoisFreaksThreatFeedConverter,
)

__all__ = [
    "WhoisFreaksThreatFeedConverter",
    "WhoisFreaksThreatFeedRecord",
]
