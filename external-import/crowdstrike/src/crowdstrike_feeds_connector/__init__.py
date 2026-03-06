"""OpenCTI CrowdStrike connector module."""

from crowdstrike_feeds_connector.connector import CrowdStrike
from crowdstrike_feeds_connector.settings import ConnectorSettings

__all__ = [
    "ConnectorSettings",
    "CrowdStrike",
]
