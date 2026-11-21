"""Spamhaus commercial API support for the abuse.ch connectors."""

__version__ = "0.1.0"

from spamhaus_client.client import (
    SPAMHAUS_API_URL,
    SPAMHAUS_REALM,
    SpamhausClient,
    build_user_agent,
)
from spamhaus_client.config import AbuseChAuthConfigMixin
from spamhaus_client.exceptions import (
    SpamhausAuthenticationError,
    SpamhausCommercialError,
    SpamhausInvalidResponseError,
    SpamhausUnavailableError,
)

__all__ = [
    "SPAMHAUS_API_URL",
    "SPAMHAUS_REALM",
    "AbuseChAuthConfigMixin",
    "SpamhausAuthenticationError",
    "SpamhausClient",
    "SpamhausCommercialError",
    "SpamhausInvalidResponseError",
    "SpamhausUnavailableError",
    "build_user_agent",
]
