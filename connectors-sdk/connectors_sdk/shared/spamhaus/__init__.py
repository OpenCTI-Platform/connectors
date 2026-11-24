"""Spamhaus commercial API support for the abuse.ch connectors."""

from connectors_sdk.shared.spamhaus.client import (
    SPAMHAUS_API_URL,
    SPAMHAUS_REALM,
    SpamhausClient,
    build_user_agent,
)
from connectors_sdk.shared.spamhaus.config import AbuseChAuthConfigMixin
from connectors_sdk.shared.spamhaus.exceptions import (
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
