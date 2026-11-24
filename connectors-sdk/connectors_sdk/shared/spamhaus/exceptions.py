"""Errors of the Spamhaus commercial API (abuse.ch data behind a JWT)."""

from __future__ import annotations

from connectors_sdk import (
    ProviderApiAuthenticationError,
    ProviderApiError,
    ProviderApiInvalidResponseError,
    ProviderApiServerError,
)


class SpamhausCommercialError(ProviderApiError):
    """Abstract base: the Spamhaus commercial mode cannot be used.

    A connector that also holds a community Auth-Key catches this error to fall
    back to the community API. Messages never hold the password, the JWT or the
    login response.
    """

    __abstract__ = True


class SpamhausAuthenticationError(
    ProviderApiAuthenticationError, SpamhausCommercialError
):
    """Spamhaus rejects the credentials (login refused, or 401/403 after a re-login)."""


class SpamhausUnavailableError(ProviderApiServerError, SpamhausCommercialError):
    """The Spamhaus API cannot answer (network, timeout, rate limit, 5xx, bad payload)."""


class SpamhausInvalidResponseError(
    ProviderApiInvalidResponseError, SpamhausCommercialError
):
    """The Spamhaus API sent a page that cannot be used (shape, cursor)."""
