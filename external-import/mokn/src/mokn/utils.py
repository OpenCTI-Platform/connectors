"""Utility functions for MokN Connector."""

from enum import IntEnum


class LoginAttemptStatus(IntEnum):
    """Enumeration for login attempt status codes."""

    INVALID = 0
    VALID = 1
    COULD_LOCK = 2
    LOCKED_ACCOUNT = 8
