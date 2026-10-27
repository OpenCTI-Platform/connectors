"""Offer exceptions raised by converters."""

from connectors_sdk.exceptions.error import UseCaseError


class ConversionError(UseCaseError):
    """Raised when a converter cannot convert a valid input.

    It is a ``UseCaseError``: the caller can skip the item and carry on with the
    next one. Always raise it with ``raise ConversionError(...) from err`` so the
    original cause is kept.

    Examples:
        >>> try:
        ...     raise ConversionError("Invalid CVSS vector") from ValueError("bad")
        ... except ConversionError as error:
        ...     isinstance(error.__cause__, ValueError)
        True

    """
