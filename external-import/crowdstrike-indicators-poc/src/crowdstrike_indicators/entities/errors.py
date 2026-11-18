"""Errors raised while extracting from CrowdStrike."""

from typing import Any


class CrowdStrikeAPIError(Exception):
    """The CrowdStrike API answered with an error status."""

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(status_code, message)
        self.status_code = status_code
        self.message = message

    def __str__(self) -> str:
        return f"CrowdStrike API error {self.status_code}: {self.message}"


class IndicatorValidationError(Exception):
    """An indicator returned by the API does not match the model.

    ``errors`` is the JSON-safe list of Pydantic validation errors, and
    ``raw`` the indicator exactly as the API returned it.
    """

    def __init__(
        self,
        indicator_id: str | None,
        errors: list[dict[str, Any]],
        raw: Any,
    ) -> None:
        super().__init__(indicator_id, errors, raw)
        self.indicator_id = indicator_id
        self.errors = errors
        self.raw = raw

    def __str__(self) -> str:
        details = "; ".join(
            f"{'.'.join(str(part) for part in error.get('loc', ())) or '<root>'}: "
            f"{error.get('msg', 'invalid')}"
            for error in self.errors
        )
        return (
            f"Indicator {self.indicator_id or '<no id>'} failed validation "
            f"({len(self.errors)} error(s)): {details}"
        )


class IndicatorConversionError(Exception):
    """An indicator could not be converted into STIX.

    ``indicator_id`` is the CrowdStrike id of the indicator and ``reason``
    says why. When the failure comes from stix2, the original exception is
    chained as ``__cause__``.
    """

    def __init__(self, indicator_id: str, reason: str) -> None:
        super().__init__(indicator_id, reason)
        self.indicator_id = indicator_id
        self.reason = reason

    def __str__(self) -> str:
        return f"Indicator {self.indicator_id} could not be converted: {self.reason}"
