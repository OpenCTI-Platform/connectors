"""Source-independent errors that connector components can raise.

They are a toolkit: the extraction, enrichment and transformation contracts
require an error that says what failed, not one of these types.
"""

import json
from typing import Any

from pydantic import ValidationError


class SourceAPIError(Exception):
    """A source API answered with an error.

    ``source`` names the source, as shown in the message. The meaning of
    ``status_code``, including a placeholder value when the source gives
    none, is left to the source.
    """

    def __init__(self, source: str, status_code: int, message: str) -> None:
        super().__init__(source, status_code, message)
        self.source = source
        self.status_code = status_code
        self.message = message

    def __str__(self) -> str:
        return f"{self.source} API error {self.status_code}: {self.message}"


class ItemValidationError(Exception):
    """A record returned by a source does not match its model.

    ``item_id`` identifies the record, or is ``None`` when it has no usable
    id. ``errors`` is the JSON-safe list of Pydantic validation errors, and
    ``raw`` the record exactly as the source returned it.
    """

    def __init__(
        self,
        item_id: str | None,
        errors: list[dict[str, Any]],
        raw: Any,
    ) -> None:
        super().__init__(item_id, errors, raw)
        self.item_id = item_id
        self.errors = errors
        self.raw = raw

    @classmethod
    def from_validation_error(
        cls, error: ValidationError, raw: Any, item_id: str | None = None
    ) -> "ItemValidationError":
        """Describe the validation failure of ``raw``.

        The validation errors become a JSON-safe list without documentation
        URLs, and ``error`` is chained as the cause. Which field identifies a
        record depends on the source, so ``item_id`` is never read from
        ``raw``.
        """
        validation_error = cls(
            item_id=item_id,
            errors=json.loads(error.json(include_url=False)),
            raw=raw,
        )
        validation_error.__cause__ = error
        return validation_error

    def __str__(self) -> str:
        details = "; ".join(
            f"{'.'.join(str(part) for part in error.get('loc', ())) or '<root>'}: "
            f"{error.get('msg', 'invalid')}"
            for error in self.errors
        )
        return (
            f"Item {self.item_id or '<no id>'} failed validation "
            f"({len(self.errors)} error(s)): {details}"
        )


class ItemConversionError(Exception):
    """An item could not be converted.

    ``item_id`` identifies the item and ``reason`` says why. When the failure
    comes from another error, that error is chained as ``__cause__``.
    """

    def __init__(self, item_id: str, reason: str) -> None:
        super().__init__(item_id, reason)
        self.item_id = item_id
        self.reason = reason

    def __str__(self) -> str:
        return f"Item {self.item_id} could not be converted: {self.reason}"
