"""Protocol definitions for duck-typed interfaces used by API helpers."""

from typing import Protocol


class CheckfirstConfigLike(Protocol):
    """Minimal interface required by API reading helpers."""

    max_row_bytes: int | None
