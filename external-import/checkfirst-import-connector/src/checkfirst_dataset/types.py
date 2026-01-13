from __future__ import annotations

from typing import Protocol


class CheckfirstConfigLike(Protocol):
    """Minimal interface required by dataset reading helpers."""

    max_file_bytes: int | None
    max_row_bytes: int | None
    max_rows_per_file: int | None
