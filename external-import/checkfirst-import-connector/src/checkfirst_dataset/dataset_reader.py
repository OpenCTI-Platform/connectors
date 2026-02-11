from __future__ import annotations

"""Data row model used by the API reader."""

from dataclasses import dataclass


@dataclass(frozen=True)
class DatasetRow:
    """A normalized row extracted from the API."""

    source_file: str
    row_number: int
    url: str
    source_title: str
    source_url: str
    canonical: str | None
    og_title: str | None
    og_description: str | None
    alternates: str | None
    publication_date: str
