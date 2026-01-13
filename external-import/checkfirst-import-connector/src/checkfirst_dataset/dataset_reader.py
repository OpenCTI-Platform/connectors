from __future__ import annotations

"""CSV dataset reader.

This module reads Checkfirst dataset files (plain `.csv` or gzipped `.csv.gz`)
and yields validated rows as `DatasetRow` objects.

Key goals:
- Validate required columns and required field presence.
- Enforce optional size/row-count guards from the connector settings.
- Provide a stable per-file cursor via `start_cursor`.
"""

import csv
import gzip
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Iterator

from checkfirst_dataset.reporting import RunReport, SkipReason
from checkfirst_dataset.types import CheckfirstConfigLike

REQUIRED_COLUMNS = {
    "URL",
    "Source Title",
    "Source URL",
    "Publication Date",
}


@dataclass(frozen=True)
class DatasetRow:
    """A normalized row extracted from a dataset file."""

    source_file: str
    row_number: int

    url: str
    source_title: str
    source_url: str
    canonical: str | None
    og_title: str | None
    og_description: str | None
    alternates: str | None
    country: str | None
    publication_date: str


class RowSkip(Exception):
    """Raised for file-level validation issues (e.g., missing headers/columns)."""

    pass


def _open_dataset_file(path: Path) -> IO[str]:
    """Open a dataset file as text, supporting gzip-compressed CSV files."""
    if [s.lower() for s in path.suffixes[-2:]] == [".csv", ".gz"]:
        return gzip.open(path, mode="rt", encoding="utf-8", newline="")
    return path.open(mode="rt", encoding="utf-8", newline="")


def _validate_header(fieldnames: list[str] | None) -> None:
    """Ensure the CSV header contains the required columns."""
    if not fieldnames:
        raise RowSkip("missing header")
    missing = REQUIRED_COLUMNS.difference(fieldnames)
    if missing:
        raise RowSkip(f"missing required columns: {sorted(missing)}")


def iter_rows(
    *,
    config: CheckfirstConfigLike,
    dataset_root: Path,
    file_path: Path,
    start_cursor: int = 0,
    report: RunReport | None = None,
) -> Iterator[DatasetRow]:
    """Iterate over validated rows from a dataset file.

    `start_cursor` skips the first N data rows (0-based index, not counting the
    header) which enables resume/retry within a file.
    """
    # Basic file-level guard
    if config.max_file_bytes is not None:
        try:
            size = file_path.stat().st_size
        except OSError:
            size = None
        if size is not None and size > config.max_file_bytes:
            if report is not None:
                report.skip(SkipReason.FILE_TOO_LARGE)
            return

    # Relative path is used for reporting/state and normalized to POSIX separators
    # for consistent behavior on Windows/Linux.
    rel = str(file_path.resolve().relative_to(dataset_root.resolve())).replace(
        "\\", "/"
    )

    with _open_dataset_file(file_path) as fp:
        reader = csv.DictReader(fp)
        _validate_header(reader.fieldnames)

        for idx, row in enumerate(reader):
            if idx < start_cursor:
                continue
            if config.max_rows_per_file is not None and idx >= config.max_rows_per_file:
                return

            # Basic row-size guard (approximate; DictReader already parsed the line)
            if config.max_row_bytes is not None:
                approx = sum(len(str(v or "")) for v in row.values())
                if approx > config.max_row_bytes:
                    if report is not None:
                        report.skip(SkipReason.ROW_TOO_LARGE)
                    continue

            url = (row.get("URL") or "").strip()
            source_title = (row.get("Source Title") or "").strip()
            source_url = (row.get("Source URL") or "").strip()
            publication_date = (row.get("Publication Date") or "").strip()

            if not url or not source_title or not source_url or not publication_date:
                if report is not None:
                    report.skip(SkipReason.ROW_MISSING_REQUIRED_FIELDS)
                continue

            yield DatasetRow(
                source_file=rel,
                row_number=idx + 1,
                url=url,
                source_title=source_title,
                source_url=source_url,
                canonical=(row.get("Canonical") or "").strip() or None,
                og_title=(row.get("OG:Title") or "").strip() or None,
                og_description=(row.get("OG:Description") or "").strip() or None,
                alternates=(row.get("Alternates") or "").strip() or None,
                country=(row.get("Country") or "").strip() or None,
                publication_date=publication_date,
            )
