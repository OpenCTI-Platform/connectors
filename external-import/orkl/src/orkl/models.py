"""Pydantic models for ORKL API responses."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

# This is a connector-side choice, not a platform limit: OpenCTI imposes no
# description length limit (verified - `description` is an unbounded
# Elasticsearch `text` field). However, the full text remains reachable
# through the `files.text` external reference, so storing tens of thousands
# of characters of extracted PDF text per report in the description would
# bloat the platform for no analyst benefit.
DESCRIPTION_MAX_LENGTH = 500

_ELLIPSIS = "…"

# The API's "no known date" sentinel is year 1 (0001-01-01T00:00:00Z). Any year
# below this threshold is treated as unset; 1970 (the Unix epoch) is a safe
# cutoff that no genuine CTI report predates.
_MIN_VALID_YEAR = 1970


def _normalise_list(v: Any) -> Any:
    """Normalise a `None` list field to an empty list."""
    if v is None:
        return []
    return v


def _parse_iso8601(value: str | None) -> datetime | None:
    """Parse an ISO-8601 timestamp (optionally with a trailing `Z`) to a tz-aware datetime."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


class OrklFiles(BaseModel):
    """Archive file URLs attached to a library entry."""

    model_config = ConfigDict(extra="allow")

    pdf: str | None = None
    text: str | None = None
    img: str | None = None


class OrklThreatActor(BaseModel):
    """A threat actor reference embedded in a library entry."""

    model_config = ConfigDict(extra="allow")

    id: str
    created_at: str | None = None
    updated_at: str | None = None
    deleted_at: str | None = None
    main_name: str
    aliases: list[str] = Field(default_factory=list)
    source_name: str | None = None
    source_id: str | None = None
    tools: list[str] = Field(default_factory=list)
    reports: list[Any] | None = None

    @field_validator("aliases", "tools", mode="before")
    @classmethod
    def _normalise_lists(cls, v: Any) -> Any:
        return _normalise_list(v)

    @property
    def other_aliases(self) -> list[str]:
        """Deduplicated aliases excluding the `main_name` itself, order preserved."""
        seen: set[str] = set()
        result: list[str] = []
        for alias in self.aliases:
            if alias == self.main_name or alias in seen:
                continue
            seen.add(alias)
            result.append(alias)
        return result


class OrklLibraryEntry(BaseModel):
    """A single ORKL library entry (report)."""

    model_config = ConfigDict(extra="allow")

    id: str
    created_at: str | None = None
    updated_at: str | None = None
    deleted_at: str | None = None
    sha1_hash: str | None = None
    title: str | None = None
    llm_title: str | None = None
    authors: str | None = None
    file_creation_date: str | None = None
    file_modification_date: str | None = None
    file_size: int | None = None
    plain_text: str | None = None
    extraction_quality: int | None = None
    language: str | None = None
    sources: list[str] = Field(default_factory=list)
    origins: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    report_names: list[str] = Field(default_factory=list)
    threat_actors: list[OrklThreatActor] = Field(default_factory=list)
    ts_created_at: int | None = None
    ts_updated_at: int | None = None
    ts_creation_date: int | None = None
    ts_modification_date: int | None = None
    files: OrklFiles | None = None

    @field_validator(
        "sources",
        "origins",
        "references",
        "report_names",
        "threat_actors",
        mode="before",
    )
    @classmethod
    def _normalise_lists(cls, v: Any) -> Any:
        return _normalise_list(v)

    @property
    def is_deleted(self) -> bool:
        """True when this entry has been soft-deleted upstream."""
        return self.deleted_at is not None

    @property
    def name(self) -> str:
        """Best available title for this entry, never empty.

        Deliberately scans the *entire* `report_names` list (not just
        `report_names[0]`) after `title`/`llm_title`: any non-empty report
        name is a better display name than the synthetic
        `ORKL report <sha1_hash>` fallback, and a whitespace-only first
        element should not force that fallback when a later element is
        usable.
        """
        candidates = [self.title, self.llm_title]
        candidates.extend(self.report_names)
        for candidate in candidates:
            if candidate and candidate.strip():
                return candidate.strip()
        if self.sha1_hash:
            return f"ORKL report {self.sha1_hash}"
        return f"ORKL report {self.id}"

    @property
    def description(self) -> str | None:
        """Collapsed and truncated `plain_text`, or `None` if unusable.

        `plain_text` is PDF-extracted text riddled with hard line breaks
        and blank lines, so internal whitespace runs (including newlines)
        are collapsed to single spaces before truncation; otherwise a
        `DESCRIPTION_MAX_LENGTH`-character preview would be mostly
        newlines instead of readable text.
        """
        if not self.plain_text:
            return None
        collapsed = " ".join(self.plain_text.split())
        if not collapsed:
            return None
        if len(collapsed) <= DESCRIPTION_MAX_LENGTH:
            return collapsed
        truncated_length = DESCRIPTION_MAX_LENGTH - len(_ELLIPSIS)
        return collapsed[:truncated_length] + _ELLIPSIS

    @property
    def publication_date(self) -> datetime | None:
        """Best available publication date, ignoring the year-1 sentinel."""
        for candidate in (self.file_creation_date, self.created_at):
            parsed = _parse_iso8601(candidate)
            if parsed is not None and parsed.year >= _MIN_VALID_YEAR:
                return parsed
        return None

    @property
    def updated_datetime(self) -> datetime | None:
        """Timezone-aware datetime parsed from `updated_at`, used as pagination cursor."""
        return _parse_iso8601(self.updated_at)

    @property
    def labels(self) -> list[str]:
        """Deduplicated union of `sources` and `origins`, order preserved."""
        seen: set[str] = set()
        result: list[str] = []
        for value in [*self.sources, *self.origins]:
            if not value or value in seen:
                continue
            seen.add(value)
            result.append(value)
        return result
