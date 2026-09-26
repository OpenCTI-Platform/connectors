# -*- coding: utf-8 -*-
"""Convert an XposedOrNot lookup result into STIX objects.

The enrichment is deliberately conservative to keep graphs clean:
  - the source Email-Addr observable is updated in place (score, labels,
    external reference) by the connector;
  - the per-breach detail lands in one markdown Note attached to the
    observable, rendered by OpenCTI.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

from connectors_sdk.models import Note, OrganizationAuthor, Reference
from connectors_sdk.models.note import NoteStix
from pycti import Note as PyctiNote
from pydantic import Field
from src.xposedornot.client_api import usable_score


class ObservableNote(Note):
    """Note whose STIX id and `created` are derived from the source observable,
    so a re-enrichment updates the existing Note in place instead of adding a
    second one. `modified` advances with each enrichment: it is the STIX
    version marker, and freezing it lets a platform treat refreshed breach
    content as an unchanged version and drop it. `supersedes` carries the
    `modified` of the version being replaced, so the new one outranks it even
    when that version claims a timestamp ahead of the clock."""

    source_id: str = Field(
        description="STIX id of the observable this note describes.",
    )
    supersedes: datetime | None = Field(
        default=None,
        description="`modified` of the version this note replaces, if any.",
    )

    @staticmethod
    def stable_id(source_id: str) -> str:
        return PyctiNote.generate_id(
            created=None, content=f"xposedornot-note:{source_id}"
        )

    def to_stix2_object(self) -> NoteStix:
        properties = dict(super().to_stix2_object())
        properties["id"] = self.stable_id(self.source_id)
        anchor = self.created or EPOCH_ANCHOR
        properties["created"] = anchor
        modified = max(datetime.now(timezone.utc), anchor)
        if self.supersedes is not None and modified <= self.supersedes:
            modified = self.supersedes + timedelta(microseconds=1)
        properties["modified"] = modified
        return NoteStix(allow_custom=True, **properties)


PLAINTEXT_PASSWORD_RISKS = frozenset({"plaintext", "plaintextpassword"})
EPOCH_ANCHOR = datetime(1970, 1, 1, tzinfo=timezone.utc)


def breach_year(breach: dict[str, Any]) -> int | None:
    """The four-digit year a breach is dated, or None when it is unreadable."""
    try:
        return int(str(breach.get("date"))[:4])
    except (TypeError, ValueError):
        return None


DEFAULT_MAX_TABLE_ROWS = 50


def read_timestamp(value: Any) -> datetime | None:
    """A timestamp exactly as given, or None when it cannot be read.

    `stable_timestamp` discards a value ahead of the clock because it is
    choosing an anchor. This one keeps it, because the caller is asking what
    an existing version already claims and therefore what it has to beat.
    """
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def stable_timestamp(value: Any) -> datetime:
    """A timestamp fixed per observable, so re-enrichment does not churn the Note.

    stix2 stamps `created` and `modified` at build time, which would give the
    same Note id a new version on every run. Anchoring on the observable's own
    creation time keeps them constant; any deterministic value works, so an
    unparseable or absent one falls back to the epoch.

    A timestamp in the future falls back too. `modified` is the later of the
    anchor and now, so an anchor ahead of the clock becomes the modified
    marker itself and stops advancing between runs, which is exactly the
    freezing this anchoring exists to avoid: a platform would read refreshed
    breach content as an unchanged version and drop it.
    """
    parsed = None
    if isinstance(value, datetime):
        parsed = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    elif isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return EPOCH_ANCHOR
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
    if parsed is None or parsed > datetime.now(timezone.utc):
        return EPOCH_ANCHOR
    return parsed


def _one_line_items(value: Any) -> list[Any]:
    """The entries of a list-shaped field, or nothing when it is not one."""
    return list(value) if isinstance(value, (list, tuple)) else []


def _one_line(value: Any) -> str:
    """Untrusted text flattened to a single printable line.

    Every character `str.splitlines` treats as a break has to go, not just
    `\n`. These values reach the note from the third-party API, and one
    carrying a carriage return, a form feed or a Unicode line separator ends
    the current markdown block and starts whatever follows as a new one,
    which is how a risk label became a heading.
    """
    text = re.sub(r"\s+", " ", str(value))
    return "".join(char for char in text if char.isprintable()).strip()


def _md_cell(value: Any) -> str:
    """Make a value safe for a one-line markdown table cell.

    As `_one_line`, and the cell separator is escaped as well so a value
    carrying a pipe cannot open a column of its own.

    Backslashes go first, and the order matters. Escaping only the pipe
    leaves a value that already ends in a backslash spelling an escaped
    backslash followed by a live separator, so it could still open a
    column despite the escaping.
    """
    text = str(value if value is not None else "—")
    text = text.replace("\\", "\\\\")
    return _one_line(text.replace("|", "\\|")) or "—"


def _fmt_records(value) -> str:
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return "—"


class ConverterToStix:
    """Build the Note describing the breach exposure of an email address."""

    def __init__(
        self,
        author: OrganizationAuthor,
        max_table_rows: int = DEFAULT_MAX_TABLE_ROWS,
    ):
        self.author = author
        self.max_table_rows = max_table_rows

    @staticmethod
    def make_author() -> OrganizationAuthor:
        return OrganizationAuthor(
            name="XposedOrNot",
            description=(
                "Breach exposure data provided by the XposedOrNot API"
                " (https://xposedornot.com)."
            ),
            organization_type="vendor",
        )

    @staticmethod
    def years(breaches: list[dict[str, Any]]) -> tuple[int | None, int | None]:
        years = [year for year in map(breach_year, breaches) if year is not None]
        return (min(years), max(years)) if years else (None, None)

    @staticmethod
    def most_recent(breaches: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Breaches newest first, so a capped table keeps the relevant rows."""
        return sorted(
            breaches, key=lambda breach: breach_year(breach) or -1, reverse=True
        )

    @staticmethod
    def has_plaintext_exposure(breaches: list[dict[str, Any]]) -> bool:
        return any(
            str(breach.get("password_risk") or "").strip().lower()
            in PLAINTEXT_PASSWORD_RISKS
            for breach in breaches
        )

    def build_note(
        self,
        source_id: str,
        result: dict[str, Any],
        markings: list[Any],
        observed_at: Any = None,
        supersedes: datetime | None = None,
    ) -> ObservableNote:
        breaches = [
            breach for breach in result.get("breaches") or [] if hasattr(breach, "get")
        ]
        first_year, latest_year = self.years(breaches)
        total_records = sum(
            b.get("records") for b in breaches if isinstance(b.get("records"), int)
        )

        lines = [
            "## XposedOrNot — breach exposure summary",
            "",
            f"**Breaches found:** {len(breaches)}  ",
        ]
        if first_year and latest_year:
            lines.append(
                f"**First exposure:** {first_year} — **Latest:** {latest_year}  "
            )
        if total_records:
            lines.append(f"**Total records across breaches:** {total_records:,}  ")
        risk_label = _one_line(result.get("risk_label") or "")
        score = usable_score(result.get("risk_score"))
        if risk_label and score is not None:
            lines.append(f"**Overall risk:** {risk_label} ({score}/100)  ")
        elif risk_label:
            lines.append(f"**Overall risk:** {risk_label}  ")
        elif score is not None:
            lines.append(f"**Overall risk:** {score}/100  ")
        if self.has_plaintext_exposure(breaches):
            lines.append("")
            lines.append("⚠️ **At least one breach stored passwords in plaintext.**")
        lines += [
            "",
            "| Breach | Date | Records | Domain | Industry | Exposed data"
            " | Password risk | Verified |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
        rendered = self.most_recent(breaches)
        if self.max_table_rows:
            rendered = rendered[: self.max_table_rows]
        for breach in rendered:
            cells = [
                _md_cell(breach.get("name")),
                _md_cell(breach.get("date")),
                _fmt_records(breach.get("records")),
                _md_cell(breach.get("domain")),
                _md_cell(breach.get("industry")),
                _md_cell(
                    ", ".join(
                        str(item)
                        for item in _one_line_items(breach.get("data_classes"))
                    )
                ),
                _md_cell(breach.get("password_risk")),
                _md_cell(breach.get("verified")),
            ]
            lines.append(f"| {' | '.join(cells)} |")
        hidden = len(breaches) - len(rendered)
        if hidden > 0:
            lines.append(
                f"| _… and {hidden} more breach(es); see xposedornot.com for"
                " the full list_ | | | | | | | |"
            )
        lines += [
            "",
            "_Generated by the XposedOrNot connector"
            " ([xposedornot.com](https://xposedornot.com))._",
        ]

        return ObservableNote(
            source_id=source_id,
            created=stable_timestamp(observed_at),
            abstract=f"XposedOrNot — exposed in {len(breaches)} data breach(es)",
            content="\n".join(lines),
            objects=[Reference(id=source_id)],
            note_types=["analysis"],
            labels=["xposedornot", "data-breach"],
            author=self.author,
            markings=markings,
            supersedes=supersedes,
        )
