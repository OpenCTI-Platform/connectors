"""Build the STIX Note that summarises an address's breach exposure."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from connectors_sdk.models import Note, OrganizationAuthor, Reference
from connectors_sdk.models.note import NoteStix
from pycti import Note as PyctiNote
from pydantic import Field
from src.xposedornot.client_api import usable_score

EPOCH_ANCHOR = datetime(1970, 1, 1, tzinfo=timezone.utc)
PLAINTEXT_PASSWORD_RISKS = frozenset({"plaintext", "plaintextpassword"})
DEFAULT_MAX_TABLE_ROWS = 50
MAX_DETAILS_CHARS = 160
TABLE_COLUMNS = (
    "Breach",
    "Date",
    "Records",
    "Domain",
    "Industry",
    "Exposed data",
    "Password risk",
    "Verified",
    "Description",
)


class ObservableNote(Note):
    """Note whose id and `created` derive from the observable, so re-enrichment
    updates it in place. `modified` always advances so the newer version wins."""

    source_id: str = Field(description="STIX id of the observable this note describes.")

    @staticmethod
    def stable_id(source_id: str) -> str:
        return PyctiNote.generate_id(
            created=None, content=f"xposedornot-note:{source_id}"
        )

    def to_stix2_object(self) -> NoteStix:
        properties = dict(super().to_stix2_object())
        anchor = self.created or EPOCH_ANCHOR
        if anchor.tzinfo is None:
            anchor = anchor.replace(tzinfo=timezone.utc)
        properties["id"] = self.stable_id(self.source_id)
        properties["created"] = anchor
        properties["modified"] = max(datetime.now(timezone.utc), anchor)
        return NoteStix(allow_custom=True, **properties)


def stable_timestamp(value: Any) -> datetime:
    """The observable's creation time, or the epoch when it is unusable."""
    if isinstance(value, str) and value:
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return EPOCH_ANCHOR
    if not isinstance(value, datetime):
        return EPOCH_ANCHOR
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value if value <= datetime.now(timezone.utc) else EPOCH_ANCHOR


def breach_year(breach: dict[str, Any]) -> int | None:
    try:
        year = int(str(breach.get("date"))[:4])
    except (TypeError, ValueError):
        return None
    return year if 1970 <= year <= datetime.now(timezone.utc).year else None


def _cell(value: Any, limit: int = 0) -> str:
    """A value flattened to one printable line, safe inside a markdown table."""
    if value is None or value == "":
        return "—"
    text = str(value).replace("\\", "\\\\").replace("|", "\\|")
    text = re.sub(r"\s+", " ", text)
    text = "".join(char for char in text if char.isprintable()).strip()
    if limit and len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return text or "—"


def _records(value: Any) -> str:
    return f"{value:,}" if type(value) is int and value >= 0 else "—"


class ConverterToStix:
    def __init__(
        self, author: OrganizationAuthor, max_table_rows: int = DEFAULT_MAX_TABLE_ROWS
    ) -> None:
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
    ) -> ObservableNote:
        breaches = list(result.get("breaches") or [])
        first_year, latest_year = self.years(breaches)
        counts = [b.get("records") for b in breaches]
        known = [c for c in counts if type(c) is int and c >= 0]
        risk_label = _cell(result.get("risk_label")) if result.get("risk_label") else ""
        score = usable_score(result.get("risk_score"))

        lines = [
            "## XposedOrNot — breach exposure summary",
            "",
            f"**Breaches found:** {len(breaches)}  ",
        ]
        if first_year and latest_year:
            lines.append(
                f"**First exposure:** {first_year} — **Latest:** {latest_year}  "
            )
        if known:
            lines.append(f"**Total records across breaches:** {sum(known):,}  ")
        if risk_label and score is not None:
            lines.append(f"**Overall risk:** {risk_label} ({score}/100)  ")
        elif risk_label:
            lines.append(f"**Overall risk:** {risk_label}  ")
        elif score is not None:
            lines.append(f"**Overall risk:** {score}/100  ")
        if self.has_plaintext_exposure(breaches):
            lines += ["", "⚠️ **At least one breach stored passwords in plaintext.**"]
        lines += [
            "",
            "| " + " | ".join(TABLE_COLUMNS) + " |",
            "|" + " --- |" * len(TABLE_COLUMNS),
        ]
        rows = sorted(breaches, key=lambda b: breach_year(b) or -1, reverse=True)
        if self.max_table_rows:
            rows = rows[: self.max_table_rows]
        for breach in rows:
            cells = [
                _cell(breach.get("name")),
                _cell(breach.get("date")),
                _records(breach.get("records")),
                _cell(breach.get("domain")),
                _cell(breach.get("industry")),
                _cell(", ".join(map(str, breach.get("data_classes") or []))),
                _cell(breach.get("password_risk")),
                _cell(breach.get("verified")),
                _cell(breach.get("details"), MAX_DETAILS_CHARS),
            ]
            lines.append("| " + " | ".join(cells) + " |")
        hidden = len(breaches) - len(rows)
        if hidden > 0:
            lines.append(
                f"| _… and {hidden} more breach(es); see xposedornot.com for the"
                " full list_ |" + " |" * (len(TABLE_COLUMNS) - 1)
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
        )
