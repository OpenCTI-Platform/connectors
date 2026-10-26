"""Build the enriched observable and the note that describe a feed listing."""

import json
import re
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

from connectors_sdk.models import Note, OrganizationAuthor, Reference
from connectors_sdk.models.note import NoteStix
from pycti import Note as PyctiNote
from pydantic import Field

OWN_SOURCE_NAME = "NetAPI"
OWN_LABEL = "netapi-compromised"
EPOCH_ANCHOR = datetime(1970, 1, 1, tzinfo=timezone.utc)


class ObservableNote(Note):
    """Note whose id and `created` derive from the observable, so re-enrichment
    updates it in place. `modified` always advances so the newer version wins."""

    source_id: str = Field(description="STIX id of the observable this note describes.")

    @staticmethod
    def stable_id(source_id: str) -> str:
        return PyctiNote.generate_id(created=None, content=f"netapi-note:{source_id}")

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


def _cell(value: Any) -> str:
    """A value flattened to one printable line, safe inside a markdown table."""
    if value is None or value == "":
        return "-"
    text = str(value).replace("\\", "\\\\").replace("|", "\\|")
    text = re.sub(r"\s+", " ", text)
    text = "".join(char for char in text if char.isprintable()).strip()
    return text or "-"


def _link(label: Any, url: Any) -> str:
    """A markdown link, or the label alone when the URL is not an https link."""
    label = _cell(label)
    if isinstance(url, str) and url.startswith("https://"):
        return f"[{label}]({url})"
    return label


class ConverterToStix:
    def __init__(self, author: OrganizationAuthor) -> None:
        self.author = author

    @staticmethod
    def make_author() -> OrganizationAuthor:
        return OrganizationAuthor(
            name=OWN_SOURCE_NAME,
            description=(
                "Compromised domain and IP feed and Top 1M ranking provided by the "
                "NetAPI JSON API (https://netapi.com/)."
            ),
            organization_type="vendor",
        )

    @staticmethod
    def status_line(check: dict[str, Any]) -> str:
        if check.get("listed_now"):
            return "listed now (seen in the compromised feed within the last 24 hours)"
        last_seen = _cell(str(check.get("last_seen") or "")[:10])
        return f"listed in the past (last seen {last_seen}), not in the current feed"

    def enrich_observable(
        self, stix_entity: dict[str, Any], check: dict[str, Any], score: int | None
    ) -> dict[str, Any]:
        """A copy of the observable carrying the label, the reference and the score.

        The label `netapi-compromised` is added when the value is listed now.
        It is never removed: OpenCTI merges the labels of an imported bundle, so
        leaving it out would not take it off, and the note carries the current
        status. Every other label and every reference of another source is kept.
        """
        entity = deepcopy(stix_entity)
        if score is not None:
            entity["x_opencti_score"] = score

        existing = (entity.get("x_opencti_labels") or []) + (
            entity.pop("labels", None) or []
        )
        labels = [label for label in dict.fromkeys(existing) if isinstance(label, str)]
        if check.get("listed_now") and OWN_LABEL not in {
            label.casefold() for label in labels
        }:
            labels.append(OWN_LABEL)
        entity["x_opencti_labels"] = labels

        references = (entity.pop("external_references", None) or []) + (
            entity.get("x_opencti_external_references") or []
        )
        kept: list[dict[str, Any]] = []
        seen: set[str] = set()
        for ref in references:
            if not isinstance(ref, dict) or ref.get("source_name") == OWN_SOURCE_NAME:
                continue
            key = json.dumps(ref, sort_keys=True, default=str)
            if key not in seen:
                seen.add(key)
                kept.append(ref)
        lists = check.get("lists") if isinstance(check.get("lists"), dict) else {}
        own_reference = {
            "source_name": OWN_SOURCE_NAME,
            "url": lists.get("page") or "https://netapi.com/compromised-urls/",
            "description": f"NetAPI compromised feed: {self.status_line(check)}",
        }
        entity["x_opencti_external_references"] = kept + [own_reference]
        return entity

    def build_note(
        self,
        source_id: str,
        value: str,
        check: dict[str, Any],
        rank: dict[str, Any] | None,
        markings: list[Any],
        observed_at: Any = None,
    ) -> ObservableNote:
        status = self.status_line(check)
        rows = [("Observable", _cell(value))]
        matched = check.get("matched_value")
        if matched and matched != value:
            rows.append(("Matched entry", f"{_cell(matched)} (the registered domain)"))
        rows += [
            ("First seen", _cell(check.get("first_seen"))),
            ("Last seen", _cell(check.get("last_seen"))),
            ("Reported by", _cell(check.get("block_reason"))),
        ]
        registrar = check.get("registrar")
        if isinstance(registrar, dict):
            name = registrar.get("brand_name") or registrar.get("name")
            rows.append(("Registrar", _link(name, registrar.get("page"))))
        if isinstance(rank, dict):
            if rank.get("in_top_1m"):
                position = f"#{_cell(rank.get('rank'))}"
                if rank.get("snapshot_date"):
                    position += f" (snapshot of {_cell(rank['snapshot_date'])})"
                rows.append(("Top 1M rank", position))
            else:
                rows.append(("Top 1M rank", "not in the NetAPI Top 1M"))

        lines = [
            "## NetAPI compromised feed",
            "",
            f"**Status:** {status}",
            "",
            "| Field | Value |",
            "| --- | --- |",
        ]
        lines += [f"| {field} | {cell} |" for field, cell in rows]
        lists = check.get("lists") if isinstance(check.get("lists"), dict) else {}
        feed_links = [
            _link(label, lists.get(key))
            for label, key in (
                ("feed page", "page"),
                ("current list", "current"),
                ("all-time list", "all_time"),
            )
            if lists.get(key)
        ]
        if feed_links:
            lines += ["", "Feed: " + ", ".join(feed_links)]
        lines += [
            "",
            "_Generated by the NetAPI connector ([netapi.com](https://netapi.com/))._",
        ]

        abstract = (
            "NetAPI - listed in the compromised feed"
            if check.get("listed_now")
            else "NetAPI - listed in the compromised feed in the past"
        )
        return ObservableNote(
            source_id=source_id,
            created=stable_timestamp(observed_at),
            abstract=abstract,
            content="\n".join(lines),
            objects=[Reference(id=source_id)],
            note_types=["external"],
            labels=["netapi"],
            author=self.author,
            markings=markings,
        )
