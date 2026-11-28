"""Convert MISP matches into STIX 2.1 objects."""

import re
from datetime import datetime, timezone
from typing import Any

import stix2
from connector.misp_client import MispMatch
from pycti import Identity, Note, Report

_THREAT_LEVELS = {"1": "High", "2": "Medium", "3": "Low", "4": "Undefined"}


class ConverterToStix:
    """
    Provides methods for converting MISP matches into STIX 2.1 objects.

    REQUIREMENTS:
        - `generate_id()` methods from `pycti` library MUST be used to generate the `id` of each entity (except observables).
    """

    def __init__(
        self, misp_url: str, attribute_comment_filter_regex: str | None = None
    ) -> None:
        self.misp_url = misp_url.rstrip("/")
        self.comment_regex = (
            re.compile(attribute_comment_filter_regex)
            if attribute_comment_filter_regex
            else None
        )
        self.author = self.create_author()

    @staticmethod
    def create_author() -> stix2.Identity:
        return stix2.Identity(
            id=Identity.generate_id(name="MISP", identity_class="organization"),
            name="MISP",
            identity_class="organization",
            description=(
                "MISP (Malware Information Sharing Platform) is an open-source threat intelligence "
                "platform for sharing, storing and correlating Indicators of Compromise."
            ),
            external_references=[
                stix2.ExternalReference(
                    source_name="MISP Project",
                    url="https://www.misp-project.org/",
                )
            ],
        )

    def event_url(self, event_id: str) -> str:
        return f"{self.misp_url}/events/view/{event_id}"

    # ------------------------------------------------------------------
    # Enriched entity: external references and labels
    # ------------------------------------------------------------------

    def create_external_reference(self, match: MispMatch) -> dict[str, str]:
        return {
            "source_name": f"MISP Event #{match.event_id}",
            "url": self.event_url(match.event_id),
            "description": match.event.get("info") or f"MISP event {match.event_id}",
        }

    def enrich_entity(
        self, stix_entity: dict, matches: list[MispMatch], labels: list[str]
    ) -> dict:
        """
        Return a copy of the STIX entity with one external reference per matched event
        and the given labels, merged with the existing ones.
        """
        enriched = dict(stix_entity)

        external_references = list(enriched.get("external_references", []))
        known_urls = {reference.get("url") for reference in external_references}
        for match in matches:
            reference = self.create_external_reference(match)
            if reference["url"] not in known_urls:
                external_references.append(reference)
                known_urls.add(reference["url"])
        enriched["external_references"] = external_references

        if labels:
            existing_labels = list(enriched.get("labels", []))
            enriched["labels"] = existing_labels + [
                label for label in labels if label not in existing_labels
            ]
        return enriched

    # ------------------------------------------------------------------
    # Note: one per matched event
    # ------------------------------------------------------------------

    def create_note(
        self,
        match: MispMatch,
        matched_values: list[str],
        entity_id: str,
        markings: list[str],
    ) -> stix2.Note:
        event = match.event
        name = event.get("info") or "N/A"
        content = self._note_content(match)
        return stix2.Note(
            id=Note.generate_id(content=content, created=None),
            abstract=f'MISP match: {", ".join(matched_values)} in "{name}"',
            content=content,
            created=self._parse_date(event.get("date")),
            created_by_ref=self.author["id"],
            object_refs=[entity_id],
            object_marking_refs=markings,
        )

    def _note_content(self, match: MispMatch) -> str:
        event = match.event
        lines: list[str] = []

        for attribute in match.attributes:
            lines.append(f"#### Attribute #{attribute.get('id') or 'N/A'}\n")
            lines.append(f"- **Category**: {attribute.get('category') or 'N/A'}")
            lines.append(f"- **Type**: {attribute.get('type') or 'N/A'}")
            lines.append(f"- **Value**: `{attribute.get('value') or 'N/A'}`")
            lines.append(f"- **First Seen**: {attribute.get('first_seen') or 'N/A'}")
            lines.append(f"- **Last Seen**: {attribute.get('last_seen') or 'N/A'}")
            lines.append(f"- **To IDS**: {'Yes' if attribute.get('to_ids') else 'No'}")
            object_id = attribute.get("object_id")
            if object_id and str(object_id) != "0":
                lines.append(f"- **Object ID**: {object_id}")
            comment = (attribute.get("comment") or "").strip()
            if comment and (
                self.comment_regex is None or self.comment_regex.search(comment)
            ):
                lines.append(f"- **Comment**: {comment}")
            attribute_tags = tag_names(attribute.get("Tag"))
            if attribute_tags:
                lines.append(f"- **Tags**: {', '.join(attribute_tags)}")
            lines.append("")

        event_url = self.event_url(match.event_id)
        lines.append(f"### Event: {event.get('info') or 'N/A'}\n")
        lines.append(
            f"- **Threat level**: {_THREAT_LEVELS.get(str(event.get('threat_level_id')), 'Undefined')}"
        )
        event_tags = tag_names(event.get("Tag"))
        if event_tags:
            lines.append(f"- **Tags**: {', '.join(event_tags)}")
        lines.append(f"- **URL**: [{event_url}]({event_url})")

        analysis_comments = self._analysis_comments(event)
        if analysis_comments:
            lines.append("- **Analysis comments**:")
            lines.extend(f"  - {comment}" for comment in analysis_comments)

        return "\n".join(lines)

    @staticmethod
    def _analysis_comments(event: dict[str, Any]) -> list[str]:
        """Values of the "External analysis / comment" attributes of the event and its objects."""
        attributes = list(event.get("Attribute") or [])
        for misp_object in event.get("Object") or []:
            attributes.extend(misp_object.get("Attribute") or [])
        return [
            attribute["value"].strip()
            for attribute in attributes
            if (attribute.get("category") or "").lower() == "external analysis"
            and (attribute.get("type") or "").lower() == "comment"
            and (attribute.get("value") or "").strip()
        ]

    # ------------------------------------------------------------------
    # Report: one per matched event (optional)
    # ------------------------------------------------------------------

    def create_report(
        self, match: MispMatch, entity_id: str, markings: list[str]
    ) -> stix2.Report:
        """
        One Report per MISP event, containing the enriched entity.
        Its ID is computed like the MISP import connector does, so both converge on the same Report.
        """
        event = match.event
        name = event.get("info") or f"MISP event {match.event_id}"
        # MISP always sets the event date: the fallback only guards against malformed events
        published = self._parse_date(event.get("date")) or datetime.now(tz=timezone.utc)
        return stix2.Report(
            id=Report.generate_id(name=name, published=published),
            name=name,
            description=f"MISP event #{match.event_id}.",
            published=published,
            report_types=["threat-report"],
            created_by_ref=self.author["id"],
            object_refs=[entity_id],
            labels=tag_names(event.get("Tag")) or None,
            external_references=[self.create_external_reference(match)],
            object_marking_refs=markings,
        )

    @staticmethod
    def _parse_date(date: str | None) -> datetime | None:
        if date:
            try:
                return datetime.strptime(date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                pass
        return None


def tag_names(tags: list[dict] | None) -> list[str]:
    """Distinct, non-empty names of a list of MISP tags, in order."""
    names: list[str] = []
    for tag in tags or []:
        name = (tag.get("name") or "").strip()
        if name and name not in names:
            names.append(name)
    return names
