"""WhoisFreaksThreatFeedConverter."""

from connectors_sdk.converters.base import AbstractConverter
from connectors_sdk.converters.exceptions import ConversionError
from connectors_sdk.converters.whoisfreaks.models import WhoisFreaksThreatFeedRecord
from connectors_sdk.models import (
    BaseAuthorEntity,
    BaseIdentifiedObject,
    DomainName,
    Indicator,
    Note,
    Relationship,
    TLPMarking,
)
from connectors_sdk.models.enums import NoteType, RelationshipType
from pydantic import ValidationError

WHOISFREAKS_FEED_TYPES = frozenset({"malware", "phishing", "spam"})


class WhoisFreaksThreatFeedConverter(AbstractConverter[WhoisFreaksThreatFeedRecord]):
    """Convert a WhoisFreaks threat-feed record into a domain, an indicator and a note.

    The ``x_whoisfreaks_*`` custom properties set by the connector are not
    produced: SDK models cannot carry custom properties.

    Examples:
        >>> from connectors_sdk.models import OrganizationAuthor, TLPMarking
        >>> converter = WhoisFreaksThreatFeedConverter(
        ...     author=OrganizationAuthor(name="WhoisFreaks"),
        ...     markings=[TLPMarking(level="amber")],
        ...     feed_type="malware",
        ... )
        >>> converter.feed_type
        'malware'

    """

    def __init__(
        self,
        author: BaseAuthorEntity,
        markings: list[TLPMarking],
        feed_type: str,
    ) -> None:
        """Initialize the converter.

        Args:
            author: The author referenced by every produced object.
            markings: The markings referenced by every produced object.
            feed_type: The threat feed, one of ``malware``, ``phishing`` or ``spam``.

        Raises:
            ValueError: If the feed type is not supported.
        """
        if feed_type not in WHOISFREAKS_FEED_TYPES:
            raise ValueError(f"Unsupported threat feed: {feed_type}")
        super().__init__(author=author, markings=markings)
        self.feed_type = feed_type

    def transform(
        self, input: WhoisFreaksThreatFeedRecord
    ) -> list[BaseIdentifiedObject]:
        """Convert a threat-feed record.

        Args:
            input: The threat-feed record.

        Returns:
            The domain name, the indicator, the ``based-on`` relationship and the note.

        Raises:
            ConversionError: If a value of the record is rejected by the models.
        """
        domain = input.domain.lower().rstrip(".")
        pattern = "[domain-name:value = '" + domain.replace("'", "\\'") + "']"
        score = round(input.confidence_score * 100)
        description = (
            f"WhoisFreaks {self.feed_type} threat feed record for {domain} "
            f"(confidence={input.confidence_score}, "
            f"threat_type={input.threat_type})."
        )
        labels = [
            "whoisfreaks",
            f"whoisfreaks-{self.feed_type}",
            f"threat-type-{input.threat_type}",
        ]

        try:
            observable = DomainName(
                value=domain,
                description=description,
                score=score,
                labels=labels,
                author=self.author,
                markings=self.markings,
            )
            indicator = Indicator(
                name=domain,
                description=description,
                indicator_types=["malicious-activity"],
                pattern_type="stix",
                pattern=pattern,
                # last_seen is the last observation, not an expiry: no valid_until.
                valid_from=input.first_seen,
                labels=labels,
                score=score,
                main_observable_type="Domain-Name",
                author=self.author,
                markings=self.markings,
            )
            relationship = Relationship(
                type=RelationshipType.BASED_ON,
                source=indicator,
                target=observable,
                author=self.author,
                markings=self.markings,
            )
            note = Note(
                abstract=f"WhoisFreaks {self.feed_type} fields for {domain}",
                content=self._note_content(domain, input),
                objects=[indicator, observable],
                labels=[
                    "whoisfreaks",
                    f"whoisfreaks-{self.feed_type}",
                    "whoisfreaks-threat-feed",
                ],
                note_types=[NoteType.EXTERNAL],
                author=self.author,
                markings=self.markings,
            )
        except ValidationError as err:
            raise ConversionError(f"Cannot convert {domain}") from err

        return [observable, indicator, relationship, note]

    def _note_content(self, domain: str, record: WhoisFreaksThreatFeedRecord) -> str:
        """Render every feed column as a Markdown table, skipping empty ones."""
        columns = record.source_fields or {
            "domain": domain,
            "threat_type": record.threat_type,
            "confidence": str(record.confidence_score),
            "first_seen": record.first_seen.isoformat(),
            "last_seen": record.last_seen.isoformat(),
            "No_of_threat_matched_pivots": str(record.no_of_threat_matched_pivots),
        }
        lines = [
            f"## WhoisFreaks {self.feed_type} threat feed — `{domain}`",
            "",
            "| Field | Value |",
            "| --- | --- |",
        ]
        for column, value in columns.items():
            text = value.strip()
            if text:
                safe = text.replace("|", "\\|").replace("\n", " ")
                lines.append(f"| `{column}` | {safe} |")
        return "\n".join(lines)
