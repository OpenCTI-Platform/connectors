"""Map Cyble engine documents (advisory, newsfeed, newsflash) to STIX Reports."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from connector.mappers.common import first_text, labeled
from connector.mappers.observables import observable_from_value
from connectors_sdk.models import (
    URL,
    BaseIdentifiedEntity,
    Country,
    ExternalReference,
    IntrusionSet,
    Malware,
    Organization,
    OrganizationAuthor,
    Report,
    TLPMarking,
    Vulnerability,
)
from connectors_sdk.models.enums import ReportType, TLPLevel
from cyble_client.engine_dates import parse_engine_datetime

_SKIP_PLACES = {"", "worldwide", "global", "multiple", "n/a", "na"}


def map_advisory(
    item: dict[str, Any],
    author: OrganizationAuthor,
    default_marking: TLPMarking,
) -> list[BaseIdentifiedEntity]:
    """Map one advisory catalog card to a Report."""
    advisory_id = item.get("id")
    title = first_text(item.get("title"), f"Cyble advisory {advisory_id}")
    published = parse_engine_datetime(item.get("publish_date"))
    if published is None:
        raise ValueError(f"advisory {advisory_id} has no publish_date")

    tags = item.get("tags") if isinstance(item.get("tags"), dict) else {}
    labels = _labels("advisory", item.get("risk_score"), tags.get("customTags"))
    labels += _place_labels(tags.get("industries"), prefix="industry")
    marking = _tlp_marking(item.get("tlp_rating"), default_marking)
    reference = ExternalReference(
        source_name="Cyble Vision Advisory",
        external_id=f"advisory:{advisory_id}",
        description=title,
    )
    description = "\n".join(
        part
        for part in (
            labeled("Risk", item.get("risk_score")),
            labeled("TLP", item.get("tlp_rating")),
            labeled("Industries", _join(tags.get("industries"))),
            labeled("Countries", _join(tags.get("countries"))),
            labeled("Tags", _join(tags.get("customTags"))),
        )
        if part
    )
    related = _countries(tags.get("countries"), author, marking)
    report = Report(
        name=title or f"Cyble advisory {advisory_id}",
        description=description or None,
        publication_date=published,
        report_types=[ReportType.THREAT_REPORT],
        objects=related or None,
        author=author,
        markings=[marking],
        labels=labels,
        external_references=[reference],
        created=published,
    )
    return [report, *related]


def map_newsfeed(
    item: dict[str, Any],
    author: OrganizationAuthor,
    default_marking: TLPMarking,
) -> list[BaseIdentifiedEntity]:
    """Map one newsfeed article to a Report plus related objects."""
    title = first_text(item.get("post_title"))
    published = parse_engine_datetime(item.get("post_date")) or parse_engine_datetime(
        item.get("created_at")
    )
    if not title or published is None:
        raise ValueError("newsfeed item needs post_title and post_date")

    post_url = first_text(item.get("post_url"))
    source = (
        item.get("post_source") if isinstance(item.get("post_source"), dict) else {}
    )
    labels = _labels("newsfeed", item.get("news_feed_type"), item.get("tags"))
    labels += _place_labels(item.get("industries"), prefix="industry")
    reference = ExternalReference(
        source_name="Cyble Vision Newsfeed",
        url=post_url,
        external_id=post_url or title,
        description=first_text(source.get("name")),
    )
    description = first_text(item.get("ai_summary"), item.get("post_description"))
    related: list[BaseIdentifiedEntity] = []
    if post_url:
        related.append(
            URL(
                value=post_url,
                author=author,
                markings=[default_marking],
                external_references=[reference],
            )
        )
    related.extend(_actors(item.get("threat_actors"), author, default_marking))
    related.extend(_malware(item.get("malwares"), author, default_marking))
    related.extend(_cves(item.get("cves"), author, default_marking))
    for ioc in item.get("iocs") or []:
        observable = observable_from_value(ioc, _SimpleContext(author, default_marking))
        if observable:
            related.append(observable)
    related.extend(_countries(item.get("countries"), author, default_marking))

    report = Report(
        name=title,
        description=description,
        publication_date=published,
        report_types=[ReportType.INTELLIGENCE_SUMMARY],
        objects=related or None,
        author=author,
        markings=[default_marking],
        labels=labels,
        external_references=[reference],
        created=published,
    )
    return [report, *related]


def map_newsflash(
    item: dict[str, Any],
    author: OrganizationAuthor,
    default_marking: TLPMarking,
) -> list[BaseIdentifiedEntity]:
    """Map one newsflash item to a spot Report plus related objects."""
    title = first_text(item.get("title"))
    published = parse_engine_datetime(item.get("publishedDate"))
    if not title or published is None:
        raise ValueError("newsflash item needs title and publishedDate")

    external_id = f"{title}|{item.get('publishedDate')}"
    labels = _labels("newsflash", None, item.get("tags"))
    labels += _place_labels(item.get("industryTypes"), prefix="industry")
    refs = [
        ExternalReference(
            source_name="Cyble Vision Newsflash",
            external_id=external_id,
            description=title,
        )
    ]
    extra = item.get("extraFields")
    if isinstance(extra, dict):
        for label, url in extra.items():
            if first_text(url) and str(url).startswith("http"):
                refs.append(
                    ExternalReference(
                        source_name=str(label),
                        url=str(url),
                        external_id=str(url),
                    )
                )

    related: list[BaseIdentifiedEntity] = []
    related.extend(_actors([item.get("threatActorHandle")], author, default_marking))
    for name in item.get("impactedOrganizations") or []:
        cleaned = first_text(name)
        if cleaned and len(cleaned) >= 3:
            related.append(
                Organization(
                    name=cleaned,
                    author=author,
                    markings=[default_marking],
                )
            )
    for website in item.get("relatedWebsites") or []:
        observable = observable_from_value(
            website, _SimpleContext(author, default_marking)
        )
        if observable:
            related.append(observable)
    related.extend(_countries(item.get("impactedCountries"), author, default_marking))

    report = Report(
        name=title,
        description=first_text(item.get("summaryOfThreatActivity")),
        publication_date=published,
        report_types=[ReportType.SPOTREP],
        objects=related or None,
        author=author,
        markings=[default_marking],
        labels=labels,
        external_references=refs,
        created=published,
    )
    return [report, *related]


class _SimpleContext:
    """Minimal context so observable_from_value can reuse alert helpers."""

    def __init__(self, author: OrganizationAuthor, marking: TLPMarking) -> None:
        self.author = author
        self.markings = [marking]
        self.external_references: list[ExternalReference] = []

    def observable_kwargs(self) -> dict[str, Any]:
        return {
            "author": self.author,
            "markings": self.markings,
            "external_references": self.external_references or None,
        }


def _labels(product: str, extra: Any, tags: Any) -> list[str]:
    labels = ["cyble", f"cyble:engine:{product}"]
    if first_text(extra):
        labels.append(str(extra).strip().lower().replace(" ", "-"))
    for tag in tags or []:
        if first_text(tag):
            labels.append(str(tag).strip())
    return labels


def _place_labels(values: Any, prefix: str) -> list[str]:
    labels = []
    for value in values or []:
        text = first_text(value)
        if text and text.lower() not in _SKIP_PLACES:
            labels.append(f"{prefix}:{text}")
    return labels


def _join(values: Any) -> str | None:
    parts = [str(value).strip() for value in (values or []) if first_text(value)]
    return ", ".join(parts) if parts else None


def _tlp_marking(raw: Any, default: TLPMarking) -> TLPMarking:
    text = first_text(raw)
    if not text:
        return default
    level = text.split(":")[-1].strip().lower()
    try:
        return TLPMarking(level=TLPLevel(level))
    except ValueError:
        return default


def _actors(
    names: Any, author: OrganizationAuthor, marking: TLPMarking
) -> list[BaseIdentifiedEntity]:
    objects = []
    for name in names or []:
        text = first_text(name)
        if text:
            objects.append(IntrusionSet(name=text, author=author, markings=[marking]))
    return objects


def _malware(
    names: Any, author: OrganizationAuthor, marking: TLPMarking
) -> list[BaseIdentifiedEntity]:
    objects = []
    for name in names or []:
        text = first_text(name)
        if text:
            objects.append(
                Malware(name=text, is_family=True, author=author, markings=[marking])
            )
    return objects


def _cves(
    names: Any, author: OrganizationAuthor, marking: TLPMarking
) -> list[BaseIdentifiedEntity]:
    objects = []
    for name in names or []:
        text = first_text(name)
        if text:
            objects.append(Vulnerability(name=text, author=author, markings=[marking]))
    return objects


def _countries(
    names: Any, author: OrganizationAuthor, marking: TLPMarking
) -> list[BaseIdentifiedEntity]:
    objects = []
    for name in names or []:
        text = first_text(name)
        if text and text.lower() not in _SKIP_PLACES:
            objects.append(Country(name=text, author=author, markings=[marking]))
    return objects


def checkpoint_value(item: dict[str, Any], *keys: str) -> str | None:
    """Return the latest parseable timestamp among the given keys, as ISO."""
    latest: datetime | None = None
    for key in keys:
        parsed = parse_engine_datetime(item.get(key))
        if parsed and (latest is None or parsed > latest):
            latest = parsed
    if latest is None:
        return None
    if latest.tzinfo is None:
        latest = latest.replace(tzinfo=timezone.utc)
    return latest.isoformat()
