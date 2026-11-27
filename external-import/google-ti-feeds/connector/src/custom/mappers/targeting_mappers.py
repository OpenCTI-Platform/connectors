"""Countries and sectors a GTI collection targets or comes from, shared by the collections.

Threat actors, malware families, campaigns and software toolkits describe their
targets with the same GTI fields (`targeted_regions_hierarchy`,
`source_regions_hierarchy`, `targeted_industries_tree`). These base mappers turn
them into Country locations and Sector identities, with the GTI dates, confidence,
source and note of each association (see `timing_models`). A collection mapper only
sets its `entity_label` and keeps its own constructor and attribute name.

The same country or sector listed several times for one entity is merged into one
object: earliest first seen, latest last seen, every distinct confidence, source and
note kept.
"""

from collections.abc import Callable, Hashable
from datetime import datetime, timezone
from typing import Any, ClassVar, TypeVar

from connector.src.custom.mappers.relationship_reasons import targeting_reason
from connector.src.custom.mappers.timing_models import (
    IdentityWithTiming,
    LocationWithTiming,
)
from connector.src.stix.octi.models.identity_sector_model import OctiIdentitySectorModel
from connector.src.stix.octi.models.location_model import OctiLocationModel
from connector.src.stix.octi.models.relationship_model import OctiRelationshipModel
from connector.src.utils.converters.generic_converter_config import BaseMapper
from connectors_sdk.models import (  # type: ignore[import-untyped]
    OrganizationAuthor,
    TLPMarking,
)
from stix2.v21 import Identity, Location  # type: ignore

TimingT = TypeVar("TimingT", LocationWithTiming, IdentityWithTiming)


def entity_alias(doc: str) -> Any:
    """Return a property naming the converted entity, e.g. `threat_actor`."""
    return property(
        lambda self: self.entity,
        lambda self, value: setattr(self, "entity", value),
        doc=doc,
    )


def seen_dates(
    first_seen: int | None, last_seen: int | None
) -> tuple[datetime | None, datetime | None]:
    """Return the GTI first and last seen timestamps as dates.

    The last seen date is dropped when not after the first seen date: a relationship
    stop time must be later than its start time.
    """
    first = datetime.fromtimestamp(first_seen, tz=timezone.utc) if first_seen else None
    last = datetime.fromtimestamp(last_seen, tz=timezone.utc) if last_seen else None
    if first and last and last <= first:
        last = None
    return first, last


def _join_distinct(values: list[str | None]) -> str | None:
    """Join the distinct non-empty values in order, or None."""
    distinct = list(
        dict.fromkeys(value.strip() for value in values if value and value.strip())
    )
    return "; ".join(distinct) or None


def merge_duplicates(
    items: list[TimingT], key: Callable[[TimingT], Hashable]
) -> list[TimingT]:
    """Merge the items with the same key, keeping the first occurrence order.

    Dates span the earliest first seen to the latest last seen. Distinct confidences,
    sources and notes are joined with '; '. Notes are prefixed with their subject
    (e.g. the industry of a sector) when several are merged.
    """
    groups: dict[Hashable, list[TimingT]] = {}
    for item in items:
        groups.setdefault(key(item), []).append(item)

    merged = []
    for group in groups.values():
        if len(group) == 1:
            merged.append(group[0])
            continue
        first_dates = [item.first_seen for item in group if item.first_seen]
        last_dates = [item.last_seen for item in group if item.last_seen]
        first_seen = min(first_dates) if first_dates else None
        last_seen = max(last_dates) if last_dates else None
        if first_seen and last_seen and last_seen <= first_seen:
            last_seen = None
        notes = [
            f"{item.subject}: {item.note}" if item.subject and item.note else item.note
            for item in group
        ]
        merged.append(
            group[0].model_copy(
                update={
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "confidence": _join_distinct([item.confidence for item in group]),
                    "source": _join_distinct([item.source for item in group]),
                    "note": _join_distinct(notes),
                }
            )
        )
    return merged


def targeting_relationships(
    source: Any,
    locations: list[LocationWithTiming],
    sectors: list[IdentityWithTiming],
    organization_id: str,
    marking_ids: list[str],
    created: datetime,
    modified: datetime,
) -> list[Any]:
    """Return the relationships from an entity to the countries and sectors GTI lists.

    'targets' to the targeted countries and sectors, 'originates-from' to the source
    countries, with the GTI dates as start and stop times and the GTI confidence,
    source and note as description (see `targeting_reason`).

    Args:
        source: The intrusion set, malware, campaign or tool.
        locations: Countries of the entity, see `BaseCountryMapper`.
        sectors: Sectors of the entity, see `BaseSectorMapper`.
        organization_id: The author of the relationships.
        marking_ids: The markings of the relationships.
        created: Creation date of the relationships.
        modified: Modification date of the relationships.

    """
    links: list[tuple[str, Any, LocationWithTiming | IdentityWithTiming]] = [
        ("targets", item.location, item) for item in locations if item.is_targeted
    ]
    links += [
        ("originates-from", item.location, item) for item in locations if item.is_source
    ]
    links += [("targets", item.identity, item) for item in sectors]
    return [
        OctiRelationshipModel.create(
            relationship_type=relationship_type,
            source_ref=source.id,
            target_ref=target.id,
            organization_id=organization_id,
            marking_ids=marking_ids,
            created=created,
            modified=modified,
            start_time=timing.first_seen,
            stop_time=timing.last_seen,
            description=targeting_reason(source, relationship_type, target, timing),
        )
        for relationship_type, target, timing in links
    ]


class _TargetingMapper(BaseMapper):
    """Base of the country and sector mappers: entity, author and marking."""

    # Entity name in error messages, e.g. "threat actor".
    entity_label: ClassVar[str]

    def __init__(
        self,
        entity: Any,
        organization: OrganizationAuthor,
        tlp_marking: TLPMarking,
    ) -> None:
        """Initialize the mapper.

        Args:
            entity: The GTI collection data to convert.
            organization: The organization identity object.
            tlp_marking: The TLP marking definition.

        """
        self.entity = entity
        self.organization = organization
        self.tlp_marking = tlp_marking

    def _attributes(self) -> Any:
        """Return the entity attributes.

        Raises:
            ValueError: If the entity has no attributes.

        """
        attributes = getattr(self.entity, "attributes", None)
        if not attributes:
            raise ValueError(f"Invalid {self.entity_label} attributes")
        return attributes


class BaseCountryMapper(_TargetingMapper):
    """Convert the targeted and source regions of a GTI collection to countries."""

    def to_stix(self) -> list[Location]:
        """Return the countries (targeted and source) as STIX Location objects."""
        return [item.location for item in self.to_stix_with_timing()]

    def to_stix_with_timing(self) -> list[LocationWithTiming]:
        """Return the countries with how GTI associated them with the entity.

        Raises:
            ValueError: If the entity has no attributes.

        """
        attributes = self._attributes()
        result = [
            country
            for region in getattr(attributes, "targeted_regions_hierarchy", None) or []
            if (country := self._create_country_from_targeted_with_timing(region))
        ]
        result += [
            country
            for region in getattr(attributes, "source_regions_hierarchy", None) or []
            if (country := self._create_country_from_source_with_timing(region))
        ]
        return merge_duplicates(
            result, key=lambda item: (item.location.id, item.is_targeted)
        )

    def _create_country_with_timing(
        self, region_data: Any, is_targeted: bool, is_source: bool
    ) -> LocationWithTiming | None:
        """Return the country of a GTI region, or None for a region without country."""
        if not region_data.country or not region_data.country_iso2:
            return None
        country = OctiLocationModel.create_country(
            name=region_data.country,
            country_code=region_data.country_iso2,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
        )
        first_seen, last_seen = seen_dates(
            region_data.first_seen, region_data.last_seen
        )
        return LocationWithTiming(
            location=country.to_stix2_object(),
            confidence=region_data.confidence,
            note=region_data.description,
            source=region_data.source,
            first_seen=first_seen,
            last_seen=last_seen,
            is_targeted=is_targeted,
            is_source=is_source,
        )

    def _create_country_from_targeted_with_timing(
        self, region_data: Any
    ) -> LocationWithTiming | None:
        """Return the country of a targeted region."""
        return self._create_country_with_timing(region_data, True, False)

    def _create_country_from_source_with_timing(
        self, region_data: Any
    ) -> LocationWithTiming | None:
        """Return the country of a source region."""
        return self._create_country_with_timing(region_data, False, True)

    def _create_country_from_targeted(self, region_data: Any) -> Location | None:
        """Return the STIX country of a targeted region."""
        country = self._create_country_from_targeted_with_timing(region_data)
        return country.location if country else None

    def _create_country_from_source(self, region_data: Any) -> Location | None:
        """Return the STIX country of a source region."""
        country = self._create_country_from_source_with_timing(region_data)
        return country.location if country else None


class BaseSectorMapper(_TargetingMapper):
    """Convert the targeted industries of a GTI collection to sectors."""

    def to_stix(self) -> list[Identity]:
        """Return the targeted sectors as STIX Identity objects."""
        return [item.identity for item in self.to_stix_with_timing()]

    def to_stix_with_timing(self) -> list[IdentityWithTiming]:
        """Return the targeted sectors with how GTI associated them with the entity.

        Raises:
            ValueError: If the entity has no attributes.

        """
        attributes = self._attributes()
        result = [
            sector
            for industry in getattr(attributes, "targeted_industries_tree", None) or []
            if (sector := self._process_industry_with_timing(industry))
        ]
        return merge_duplicates(result, key=lambda item: item.identity.id)

    @staticmethod
    def _sector_name(industry_data: Any) -> str | None:
        """Return the sector name: the GTI industry group, or None without group.

        The industry alone is not used: GTI industries (e.g. 'Banking') are finer
        than the OpenCTI sectors, and would create sectors outside the standard set.
        """
        group = industry_data.industry_group
        return str(group.strip()) if group and group.strip() else None

    def _create_sector_with_timing(self, industry_data: Any) -> IdentityWithTiming:
        """Return the sector of a GTI targeted industry.

        Raises:
            ValueError: If the industry has no group nor industry name.

        """
        name = self._sector_name(industry_data)
        if name is None:
            raise ValueError("Targeted industry without name")
        sector = OctiIdentitySectorModel.create(
            name=name,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
        )
        first_seen, last_seen = seen_dates(
            industry_data.first_seen, industry_data.last_seen
        )
        industry = (industry_data.industry or "").strip()
        return IdentityWithTiming(
            identity=sector.to_stix2_object(),
            confidence=industry_data.confidence,
            note=industry_data.description,
            source=industry_data.source,
            subject=industry if industry and industry != name else None,
            first_seen=first_seen,
            last_seen=last_seen,
        )

    def _process_industry_with_timing(
        self, industry_data: Any
    ) -> IdentityWithTiming | None:
        """Return the sector of a GTI targeted industry, or None without name."""
        if self._sector_name(industry_data) is None:
            return None
        return self._create_sector_with_timing(industry_data)

    def _process_industry(self, industry_data: Any) -> Identity | None:
        """Return the STIX sector of a GTI targeted industry, or None without name."""
        sector = self._process_industry_with_timing(industry_data)
        return sector.identity if sector else None

    def _create_sector(self, industry_data: Any) -> Identity:
        """Return the STIX sector of a GTI targeted industry."""
        return self._create_sector_with_timing(industry_data).identity
