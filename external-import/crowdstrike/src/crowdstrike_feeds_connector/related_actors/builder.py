# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike related actors builder module."""

import logging
from crowdstrike_feeds_services.utils import (
    create_external_reference,
    create_intrusion_set,
    create_originates_from_relationships,
    create_regions_and_countries_from_entities,
    create_sectors_from_entities,
    create_targets_relationships,
    create_uses_relationships,
    normalize_start_time_and_stop_time,
    remove_html_tags,
    timestamp_to_datetime,
)
from typing import Any, List, Mapping, Optional
from stix2 import Identity  # type: ignore
from stix2 import (
    AttackPattern,
    Bundle,
    ExternalReference,
    IntrusionSet,
    Location,
    MarkingDefinition,
    Relationship,
)
from stix2.v21 import _DomainObject

logger = logging.getLogger(__name__)


class RelatedActorBundleBuilder:
    """CrowdStrike related actor bundle builder."""

    """Actor bundle builder."""

    def __init__(
        self,
        actor: dict,
        author: Identity,
        source_name: str,
        object_markings: List[MarkingDefinition],
        confidence_level: int,
        attack_patterns: Optional[List] = None,
    ) -> None:
        """Initialize actor bundle builder."""
        self.actor = actor
        self.author = author
        self.source_name = source_name
        self.object_markings = object_markings
        self.confidence_level = confidence_level
        self.attack_patterns = attack_patterns or []

        first_seen = timestamp_to_datetime(self.actor["first_activity_date"])
        last_seen = timestamp_to_datetime(self.actor["last_activity_date"])

        first_seen, last_seen = normalize_start_time_and_stop_time(
            first_seen, last_seen
        )

        self.first_seen = first_seen
        self.last_seen = last_seen

    def _create_intrusion_set_from_actor_entity(
        self,
        actor: Mapping[str, Any],
        created_by: Optional[Identity] = None,
        confidence: Optional[int] = None,
        object_markings: Optional[List[MarkingDefinition]] = None,
    ) -> IntrusionSet:
        """
        Create a STIX IntrusionSet from a CrowdStrike actor entity.

        Expects a full actor resource as returned by the Intel API.
        """
        # Name / slug
        name = actor.get("name")
        if not name:
            raise ValueError("Actor entity is missing both 'name'")

        # Description
        description = actor.get("description") or actor.get("short_description")

        # First / last seen (CrowdStrike gives Unix timestamps)
        first_seen = None
        last_seen = None

        first_activity_ts = actor.get("first_activity_date")
        if isinstance(first_activity_ts, int) and first_activity_ts > 0:
            first_seen = timestamp_to_datetime(first_activity_ts)

        last_activity_ts = actor.get("last_activity_date")
        if isinstance(last_activity_ts, int) and last_activity_ts > 0:
            last_seen = timestamp_to_datetime(last_activity_ts)

        # Aliases
        # CrowdStrike uses "known_as" as a comma-separated string of aliases, e.g.:
        # "Sality, KuKu, SalLoad, Kookoo, SaliCode, Kukacka"
        # It may also provide a list in "aliases". Normalize everything into a clean list.
        raw_aliases = actor.get("aliases") or actor.get("known_as") or []
        aliases: List[str] = []

        if isinstance(raw_aliases, str):
            # Split comma-separated string and trim whitespace
            for alias in raw_aliases.split(","):
                alias_clean = alias.strip()
                if alias_clean:
                    aliases.append(alias_clean)
        elif isinstance(raw_aliases, list):
            for alias_entry in raw_aliases:
                if isinstance(alias_entry, str):
                    alias_clean = alias_entry.strip()
                elif isinstance(alias_entry, Mapping):
                    alias_clean = str(
                        alias_entry.get("value")
                        or alias_entry.get("name")
                        or alias_entry.get("slug")
                        or ""
                    ).strip()
                else:
                    alias_clean = ""

                if alias_clean:
                    aliases.append(alias_clean)

        # Also add a compact alias without spaces (e.g. "SALTY SPIDER" -> "SALTYSPIDER")
        if isinstance(name, str):
            compact = name.replace(" ", "")
            if compact and compact != name and compact not in aliases:
                aliases.append(compact)

        # Deduplicate while preserving order
        seen_aliases = set()
        deduped_aliases: List[str] = []
        for alias in aliases:
            if alias not in seen_aliases and alias != name:
                seen_aliases.add(alias)
                deduped_aliases.append(alias)
        aliases = deduped_aliases

        # Motivations
        # CrowdStrike 'motivations' is a list of objects, e.g.:
        # [{"id": 1001485, "slug": "state-sponsored", "value": "State-Sponsored"}, ...]
        # STIX IntrusionSet expects a single primary_motivation string and an optional list
        # of secondary_motivations, so we derive those from the list.
        motivations_raw = actor.get("motivations") or []
        primary_motivation = None
        secondary_motivations: Optional[List[str]] = None

        if isinstance(motivations_raw, list) and motivations_raw:
            # Use the first motivation as primary
            first = motivations_raw[0]
            primary_motivation = (
                first.get("value") or first.get("slug") or ""
            ).strip() or None

            # Any additional motivations become secondary
            if len(motivations_raw) > 1:
                secondary_values: List[str] = []
                for mot in motivations_raw[1:]:
                    val = (mot.get("value") or mot.get("slug") or "").strip()
                    if val:
                        secondary_values.append(val)
                if secondary_values:
                    secondary_motivations = secondary_values
        logger.debug(
            "Mapped CrowdStrike actor to IntrusionSet motivations and aliases",
            {
                "actor_id": actor.get("id"),
                "actor_name": name,
                "motivations_raw": motivations_raw,
                "primary_motivation": primary_motivation,
                "secondary_motivations": secondary_motivations,
                "aliases": aliases,
            },
        )

        # Goals (map CrowdStrike 'objectives' to STIX goals)
        goals_raw = actor.get("objectives") or []
        goals: Optional[List[str]] = None

        if isinstance(goals_raw, list) and goals_raw:
            goal_values: List[str] = []
            for obj in goals_raw:
                val = (obj.get("value") or obj.get("slug") or "").strip()
                if val:
                    goal_values.append(val)
            if goal_values:
                goals = goal_values

        # External reference back to CrowdStrike
        external_references: List[ExternalReference] = []
        cs_id = str(actor.get("id") or "")
        url = actor.get("url")
        if cs_id and url:
            external_references.append(
                create_external_reference(
                    "CrowdStrike Intel",
                    cs_id,
                    url,
                )
            )

        return create_intrusion_set(
            name,
            created_by=created_by,
            description=description,
            aliases=aliases or None,
            first_seen=first_seen,
            last_seen=last_seen,
            goals=goals or None,
            primary_motivation=primary_motivation,
            secondary_motivations=secondary_motivations or None,
            confidence=confidence,
            external_references=external_references or None,
            object_markings=object_markings,
        )
