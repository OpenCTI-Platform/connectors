# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike related actors builder module."""

import logging
from collections.abc import Mapping
from typing import Any, cast

from crowdstrike_feeds_services.utils import (
    create_external_reference,
    create_intrusion_set,
    normalize_start_time_and_stop_time,
    timestamp_to_datetime,
)
from stix2 import (
    AttackPattern,
    ExternalReference,
    Identity,
    IntrusionSet,
    MarkingDefinition,
)

logger = logging.getLogger(__name__)


class RelatedActorBundleBuilder:
    """CrowdStrike related actor bundle builder."""

    def __init__(
        self,
        actor: Any,
        author: Identity,
        source_name: str,
        object_markings: list[MarkingDefinition],
        confidence_level: int,
        attack_patterns: list[AttackPattern] | None = None,
    ) -> None:
        """Initialize actor bundle builder."""
        if isinstance(actor, str):
            self.actor: Mapping[str, Any] = {"name": actor}
        elif isinstance(actor, Mapping):
            self.actor = cast(Mapping[str, Any], actor)
        else:
            self.actor = cast(Any, actor)
        self.author = author
        self.source_name = source_name
        self.object_markings = object_markings
        self.confidence_level = confidence_level
        self.attack_patterns = attack_patterns or []

    def build(self) -> list[IntrusionSet]:
        """Build and return IntrusionSets for the provided actor entity."""
        actor = self.actor

        # Normalize string actor entries defensively
        if isinstance(actor, str):
            actor = {"name": actor}

        if not isinstance(actor, Mapping):
            logger.warning(
                "Skipping unresolved actor entry (expected mapping or string)",
                {"actor_entry_type": type(actor).__name__, "actor_entry": actor},
            )
            return []

        intrusion_set = self._create_intrusion_set_from_actor_entity(
            cast(Mapping[str, Any], actor),
            created_by=self.author,
            confidence=self.confidence_level,
            object_markings=self.object_markings,
        )

        if self.attack_patterns:
            logger.debug(
                "RelatedActorBundleBuilder received attack_patterns but does not yet create relationships",
                {"count": len(self.attack_patterns)},
            )

        return [intrusion_set]

    def _normalize_aliases(self, name: str, actor: Mapping[str, Any]) -> list[str]:
        """Normalize CrowdStrike actor aliases into a clean, deduplicated list."""
        raw_aliases = actor.get("aliases") or actor.get("known_as") or []

        aliases: list[str] = []

        if isinstance(raw_aliases, str):
            aliases.extend(self._split_alias_string(raw_aliases))
        elif isinstance(raw_aliases, list):
            for alias_entry in raw_aliases:
                alias_clean = self._alias_from_entry(alias_entry)
                if alias_clean:
                    aliases.append(alias_clean)

        # Also add a compact alias without spaces (e.g. "SALTY SPIDER" -> "SALTYSPIDER")
        compact = name.replace(" ", "")
        if compact and compact != name and compact not in aliases:
            aliases.append(compact)

        return self._dedupe_aliases(name, aliases)

    def _split_alias_string(self, raw: str) -> list[str]:
        """Split a comma-separated alias string and trim whitespace."""
        out: list[str] = []
        for alias in raw.split(","):
            alias_clean = alias.strip()
            if alias_clean:
                out.append(alias_clean)
        return out

    def _alias_from_entry(self, entry: Any) -> str:
        """Extract a single alias string from a list entry."""
        if isinstance(entry, str):
            return entry.strip()
        if isinstance(entry, Mapping):
            return str(
                entry.get("value") or entry.get("name") or entry.get("slug") or ""
            ).strip()
        return ""

    def _dedupe_aliases(self, name: str, aliases: list[str]) -> list[str]:
        """Deduplicate aliases while preserving order and excluding the primary name."""
        seen: set[str] = set()
        out: list[str] = []
        for alias in aliases:
            if alias and alias != name and alias not in seen:
                seen.add(alias)
                out.append(alias)
        return out

    def _create_intrusion_set_from_actor_entity(
        self,
        actor: Any,
        created_by: Identity | None = None,
        confidence: int | None = None,
        object_markings: list[MarkingDefinition] | None = None,
    ) -> IntrusionSet:
        """
        Create a STIX IntrusionSet from a CrowdStrike actor entity.

        Expects a full actor resource as returned by the Intel API.
        """
        # Defensive normalization: actor may be a plain string (name/slug)
        if isinstance(actor, str):
            actor = {"name": actor}
        if not isinstance(actor, Mapping):
            raise TypeError(
                f"Expected actor mapping or string, got {type(actor).__name__}"
            )

        # Name
        name = actor.get("name") or ""
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

        # If only one of the two exists, set both (STIX first_seen/last_seen are expected as a pair)
        if first_seen is not None or last_seen is not None:
            if first_seen is None:
                first_seen = last_seen
            if last_seen is None:
                last_seen = first_seen

            assert first_seen is not None and last_seen is not None
            first_seen, last_seen = normalize_start_time_and_stop_time(
                first_seen, last_seen
            )

        # Aliases
        aliases = self._normalize_aliases(str(name), actor)

        # Motivations
        # CrowdStrike 'motivations' is a list of objects, e.g.:
        # [{"id": 1001485, "slug": "state-sponsored", "value": "State-Sponsored"}, ...]
        # STIX IntrusionSet expects a single primary_motivation string and an optional list
        # of secondary_motivations, so we derive those from the list.
        motivations_raw = actor.get("motivations") or []
        primary_motivation = None
        secondary_motivations: list[str] | None = None

        if isinstance(motivations_raw, list) and motivations_raw:
            # Use the first motivation as primary
            first = motivations_raw[0]
            if isinstance(first, Mapping):
                primary_motivation = (
                    str(first.get("value") or first.get("slug") or "").strip()
                ) or None
            else:
                primary_motivation = str(first).strip() or None

            # Any additional motivations become secondary
            if len(motivations_raw) > 1:
                secondary_values: list[str] = []
                for mot in motivations_raw[1:]:
                    if isinstance(mot, Mapping):
                        val = str(mot.get("value") or mot.get("slug") or "").strip()
                    else:
                        val = str(mot).strip()
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
        goals: list[str] | None = None

        if isinstance(goals_raw, list) and goals_raw:
            goal_values: list[str] = []
            for obj in goals_raw:
                if isinstance(obj, Mapping):
                    val = str(obj.get("value") or obj.get("slug") or "").strip()
                else:
                    val = str(obj).strip()
                if val:
                    goal_values.append(val)
            if goal_values:
                goals = goal_values

        # External reference back to CrowdStrike
        external_references: list[ExternalReference] = []
        cs_id = str(actor.get("id") or "")
        url = actor.get("url")
        if cs_id and url:
            external_references.append(
                create_external_reference(
                    self.source_name,
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
