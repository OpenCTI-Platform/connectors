# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike related actor normalization helper."""

from typing import Any, Dict, List, Optional, cast

from crowdstrike_feeds_services.client.actors import ActorsAPI
from pycti.connector.opencti_connector_helper import (
    OpenCTIConnectorHelper,
)


class RelatedActorImporter:
    """CrowdStrike actor importer."""

    _resolved_actor_entity_cache: Dict[str, Dict[str, Any]] = {}
    _NAME = "Actor"

    _LATEST_ACTOR_TIMESTAMP = "latest_actor_timestamp"

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
    ) -> None:
        """Initialize CrowdStrike actor normalization helper."""
        self.helper = helper
        self.actors_api_cs = ActorsAPI(helper)

    def _process_related_actors(
        self, orig_entity_id: Any, related_actors: List[str]
    ) -> List[Dict[str, Any]]:
        if not related_actors:
            return []

        # Determine which tokens we still need to resolve.
        uncached_tokens = [
            t
            for t in related_actors
            if t and t not in RelatedActorImporter._resolved_actor_entity_cache
        ]

        unresolved: List[str] = []

        if uncached_tokens:
            try:
                for raw_actor in uncached_tokens:
                    safe = str(raw_actor).replace("'", "\\'")
                    # Use name-only filter (validated to work best for ALLCAPS tokens like WICKEDPANDA)
                    fql_filter = f"(name:'{safe}')"

                    response: Optional[Dict[str, Any]] = self.actors_api_cs.get_combined_actor_entities(
                        fql_filter=fql_filter,
                        limit=100,
                        offset=0,
                        sort="created_date|desc",
                        fields="__full__",
                    )
                    response_dict: Dict[str, Any] = response or {}
                    actors_data = cast(List[Dict[str, Any]], response_dict.get("resources", []))

                    if not actors_data:
                        unresolved.append(raw_actor)
                        continue

                    # Prefer an exact name match when possible; otherwise keep the most recent result.
                    raw_upper = str(raw_actor).upper()
                    best: Dict[str, Any] = actors_data[0]
                    for a in actors_data:
                        name = str(a.get("name") or "").upper()
                        slug = str(a.get("slug") or "").upper()
                        if name == raw_upper or slug == raw_upper:
                            best = a
                            break

                    # Cache by the raw token, plus any other stable identifiers.
                    RelatedActorImporter._resolved_actor_entity_cache[raw_actor] = best
                    best_name = best.get("name")
                    best_slug = best.get("slug")
                    if isinstance(best_name, str) and best_name:
                        RelatedActorImporter._resolved_actor_entity_cache[best_name] = best
                    if isinstance(best_slug, str) and best_slug:
                        RelatedActorImporter._resolved_actor_entity_cache[best_slug] = best

            except Exception as err:
                # If resolution fails, do not emit raw tokens as names because it can create incorrectly named
                # Intrusion Sets (e.g. LABYRINTHCHOLLIMA). Instead, log and skip unresolved values.
                self.helper.connector_logger.warning(
                    "Failed to resolve related actors; skipping unresolved values.",
                    {
                        "orig_entity_id": orig_entity_id,
                        "error": str(err),
                    },
                )
                unresolved.extend([t for t in uncached_tokens if t])

        # Build final list of resolved actor entities (dicts only)
        resolved_entities: List[Dict[str, Any]] = []
        for token in related_actors:
            if not token:
                continue
            entity = RelatedActorImporter._resolved_actor_entity_cache.get(token)
            if isinstance(entity, dict) and entity:
                resolved_entities.append(entity)
            else:
                unresolved.append(token)

        if unresolved:
            # Keep the list reasonably sized in logs.
            unique_unresolved = sorted(set(unresolved))
            self.helper.connector_logger.warning(
                "Some related actors could not be resolved; skipping.",
                {
                    "orig_entity_id": orig_entity_id,
                    "unresolved_actors": unique_unresolved[:25],
                    "unresolved_count": len(unique_unresolved),
                },
            )

        return resolved_entities

