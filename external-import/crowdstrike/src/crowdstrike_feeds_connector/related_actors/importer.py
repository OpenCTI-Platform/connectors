# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike related actor normalization helper."""

from typing import Any, Dict, List, Optional

from crowdstrike_feeds_services.client.actors import ActorsAPI
from stix2 import Identity, MarkingDefinition

from pycti.connector.opencti_connector_helper import (
    OpenCTIConnectorHelper,
)  # noqa: E501 # isort: skip


class RelatedActorImporter:
    """CrowdStrike actor importer."""

    _resolved_actor_name_cache: Dict[str, str] = {}
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
    ) -> List[str]:
        # Normalize CrowdStrike actor tokens to stable human-readable names before building the bundle.
        # Indicators frequently contain actor values as strings (internal tokens / slugs). We only
        # normalize the names for stable Intrusion Set creation; the Actor feed/enrichment owns the full profile.
        if related_actors:
            uncached_tokens = [
                t
                for t in related_actors
                if t and t not in RelatedActorImporter._resolved_actor_name_cache
            ]

            if uncached_tokens:
                try:
                    for raw_actor in uncached_tokens:
                        safe = str(raw_actor).replace("'", "\\'")
                        # Use name-only filter (validated to work best for ALLCAPS tokens like WICKEDPANDA)
                        fql_filter = f"(name:'{safe}')"

                        response: Optional[Dict[str, Any]] = (
                            self.actors_api_cs.get_combined_actor_entities(
                                fql_filter=fql_filter,
                                limit=100,
                                offset=0,
                                sort="created_date|desc",
                                fields="__full__",
                            )
                        )
                        response_dict: Dict[str, Any] = response or {}
                        actors_data = response_dict.get("resources", [])

                        for actor in actors_data:
                            slug = actor.get("slug")
                            name = actor.get("name")
                            if name:
                                RelatedActorImporter._resolved_actor_name_cache[
                                    raw_actor
                                ] = name
                                if slug:
                                    RelatedActorImporter._resolved_actor_name_cache[
                                        slug
                                    ] = name

                except Exception as err:
                    self.helper.connector_logger.warning(
                        f"Failed to normalize related actors; using raw values. orig_entity_id={orig_entity_id} {err}",
                    )
                    for token in uncached_tokens:
                        RelatedActorImporter._resolved_actor_name_cache[token] = token

            related_actors = [
                RelatedActorImporter._resolved_actor_name_cache.get(token, token)
                for token in related_actors
                if token
            ]
        return related_actors
