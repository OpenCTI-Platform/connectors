# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike actor importer module."""

from datetime import datetime
from typing import Any, Dict, Generator, List, Optional

from crowdstrike_feeds_connector.related_actors.importer import (
    RelatedActorImporter,
)
from crowdstrike_feeds_services.client.actors import ActorsAPI
from crowdstrike_feeds_services.utils import (
    create_attack_pattern,
    datetime_to_timestamp,
    paginate,
    timestamp_to_datetime,
)
from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper
from stix2 import Bundle, Identity, MarkingDefinition

from ..importer import BaseImporter
from .builder import ActorBundleBuilder


class ActorImporter(BaseImporter):
    """CrowdStrike actor importer."""

    _NAME = "Actor"

    _LATEST_ACTOR_TIMESTAMP = "latest_actor_timestamp"

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        author: Identity,
        default_latest_timestamp: int,
        tlp_marking: MarkingDefinition,
    ) -> None:
        """Initialize CrowdStrike actor importer."""
        super().__init__(helper, author, tlp_marking)
        self.actors_api_cs = ActorsAPI(helper)
        self.default_latest_timestamp = default_latest_timestamp

    def run(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Run importer."""
        self._info("Running actor importer with state: {0}...", state)

        fetch_timestamp = state.get(
            self._LATEST_ACTOR_TIMESTAMP, self.default_latest_timestamp
        )

        self.current_state = state.copy()

        new_state = state.copy()

        latest_actor_created_timestamp = None

        for actors_batch in self._fetch_actors(fetch_timestamp):
            if not actors_batch:
                break

            latest_actor_created_datetime = self._process_actors(actors_batch)

            if latest_actor_created_datetime is not None:
                latest_actor_created_timestamp = datetime_to_timestamp(
                    latest_actor_created_datetime
                )

                new_state[self._LATEST_ACTOR_TIMESTAMP] = latest_actor_created_timestamp
                self._set_state(new_state)

        latest_actor_timestamp = latest_actor_created_timestamp or fetch_timestamp

        self._info(
            "Actor importer completed, latest fetch {0}.",
            timestamp_to_datetime(latest_actor_timestamp),
        )

        return {self._LATEST_ACTOR_TIMESTAMP: latest_actor_timestamp}

    def _fetch_actors(self, start_timestamp: int) -> Generator[List, None, None]:
        limit = 50
        sort = "last_modified_date|asc"
        fql_filter = f"last_modified_date:>{start_timestamp}"
        fields = ["__full__"]

        paginated_query = paginate(self._query_actor_entities)

        return paginated_query(
            limit=limit, sort=sort, fql_filter=fql_filter, fields=fields
        )

    def _query_actor_entities(
        self,
        limit: int = 50,
        offset: int = 0,
        sort: Optional[str] = None,
        fql_filter: Optional[str] = None,
        fields: Optional[List[str]] = None,
    ):
        self._info(
            "Query actors limit: {0}, offset: {1}, sort: {2}, filter: {3}, fields: {4}",
            limit,
            offset,
            sort,
            fql_filter,
            fields,
        )

        actors = self.actors_api_cs.get_combined_actor_entities(
            limit=limit,
            offset=offset,
            sort=sort,
            fql_filter=fql_filter,
            fields=fields,
        )

        return actors

    def _process_actors(self, actors: List) -> Optional[datetime]:
        actor_count = len(actors)
        self._info("Processing {0} actors...", actor_count)

        latest_modified_timestamp: int | None = None

        for actor in actors:
            self._process_actor(actor)

            modified_date = actor.get("last_modified_date")
            if modified_date is None:
                self._error(
                    "Missing last_modified_date for actor {0} ({1})",
                    actor.get("name"),
                    actor.get("id"),
                )
                continue

            # CrowdStrike returns dates as timestamps; normalize to int for comparisons.
            try:
                modified_ts = int(modified_date)
            except (TypeError, ValueError):
                self._error(
                    "Invalid last_modified_date for actor {0} ({1}): {2}",
                    actor.get("name"),
                    actor.get("id"),
                    modified_date,
                )
                continue

            if (
                latest_modified_timestamp is None
                or modified_ts > latest_modified_timestamp
            ):
                latest_modified_timestamp = modified_ts

        RelatedActorImporter._resolved_actor_entity_cache.update(
            {
                a.get("id"): a.get("name")
                for a in actors
                if a.get("id") is not None and a.get("name") is not None
            }
        )

        self.helper.connector_logger.debug(
            "Actor batch processed",
            {
                "count": actor_count,
                "latest_modified_timestamp": latest_modified_timestamp,
            },
        )

        self._info(
            "Processing actors completed (imported: {0}, latest: {1})",
            actor_count,
            latest_modified_timestamp,
        )

        if latest_modified_timestamp is None:
            return None

        return timestamp_to_datetime(latest_modified_timestamp)

    def _process_actor(self, actor) -> None:
        self._info("Processing actor {0} ({1})...", actor["name"], actor["id"])

        actor_bundle = self._create_actor_bundle(actor)

        self._send_bundle(actor_bundle)

    def _create_actor_bundle(self, actor) -> Bundle:
        author = self.author
        source_name = self._source_name()
        object_marking_refs = [self.tlp_marking]
        confidence_level = self._confidence_level()

        attack_patterns = self._get_and_create_attack_patterns(actor)

        # MVP3
        bundle_builder = ActorBundleBuilder(
            actor,
            author,
            source_name,
            object_marking_refs,
            confidence_level,
            attack_patterns,
        )
        return bundle_builder.build()

    def _get_and_create_attack_patterns(self, actor) -> List:
        """Get MITRE ATT&CK TTPs and create AttackPattern entities."""
        try:
            actor_id = actor["id"]
            actor_name = actor["name"]

            self._info(
                "Fetching MITRE ATT&CK TTPs for actor: {0} (ID: {1})",
                actor_name,
                actor_id,
            )

            ttps_response = self.actors_api_cs.query_mitre_attacks(actor_id)
            if not ttps_response:
                self._info("No MITRE ATT&CK response for actor: {0}", actor_name)
                return []

            ttp_ids = ttps_response.get("resources", [])

            if not ttp_ids:
                self._info("No TTPs found for actor: {0}", actor_name)
                return []

            self._info("Retrieved {0} TTPs for actor: {1}", len(ttp_ids), actor_name)

            technique_ids = {
                ttp_id.split("_")[2]
                for ttp_id in ttp_ids
                if "_" in ttp_id
                and len(ttp_id.split("_")) >= 3
                and ttp_id.split("_")[2].startswith("T")
            }

            attack_patterns = [
                create_attack_pattern(
                    name=technique_id,
                    mitre_id=technique_id,
                    created_by=self.author,
                    object_markings=[self.tlp_marking],
                )
                for technique_id in technique_ids
            ]

            self._info(
                "Created {0} AttackPattern entities for actor: {1}",
                len(attack_patterns),
                actor_name,
            )
            return attack_patterns

        except Exception as err:
            self.helper.connector_logger.error(
                "[ERROR] Failed to retrieve and process TTPs for actor.",
                {
                    "error": err,
                    "actor_id": actor.get("id"),
                    "actor_name": actor.get("name"),
                },
            )
            return []
