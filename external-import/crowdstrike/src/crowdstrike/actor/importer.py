# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike actor importer module."""

from datetime import datetime
from typing import Any, Dict, Generator, List, Optional

from crowdstrike.actor.builder import ActorBundleBuilder
from crowdstrike.importer import BaseImporter
from crowdstrike.utils import datetime_to_timestamp, paginate, timestamp_to_datetime
from crowdstrike_client.api.intel.actors import Actors
from crowdstrike_client.api.models import Response
from crowdstrike_client.api.models.actor import Actor
from pycti.connector.opencti_connector_helper import (  # type: ignore  # noqa: E501
    OpenCTIConnectorHelper,
)
from stix2 import Bundle, Identity, MarkingDefinition  # type: ignore


class ActorImporter(BaseImporter):
    """CrowdStrike actor importer."""

    _LATEST_ACTOR_TIMESTAMP = "latest_actor_timestamp"

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        actors_api: Actors,
        update_existing_data: bool,
        author: Identity,
        default_latest_timestamp: int,
        tlp_marking: MarkingDefinition,
    ) -> None:
        """Initialize CrowdStrike actor importer."""
        super().__init__(helper, author, tlp_marking, update_existing_data)

        self.actors_api = actors_api

        self.default_latest_timestamp = default_latest_timestamp

    def run(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Run importer."""
        self._info("Running actor importer with state: {0}...", state)

        fetch_timestamp = state.get(
            self._LATEST_ACTOR_TIMESTAMP, self.default_latest_timestamp
        )

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

    def _fetch_actors(self, start_timestamp: int) -> Generator[List[Actor], None, None]:
        limit = 50
        sort = "created_date|asc"
        fql_filter = f"created_date:>{start_timestamp}"
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
    ) -> Response[Actor]:
        self._info(
            "Query actors limit: {0}, offset: {1}, sort: {2}, filter: {3}, fields: {4}",
            limit,
            offset,
            sort,
            fql_filter,
            fields,
        )

        return self.actors_api.query_entities(
            limit=limit, offset=offset, sort=sort, fql_filter=fql_filter, fields=fields
        )

    def _process_actors(self, actors: List[Actor]) -> Optional[datetime]:
        actor_count = len(actors)
        self._info("Processing {0} actors...", actor_count)

        latest_created_datetime = None

        for actor in actors:
            self._process_actor(actor)

            created_date = actor.created_date
            if created_date is None:
                self._error(
                    "Missing created date for actor {0} ({1})",
                    actor.name,
                    actor.id,
                )
                continue

            if (
                latest_created_datetime is None
                or created_date > latest_created_datetime
            ):
                latest_created_datetime = created_date

        self._info(
            "Processing actors completed (imported: {0}, latest: {1})",
            actor_count,
            latest_created_datetime,
        )

        return latest_created_datetime

    def _process_actor(self, actor: Actor) -> None:
        self._info("Processing actor {0} ({1})...", actor.name, actor.id)

        actor_bundle = self._create_actor_bundle(actor)

        # with open(f"actor_bundle_{actor.id}.json", "w") as f:
        #     f.write(actor_bundle.serialize(pretty=True))

        self._send_bundle(actor_bundle)

    def _create_actor_bundle(self, actor: Actor) -> Bundle:
        author = self.author
        source_name = self._source_name()
        object_marking_refs = [self.tlp_marking]
        confidence_level = self._confidence_level()

        bundle_builder = ActorBundleBuilder(
            actor, author, source_name, object_marking_refs, confidence_level
        )
        return bundle_builder.build()
