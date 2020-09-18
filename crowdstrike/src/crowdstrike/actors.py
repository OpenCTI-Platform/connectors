# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike actors importer module."""

from typing import Any, Generator, List, Mapping, Optional

from crowdstrike_client.api.intel.actors import Actors
from crowdstrike_client.api.models import Response
from crowdstrike_client.api.models.actor import Actor

from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper

from stix2 import Bundle, Identity, MarkingDefinition

from crowdstrike.actor_bundle_builder import ActorBundleBuilder
from crowdstrike.utils import datetime_to_timestamp, paginate, timestamp_to_datetime


class ActorImporter:
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
        self.helper = helper
        self.actors_api = actors_api
        self.update_existing_data = update_existing_data
        self.author = author
        self.tlp_marking = tlp_marking
        self.default_latest_timestamp = default_latest_timestamp

    def run(self, state: Mapping[str, Any]) -> Mapping[str, Any]:
        """Run importer."""
        self._info("Running actor importer with state: {0}...", state)

        fetch_timestamp = state.get(
            self._LATEST_ACTOR_TIMESTAMP, self.default_latest_timestamp
        )

        latest_fetched_actor_timestamp = None

        for actors_batch in self._fetch_actors(fetch_timestamp):
            if not actors_batch:
                break

            if latest_fetched_actor_timestamp is None:
                first_in_batch = actors_batch[0]

                created_date = first_in_batch.created_date
                if created_date is None:
                    self._error(
                        "Missing created date for actor {0} ({1})",
                        first_in_batch.name,
                        first_in_batch.id,
                    )
                    break

                latest_fetched_actor_timestamp = datetime_to_timestamp(created_date)

            self._process_actors(actors_batch)

        state_timestamp = latest_fetched_actor_timestamp or fetch_timestamp

        self._info(
            "Actor importer completed, latest fetch {0}.",
            timestamp_to_datetime(state_timestamp),
        )

        return {self._LATEST_ACTOR_TIMESTAMP: state_timestamp}

    def _info(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_info(fmt_msg)

    def _error(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_error(fmt_msg)

    def _fetch_actors(self, start_timestamp: int) -> Generator[List[Actor], None, None]:
        limit = 50
        sort = "created_date|desc"
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

    def _process_actors(self, actors: List[Actor]) -> None:
        actor_count = len(actors)
        self._info("Processing {0} actors...", actor_count)

        for actor in actors:
            self._process_actor(actor)

        self._info("Processing actors completed (imported: {0})", actor_count)

    def _process_actor(self, actor: Actor) -> None:
        self._info("Processing actor {0} ({1})...", actor.name, actor.id)

        actor_bundle = self._create_actor_bundle(actor)

        with open(f"actor_bundle_{actor.id}.json", "w") as f:
            f.write(actor_bundle.serialize(pretty=True))

        self._send_bundle(actor_bundle)

    def _create_actor_bundle(self, actor: Actor) -> Optional[Bundle]:
        author = self.author
        source_name = self._source_name()
        object_marking_refs = [self.tlp_marking]
        confidence_level = self._confidence_level()

        bundle_builder = ActorBundleBuilder(
            actor, author, source_name, object_marking_refs, confidence_level
        )
        return bundle_builder.build()

    def _source_name(self) -> str:
        return self.helper.connect_name

    def _confidence_level(self) -> int:
        return self.helper.connect_confidence_level

    def _send_bundle(self, bundle: Bundle) -> None:
        serialized_bundle = bundle.serialize()
        self.helper.send_stix2_bundle(
            serialized_bundle, None, self.update_existing_data, False
        )
