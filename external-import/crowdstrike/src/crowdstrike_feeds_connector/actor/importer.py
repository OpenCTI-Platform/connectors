# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike actor importer module."""

from collections import Counter
from datetime import datetime
from typing import Any, Dict, Generator, List, Optional

from crowdstrike_feeds_services.client.actors import ActorsAPI
from crowdstrike_feeds_services.client.indicators import IndicatorsAPI
from crowdstrike_feeds_services.utils import (
    create_attack_pattern,
    datetime_to_timestamp,
    paginate,
    timestamp_to_datetime,
)
from pycti.connector.opencti_connector_helper import (  # type: ignore  # noqa: E501
    OpenCTIConnectorHelper,
)
from stix2 import Bundle, Identity, MarkingDefinition  # type: ignore

from ..importer import BaseImporter
from ..indicator.builder import IndicatorBundleBuilder, IndicatorBundleBuilderConfig
from .builder import ActorBundleBuilder


class ActorImporter(BaseImporter):
    """CrowdStrike actor importer."""

    _NAME = "Actor"

    _LATEST_ACTOR_TIMESTAMP = "latest_actor_timestamp"
    _LATEST_INDICATOR_TIMESTAMP = "latest_indicator_timestamp"

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        author: Identity,
        default_latest_timestamp: int,
        tlp_marking: MarkingDefinition,
        indicator_config: Dict[str, Any],
    ) -> None:
        """Initialize CrowdStrike actor importer."""
        super().__init__(helper, author, tlp_marking)
        self.actors_api_cs = ActorsAPI(helper)
        self.indicators_api_cs = IndicatorsAPI(helper)
        self.default_latest_timestamp = default_latest_timestamp
        self.indicator_config = indicator_config

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
            limit=limit, offset=offset, sort=sort, fql_filter=fql_filter, fields=fields
        )

        return actors

    def _process_actors(self, actors: List) -> Optional[datetime]:
        actor_count = len(actors)
        self._info("Processing {0} actors...", actor_count)

        latest_modified_datetime = None

        for actor in actors:
            self._process_actor(actor)

            modified_date = actor["last_modified_date"]
            if modified_date is None:
                self._error(
                    "Missing created date for actor {0} ({1})",
                    actor["name"],
                    actor["id"],
                )
                continue

            if (
                latest_modified_datetime is None
                or modified_date > latest_modified_datetime
            ):
                latest_modified_datetime = modified_date

        self._info(
            "Processing actors completed (imported: {0}, latest: {1})",
            actor_count,
            latest_modified_datetime,
        )

        return timestamp_to_datetime(latest_modified_datetime)

    def _process_actor(self, actor) -> None:
        self._info("Processing actor {0} ({1})...", actor["name"], actor["id"])

        actor_bundle = self._create_actor_bundle(actor)

        self._send_bundle(actor_bundle)

    def _get_related_iocs(self, actor_name: str) -> List[Any]:
        """Get IOCs associated with the specified actor."""
        try:
            related_indicators = []
            related_indicators_with_related_entities = []
            _limit = 10000
            _sort = "last_updated|asc"

            fetch_timestamp = self.indicator_config.get(
                "default_latest_timestamp", self.default_latest_timestamp
            )
            timestamp_source = "config_default"

            if self.current_state.get(self._LATEST_INDICATOR_TIMESTAMP):
                fetch_timestamp = self.current_state.get(
                    self._LATEST_INDICATOR_TIMESTAMP
                )
                timestamp_source = "indicator"
            elif self.current_state.get(self._LATEST_ACTOR_TIMESTAMP):
                fetch_timestamp = self.current_state.get(self._LATEST_ACTOR_TIMESTAMP)
                timestamp_source = "actor"

            _fql_filter = f"actors:['{actor_name}']+last_updated:>{fetch_timestamp}"

            exclude_types = self.indicator_config.get("exclude_types", [])
            if exclude_types:
                _fql_filter = f"{_fql_filter}+type:!{exclude_types}"

            self._info(
                "Fetching IOCs for actor {0} with timestamp filter {1} (using {2} timestamp)",
                actor_name,
                timestamp_to_datetime(fetch_timestamp),
                timestamp_source,
            )

            response = self.indicators_api_cs.get_combined_indicator_entities(
                limit=_limit, sort=_sort, fql_filter=_fql_filter, deep_pagination=True
            )
            related_indicators.extend(response["resources"])

            self._info(
                "Retrieved {0} raw IOCs from CrowdStrike for actor: {1}",
                len(related_indicators),
                actor_name,
            )

            if related_indicators is not None:
                for indicator in related_indicators:
                    bundle_builder_config = IndicatorBundleBuilderConfig(
                        indicator=indicator,
                        author=self.author,
                        source_name=self._source_name(),
                        object_markings=[self.tlp_marking],
                        confidence_level=self._confidence_level(),
                        create_observables=self.indicator_config["create_observables"],
                        create_indicators=self.indicator_config["create_indicators"],
                        default_x_opencti_score=self.indicator_config[
                            "default_x_opencti_score"
                        ],
                        indicator_low_score=self.indicator_config[
                            "indicator_low_score"
                        ],
                        indicator_low_score_labels=self.indicator_config[
                            "indicator_low_score_labels"
                        ],
                        indicator_medium_score=self.indicator_config[
                            "indicator_medium_score"
                        ],
                        indicator_medium_score_labels=self.indicator_config[
                            "indicator_medium_score_labels"
                        ],
                        indicator_high_score=self.indicator_config[
                            "indicator_high_score"
                        ],
                        indicator_high_score_labels=self.indicator_config[
                            "indicator_high_score_labels"
                        ],
                        indicator_unwanted_labels=self.indicator_config[
                            "indicator_unwanted_labels"
                        ],
                    )
                    try:
                        bundle_builder = IndicatorBundleBuilder(
                            self.helper, bundle_builder_config
                        )
                    except TypeError as err:
                        self.helper.connector_logger.warning(
                            "Skipping unsupported indicator type for actor.",
                            {
                                "actor_name": actor_name,
                                "indicator_id": indicator.get("id"),
                                "indicator_type": indicator.get("type"),
                                "indicator_value": indicator.get("indicator"),
                                "error": str(err),
                            },
                        )
                        continue
                    indicator_bundle_built = bundle_builder.build()
                    if indicator_bundle_built:
                        indicator_with_related_entities = indicator_bundle_built[
                            "object_refs"
                        ]
                        related_indicators_with_related_entities.extend(
                            indicator_with_related_entities
                        )
                    else:
                        self.helper.connector_logger.debug(
                            "[DEBUG] The construction of the indicator has been skipped in the actor.",
                            {
                                "indicator_id": indicator.get("id"),
                                "indicator_type": indicator.get("type"),
                            },
                        )
                        continue

            return related_indicators_with_related_entities
        except Exception as err:
            self.helper.connector_logger.error(
                "[ERROR] An unexpected error occurred when retrieving indicators for the actor.",
                {
                    "error": err,
                    "actor_name": actor_name,
                },
            )
            raise

    def _create_actor_bundle(self, actor) -> Bundle:
        author = self.author
        source_name = self._source_name()
        object_marking_refs = [self.tlp_marking]
        confidence_level = self._confidence_level()
        related_indicators_with_related_entities = []

        actor_name = actor["name"]
        if actor_name is not None:
            self._info("Fetching related IOCs for actor: {0}", actor_name)
            related_indicators_with_related_entities = self._get_related_iocs(
                actor_name
            )
            if len(related_indicators_with_related_entities) > 0:
                counts = Counter(
                    s["type"]
                    for s in {
                        (stix["type"], stix["id"]): stix
                        for stix in related_indicators_with_related_entities
                        if stix["type"] not in ["relationship", "indicator"]
                    }.values()
                )

                summary = ", ".join(f"{t}:{n}" for t, n in counts.items())
                self._info(
                    "Creating {0} stix objects for the IOCs and related entities for actor: {1}",
                    summary,
                    actor_name,
                )

        attack_patterns = self._get_and_create_attack_patterns(actor)

        bundle_builder = ActorBundleBuilder(
            actor,
            author,
            source_name,
            object_marking_refs,
            confidence_level,
            related_indicators_with_related_entities,
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
