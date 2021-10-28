import json
from datetime import timedelta
from logging import getLogger
from threading import Event, Thread

from elasticsearch import Elasticsearch, NotFoundError
from elasticsearch_dsl import Search
from pycti import OpenCTIConnectorHelper
from scalpl import Cut

from . import LOGGER_NAME
from .utils import parse_duration

logger = getLogger(LOGGER_NAME)

DEFAULT_QUERY = """
{"query": {"bool": {"must": {"match": { "signal.rule.type": "threat_match" }}}}}
"""

DEFAULT_LOOKBACK = "5m"


class SignalsManager(Thread):
    def __init__(
        self,
        config: dict,
        shutdown_event: Event,
        opencti_client: OpenCTIConnectorHelper,
        elasticsearch_client: Elasticsearch,
    ) -> None:
        super(SignalsManager, self).__init__()
        self.config: Cut = Cut(config)
        self.shutdown_event: Event = shutdown_event
        self.es_client: Elasticsearch = elasticsearch_client

        self.helper: OpenCTIConnectorHelper = opencti_client
        self.author_id = None

        # Default to 5 minutes
        self.interval = 300
        _interval: str = self.config.get("elastic.signals.query_interval", "5m")
        _dur: timedelta = parse_duration(_interval)
        if _dur is not None:
            self.interval = _dur.total_seconds()

        self.search_idx = self.config.get(
            "elastic.signals.signal_index", ".siem-signals-*"
        )
        _query: dict = json.loads(
            self.config.get("elastic.signals.query", DEFAULT_QUERY)
        )
        _lookback: str = self.config.get(
            "elastic.signals.lookback_interval", DEFAULT_LOOKBACK
        )

        assert self.es_client.ping()
        self.signals_search: dict = (
            Search(using=self.es_client, index=self.search_idx)
            .from_dict(_query)
            .filter(
                "range", **{"@timestamp": {"gte": f"now-{_lookback}/m", "lt": "now/m"}}
            )
            .to_dict()
        )

        logger.info("Signals manager thread initialized")

    def _get_elastic_entity(self) -> str:
        """Get or create a Elastic Threatintel Connector entity if not exists"""
        if self.author_id is not None:
            return self.author_id

        _entity_name = self.config.get(
            "connector.entity_name", "Elastic ThreatIntel Connector"
        )
        _entity_desc = self.config.get("connector.entity_description", "")

        elastic_entity = self.helper.api.stix_domain_object.get_by_stix_id_or_name(
            name=_entity_name
        )
        if not elastic_entity:
            logger.info(f"Creating {_entity_name} STIX identity")
            self.author_id = self.helper.api.identity.create(
                # NOTE: This should maybe be `system` See https://github.com/OpenCTI-Platform/opencti/issues/1322
                type="Organization",
                name=_entity_name,
                description=_entity_desc,
            )["id"]
            return self.author_id
        else:
            logger.info(f"Caching {_entity_name} id")
            self.author_id = elastic_entity["id"]
            return self.author_id

    def run(self) -> None:

        logger.info("Signals manager thread starting")

        """Main loop"""
        while not self.shutdown_event.is_set():

            logger.debug("Searching for new signals")

            # Look for new Threat Match Signals from Elastic SIEM
            results = self.es_client.search(
                index=self.search_idx, body=self.signals_search
            )
            ids_dict = {}

            # Parse the results
            for hit in results["hits"]["hits"]:
                for indicator in hit["_source"]["threat"]["indicator"]:
                    # Get original threatintel document
                    try:
                        _doc = self.es_client.get(
                            index=indicator["matched"]["index"],
                            id=indicator["matched"]["id"],
                        )
                    except NotFoundError as err:
                        logger.error(
                            f"ThreatIntel document for {indicator['matched']['atomic'][0]} was not found",
                            err,
                        )
                        continue

                    if _doc["found"] is not True:
                        continue

                    if (
                        "threatintel" in _doc["_source"]
                        and "opencti" in _doc["_source"]["threatintel"]
                    ):
                        _opencti_id = _doc["_source"]["threatintel"]["opencti"][
                            "internal_id"
                        ]
                    else:
                        logger.warn(
                            "Signal for threatintel document doesn't have opencti reference. Skipping"
                        )
                        # XXX Optionally, could look up via OpenCTI API for an indicator that matches
                        continue

                    _timestamp = hit["_source"]["signal"]["original_time"]
                    if _opencti_id not in ids_dict:
                        ids_dict[_opencti_id] = {
                            "first_seen": _timestamp,
                            "last_seen": _timestamp,
                            "count": 1,
                        }
                    else:
                        ids_dict[_opencti_id]["count"] += 1

                        if _timestamp < ids_dict[_opencti_id]["first_seen"]:
                            ids_dict[_opencti_id]["first_seen"] = _timestamp
                        elif _timestamp > ids_dict[_opencti_id]["last_seen"]:
                            ids_dict[_opencti_id]["last_seen"] = _timestamp

            # Loop through signal hits and create new sightings
            for k, v in ids_dict.items():

                # Check if indicator exists
                indicator = self.helper.api.indicator.read(id=k)
                if indicator:

                    logger.info("Found matching indicator in OpenCTI")
                    stix_id = indicator["standard_id"]

                    entity_id = self._get_elastic_entity()
                    confidence = int(
                        self.config.get("connector.confidence_level", "80")
                    )

                    logger.debug(f"Creating sighting from {stix_id} -> {entity_id}")

                    # Create new Sighting
                    self.helper.api.stix_sighting_relationship.create(
                        fromId=stix_id,
                        toId=entity_id,
                        stix_id=None,
                        description="Threat Match sighting from Elastic SIEM",
                        first_seen=v["first_seen"],
                        last_seen=v["last_seen"],
                        count=v["count"],
                        x_opencti_negative=False,
                        created=None,
                        modified=None,
                        confidence=confidence,
                        created_by=entity_id,
                        object_marking=None,
                        object_label=None,
                        external_references=None,
                        update=False,
                    )

            # Wait allows us to return earlier during a shutdown
            logger.debug(f"Sleeping for {self.interval} seconds")
            self.shutdown_event.wait(self.interval)
