from datetime import timedelta
from threading import Thread, Event
from logging import getLogger
from scalpl import Cut
import json

from elasticsearch import Elasticsearch
from pycti import OpenCTIConnectorHelper

from .utils import parse_duration

logger = getLogger("elastic-threatintel-connector")

DEFAULT_QUERY = """
{
  "query": {
    "bool": {
      "must": {
        "match": { "signal.rule.type": "threat_match" }
      },
      "filter": {
        "range": {
          "@timestamp": {
            "gte": "now-5m/m",
            "lt": "now/m"
          }
        }
      }
    }
  }
}
"""


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

        # Default to 5 minutes
        self.interval = 300
        _interval: str = self.config.get("elastic.signals.query_interval", "5m")
        _dur: timedelta = parse_duration(_interval)
        if _dur is not None:
            self.interval = _dur.total_seconds()

        self.search_idx = self.config.get(
            "elastic.signals.signal_index", ".siem-signals-*"
        )
        self.signals_query = self.config.get("elastic.signals.query", DEFAULT_QUERY)

        # XXX MAD HAX!
        # self.author_id = self.config.get("connector.author_id")
        self.author_id = "identity--9a7de335-5d7b-55a1-bfde-cb9c98ca6ebc"

        logger.info("Signals manager thread initialized")

    def _get_elastic_entity(self) -> str:
        return self.author_id

    def run(self) -> None:

        # Wait the first interval before first query
        # self.shutdown_event.wait(self.interval)

        logger.info("Signals manager thread starting")

        """Main loop"""
        while not self.shutdown_event.is_set():

            logger.debug("Searching for new signals")

            # Look for new Threat Match Signals from Elastic SIEM
            results = self.es_client.search(
                index=self.search_idx, body=self.signals_query
            )
            ids_dict = {}

            # Parse the results
            for hit in results["hits"]["hits"]:

                for indicator in hit["_source"]["threat"]["indicator"]:
                    b = json.loads(
                        '{"query": {"bool": {"must": {"match": {"_id" : "'
                        + indicator["matched"]["id"]
                        + '"}}}}}'
                    )
                    i = indicator["matched"]["index"]

                    # Lookup and parse the openCTI ID from the threatintel index
                    threat_intel_hits = self.es_client.search(index=i, body=b)

                    for h in threat_intel_hits["hits"]["hits"]:
                        ids_dict[
                            h["_source"]["threatintel"]["opencti"]["internal_id"]
                        ] = h["_source"]["@timestamp"]

            # Loop through signal hits and create new sightings
            for item in ids_dict:

                # Check if indicator exists
                indicator = self.helper.api.indicator.read(id=item)
                if indicator:

                    logger.info("Found matching indicator in OpenCTI")

                    stix_id = indicator["standard_id"]
                    t = ids_dict[item]

                    entity_id = self._get_elastic_entity()

                    logger.debug(f"{stix_id} -> {entity_id}")

                    # Create new Sighting
                    self.helper.api.stix_sighting_relationship.create(
                        fromId=stix_id,
                        toId=entity_id,
                        stix_id=None,
                        description="Threat Match sighting from Elastic SIEM",
                        first_seen=t,
                        last_seen=t,
                        count=1,
                        x_opencti_negative=False,
                        created=None,
                        modified=None,
                        confidence=50,
                        created_by=entity_id,
                        object_marking=None,
                        object_label=None,
                        external_references=None,
                        update=False,
                    )

            # Wait allows us to return earlier during a shutdown
            logger.debug(f"Sleeping for {self.interval} seconds")
            self.shutdown_event.wait(self.interval)
