import json
import sys
import time
from datetime import datetime, timedelta, timezone

from pycti import OpenCTIConnectorHelper

from .api_handler import DefenderApiHandler
from .config_variables import ConfigConnector
from .utils import (
    FILE_HASH_TYPES_MAPPER,
)


def chunker_list(a, n):
    """
    Split a list into chunks of size n.
    :param a: List to be split
    :param n: Size of each chunk
    :return: List of chunks
    """
    return [a[i : i + n] for i in range(0, len(a), n)]


class MicrosoftDefenderIntelSynchronizerConnector:
    """
    Specifications of the Stream connector

    This class encapsulates the main actions, expected to be run by any stream connector.
    Note that the attributes defined below will be complemented per each connector type.
    This type of connector has the capability to listen to live streams from the OpenCTI platform.
    It is highly useful for creating connectors that can react and make decisions in real time.
    Actions on OpenCTI will apply the changes to the third-party connected platform
    ---

    Attributes
        - `config (ConfigConnector())`:
            Initialize the connector with necessary configuration environment variables

        - `helper (OpenCTIConnectorHelper(config))`:
            This is the helper to use.
            ALL connectors have to instantiate the connector helper with configurations.
            Doing this will do a lot of operations behind the scene.

    ---

    Best practices
        - `self.helper.connector_logger.[info/debug/warning/error]` is used when logging a message

    """

    def __init__(self):
        """
        Initialize the Connector with necessary configurations
        """

        # Load configuration file and connection helper
        self.config = ConfigConnector()
        self.helper = self.config.helper
        self.api = DefenderApiHandler(self.helper, self.config)

    def _convert_indicator_to_observables(self, data) -> list[dict]:
        """
        Convert an OpenCTI indicator to its corresponding observables.
        Observables taken into account:
        :param data: OpenCTI indicator data
        :return: Observables data
        """
        try:
            observables = []
            parsed_observables = self.helper.get_attribute_in_extension(
                "observable_values", data
            )
            if parsed_observables:
                # Iterate over the parsed observables
                for observable in parsed_observables:
                    observable_data = {}
                    observable_data.update(data)
                    x_opencti_observable_type = observable.get("type").lower()
                    if x_opencti_observable_type != "stixfile":
                        observable_data["type"] = x_opencti_observable_type
                        observable_data["value"] = observable.get("value")
                        observables.append(observable_data)
                    else:
                        file = {}
                        for key, value in observable.get("hashes", {}).items():
                            hash_type = FILE_HASH_TYPES_MAPPER.get(key.lower())
                            if hash_type is not None:
                                file[hash_type] = value
                        if file:
                            observable_data["type"] = "file"
                            observable_data["hashes"] = file
                            observables.append(observable_data)

            return observables
        except Exception:
            indicator_opencti_id = OpenCTIConnectorHelper.get_attribute_in_extension(
                "id", data
            )
            self.helper.connector_logger.warning(
                "[CREATE] Cannot convert STIX indicator { " + indicator_opencti_id + "}"
            )

    INDICATOR_QUERY = """
    query Indicators(
    $filters: FilterGroup,
    $first: Int,
    $after: ID,
    $orderBy: IndicatorsOrdering,
    $orderMode: OrderingMode
    ) {
    indicators(
        filters: $filters,
        first: $first,
        after: $after,
        orderBy: $orderBy,
        orderMode: $orderMode
    ) {
        edges {
        node {
            id
            standard_id
            created
            modified
            confidence
            x_opencti_score
            toStix
        }
        }
        pageInfo {
        globalCount
        endCursor
        hasNextPage
        }
    }
    }
    """

    def fetch_indicators_batched(
        self, filters, max_size=15000, batch_size=500, collection_name=None
    ):
        """
        Fetch indicators in batches using cursor-based pagination, stopping at the end of the collection or max_size.
        Logs each batch request for debugging, including the collection name if provided.
        """
        indicators = []
        after = None
        total_fetched = 0
        batch_num = 1
        collection_str = (
            f" for collection '{collection_name}'" if collection_name else ""
        )
        while total_fetched < max_size:
            variables = {
                "filters": filters,
                "first": min(batch_size, max_size - total_fetched),
                "orderBy": "modified",
                "orderMode": "desc",
            }
            if after:
                variables["after"] = after
            self.helper.connector_logger.info(
                f"[DEBUG] Fetching batch {batch_num}{collection_str}: after={after}, batch_size={variables['first']}, total_fetched={total_fetched}"
            )
            try:
                result = self.helper.api.query(self.INDICATOR_QUERY, variables)
                data = result["data"]["indicators"]
                edges = data["edges"]
                if not edges:
                    self.helper.connector_logger.info(
                        f"[DEBUG] Batch {batch_num}{collection_str}: No more edges returned, stopping."
                    )
                    break
                for edge in edges:
                    indicators.append(edge["node"])
                    total_fetched += 1
                    if total_fetched >= max_size:
                        break
                page_info = data.get("pageInfo", {})
                after = page_info.get("endCursor")
                has_next_page = page_info.get("hasNextPage", False)
                self.helper.connector_logger.info(
                    f"[DEBUG] Batch {batch_num}{collection_str}: Retrieved {len(edges)} indicators, after={after}, has_next_page={has_next_page}"
                )
                batch_num += 1
                # Stop if there are no more results
                if not has_next_page or not after or len(edges) == 0:
                    self.helper.connector_logger.info(
                        f"[DEBUG] Batch {batch_num-1}{collection_str}: No more pages, stopping."
                    )
                    break
            except Exception as e:
                self.helper.connector_logger.error(
                    "GraphQL query failed",
                    {"error": str(e), "variables": variables},
                )
                break
        self.helper.connector_logger.info(
            f"Fetched {len(indicators)} indicators{collection_str}"
        )
        return indicators

    def run(self) -> None:
        import signal

        def handle_sigint(signum, frame):
            self.helper.connector_logger.info(
                "Received interrupt signal, shutting down gracefully."
            )
            sys.exit(0)

        signal.signal(signal.SIGINT, handle_sigint)

        while True:
            start_time = time.time()
            try:
                state = self.helper.get_state() or {}
                opencti_all_indicators = []
                defender_indicators_to_delete = []
                opencti_indicators_to_create = []

                now_iso = (
                    datetime.now(timezone.utc) + timedelta(minutes=10)
                ).isoformat()

                validity_filter = {
                    "key": "valid_until",
                    "operator": "gt",
                    "values": [now_iso],
                    "mode": "or",
                }

                # Prepare a mapping of collection to its rank (order in config)
                collection_rank = {
                    col: i for i, col in enumerate(self.config.taxii_collections)
                }

                # Get OpenCTI indicators
                for collection in self.config.taxii_collections:
                    if collection not in state:
                        state[collection] = {}
                    query = """
                        query TaxiiCollections($id: String!) {
                            taxiiCollection(id: $id) {
                                filters
                            }
                        }
                    """
                    result = self.helper.api.query(query, {"id": collection})
                    if (
                        "taxiiCollection" in result["data"]
                        and "filters" in result["data"]["taxiiCollection"]
                    ):
                        filters = result["data"]["taxiiCollection"]["filters"]
                        filters = json.loads(filters)
                        filters["filters"].append(validity_filter)
                        opencti_indicators = self.fetch_indicators_batched(
                            filters, collection_name=collection
                        )
                        self.helper.connector_logger.info(
                            f"Fetched {len(opencti_indicators)} indicators from collection '{collection}'"
                        )
                        if opencti_indicators:
                            try:
                                first_indicator = json.loads(
                                    opencti_indicators[0]["toStix"]
                                )
                                state[collection]["last_timestamp"] = (
                                    first_indicator.get("modified")
                                )
                            except Exception as e:
                                self.helper.connector_logger.warning(
                                    f"[STATE] Could not extract timestamp from first indicator: {e}"
                                )
                        state[collection]["last_count"] = len(opencti_indicators)
                        opencti_indicators = [
                            {
                                **json.loads(opencti_indicator["toStix"]),
                                "_collection": collection,
                                "_collection_rank": collection_rank[collection],
                            }
                            for opencti_indicator in opencti_indicators
                        ]
                        opencti_all_indicators.extend(opencti_indicators)
                    else:
                        self.helper.connector_logger.error(
                            "TAXII collection not found", {"id": collection}
                        )

                self.helper.log_info(
                    f"Found {len(opencti_all_indicators)} indicators in TAXII collections"
                )

                # Get Microsoft Defender Indicators
                defender_indicators = self.api.get_indicators()

                self.helper.connector_logger.info(
                    f"Found {len(defender_indicators)} indicators in Microsoft Defender"
                )

                def parse_modified(item):
                    value = item.get("modified")
                    if not value:
                        return datetime.min
                    try:
                        # Try to parse ISO format (Python 3.7+)
                        return datetime.fromisoformat(value.replace("Z", "+00:00"))
                    except Exception:
                        return datetime.min

                def safe_confidence(item):
                    try:
                        return int(item.get("confidence", 1))
                    except Exception:
                        return 1

                opencti_all_indicators.sort(
                    key=lambda item: (
                        -int(safe_confidence(item)),
                        parse_modified(item),
                        -int(item.get("_collection_rank", sys.maxsize)),
                    ),
                    reverse=True,
                )

                # Cut at 15 000
                opencti_all_indicators = opencti_all_indicators[:15000]

                # Use dicts for O(1) lookups
                defender_external_ids = {
                    d["externalId"]: d for d in defender_indicators if "externalId" in d
                }
                opencti_ids = set()

                for opencti_indicator in opencti_all_indicators:
                    opencti_id = OpenCTIConnectorHelper.get_attribute_in_extension(
                        "id", opencti_indicator
                    )
                    opencti_ids.add(opencti_id)

                # Find Defender indicators to delete (not present in OpenCTI)
                for ext_id, defender_indicator in defender_external_ids.items():
                    if ext_id not in opencti_ids:
                        defender_indicators_to_delete.append(defender_indicator)

                # Find OpenCTI indicators to create (not present in Defender)
                defender_external_ids_set = set(defender_external_ids.keys())
                for opencti_indicator in opencti_all_indicators:
                    observables = (
                        self._convert_indicator_to_observables(opencti_indicator) or []
                    )
                    for observable_data in observables:
                        observable_id = (
                            OpenCTIConnectorHelper.get_attribute_in_extension(
                                "id", observable_data
                            )
                        )
                        if observable_id not in defender_external_ids_set:
                            opencti_indicators_to_create.append(observable_data)

                # Dedup
                defender_indicators_to_delete = {
                    obj["id"]: obj
                    for obj in reversed(defender_indicators_to_delete)
                    if "id" in obj
                }
                defender_indicators_to_delete = list(
                    defender_indicators_to_delete.values()
                )
                defender_indicators_to_delete_ids = [
                    defender_indicator_to_delete["id"]
                    for defender_indicator_to_delete in defender_indicators_to_delete
                ]
                self.helper.connector_logger.info(
                    f"[DELETE] Deleting {len(defender_indicators_to_delete)} indicators..."
                )
                if defender_indicators_to_delete_ids:
                    defender_indicators_to_delete_ids_chunked = chunker_list(
                        defender_indicators_to_delete_ids, 500
                    )
                    for (
                        defender_indicators_to_delete_ids_chunk
                    ) in defender_indicators_to_delete_ids_chunked:
                        try:
                            self.api.delete_indicators(
                                defender_indicators_to_delete_ids_chunk
                            )
                            self.helper.connector_logger.info(
                                f"[DELETE] Deleted {len(defender_indicators_to_delete_ids_chunk)} indicators"
                            )
                            # Wait a few seconds to allow Defender to free up capacity
                            time.sleep(20)
                        except Exception as e:
                            self.helper.connector_logger.error(
                                "Cannot delete indicators",
                                {
                                    "error": str(e),
                                    "ids": defender_indicators_to_delete_ids_chunk,
                                },
                            )
                # Dedup
                opencti_indicators_to_create = {
                    obj["id"]: obj
                    for obj in reversed(opencti_indicators_to_create)
                    if "id" in obj
                }
                opencti_indicators_to_create = list(
                    opencti_indicators_to_create.values()
                )
                self.helper.connector_logger.info(
                    f"[CREATE] Creating {len(opencti_indicators_to_create)} indicators..."
                )
                if opencti_indicators_to_create:
                    opencti_indicators_to_create_chunked = chunker_list(
                        opencti_indicators_to_create, 500
                    )
                    for (
                        opencti_indicators_to_create_chunk
                    ) in opencti_indicators_to_create_chunked:
                        try:
                            data = self.api.post_indicators(
                                opencti_indicators_to_create_chunk
                            )
                            self.helper.connector_logger.info(
                                f"[CREATE] Created {data.get('total_count', len(opencti_indicators_to_create_chunk)) - data.get('failed_count', 0)} of {data.get('total_count', len(opencti_indicators_to_create_chunk))} indicators"
                            )
                        except Exception as e:
                            self.helper.connector_logger.error(
                                "Cannot create indicators",
                                {
                                    "error": str(e),
                                    "count": len(opencti_indicators_to_create_chunk),
                                },
                            )
                self.helper.set_state(state)
            except Exception as e:
                self.helper.connector_logger.error(
                    "An error occurred during the run", {"error": str(e)}
                )
            # Adjust sleep to maintain accurate interval
            elapsed = time.time() - start_time
            sleep_time = max(0, self.config.interval - elapsed)
            if sleep_time > 0:
                time.sleep(sleep_time)
