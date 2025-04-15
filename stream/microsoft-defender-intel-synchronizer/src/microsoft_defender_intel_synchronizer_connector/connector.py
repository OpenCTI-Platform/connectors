import json
import time

from pycti import OpenCTIConnectorHelper

from .api_handler import DefenderApiHandler
from .config_variables import ConfigConnector
from .utils import (
    FILE_HASH_TYPES_MAPPER,
)


def chunker_list(a, n):
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
        self.helper = OpenCTIConnectorHelper(self.config.load)
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
        except:
            indicator_opencti_id = OpenCTIConnectorHelper.get_attribute_in_extension(
                "id", data
            )
            self.helper.connector_logger.warning(
                "[CREATE] Cannot convert STIX indicator { " + indicator_opencti_id + "}"
            )

    def run(self) -> None:
        while True:
            try:
                state = self.helper.get_state()
                if state is None:
                    state = {}
                opencti_all_indicators = []
                defender_indicators_to_delete = []
                opencti_indicators_to_create = []

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
                        opencti_indicators = self.helper.api.indicator.list(
                            order_by="modified",
                            orderMode="desc",
                            filters=json.loads(filters),
                            first=10000,
                            toStix=True,
                        )
                        if len(opencti_indicators) > 0:
                            first_indicator = json.loads(
                                opencti_indicators[0]["toStix"]
                            )
                            state[collection]["last_timestamp"] = first_indicator[
                                "modified"
                            ]
                        state[collection]["last_count"] = len(opencti_indicators)
                        opencti_indicators = [
                            json.loads(opencti_indicator["toStix"])
                            for opencti_indicator in opencti_indicators
                        ]
                        opencti_all_indicators = (
                            opencti_all_indicators + opencti_indicators
                        )
                    else:
                        self.helper.connector_logger.error(
                            "TAXII collection not found", {"id": collection}
                        )

                self.helper.connector_logger.info(
                    "Found "
                    + str(len(opencti_all_indicators))
                    + " indicators in TAXII collections"
                )

                # Get Microsoft Defender Indicators
                defender_indicators = self.api.get_indicators()

                self.helper.connector_logger.info(
                    "Found "
                    + str(len(defender_indicators))
                    + " indicators in Microsoft Defender"
                )

                # Cut at 15 000
                opencti_all_indicators.sort(
                    key=lambda item: item["modified"], reverse=True
                )
                opencti_all_indicators = opencti_all_indicators[:15000]

                for defender_indicator in defender_indicators:
                    is_found = False
                    for opencti_indicator in opencti_all_indicators:
                        if defender_indicator[
                            "externalId"
                        ] == OpenCTIConnectorHelper.get_attribute_in_extension(
                            "id", opencti_indicator
                        ):
                            is_found = True
                    if not is_found:
                        defender_indicators_to_delete.append(defender_indicator)

                for opencti_indicator in opencti_all_indicators:
                    observables = self._convert_indicator_to_observables(
                        opencti_indicator
                    )
                    for observable_data in observables:
                        is_found = False
                        for defender_indicator in defender_indicators:
                            if defender_indicator[
                                "externalId"
                            ] == OpenCTIConnectorHelper.get_attribute_in_extension(
                                "id", observable_data
                            ):
                                is_found = True
                        if not is_found:
                            opencti_indicators_to_create.append(observable_data)

                # Dedup
                defender_indicators_to_delete = {
                    obj["id"]: obj for obj in reversed(defender_indicators_to_delete)
                }
                defender_indicators_to_delete = list(
                    defender_indicators_to_delete.values()
                )
                defender_indicators_to_delete_ids = [
                    defender_indicator_to_delete["id"]
                    for defender_indicator_to_delete in defender_indicators_to_delete
                ]
                self.helper.connector_logger.info(
                    "[DELETE] Deleting "
                    + str(len(defender_indicators_to_delete))
                    + " indicators..."
                )
                if len(defender_indicators_to_delete_ids) > 0:
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
                                "[DELETE] Deleted "
                                + str(len(defender_indicators_to_delete_ids_chunk))
                                + " indicators"
                            )
                        except Exception as e:
                            self.helper.connector_logger.error(
                                "Cannot delete indicators", {"error": str(e)}
                            )
                # Dedup
                opencti_indicators_to_create = {
                    obj["id"]: obj for obj in reversed(opencti_indicators_to_create)
                }
                opencti_indicators_to_create = list(
                    opencti_indicators_to_create.values()
                )
                self.helper.connector_logger.info(
                    "[CREATE] Creating "
                    + str(len(opencti_indicators_to_create))
                    + " indicators..."
                )
                if len(opencti_indicators_to_create) > 0:
                    opencti_indicators_to_create_chunked = chunker_list(
                        opencti_indicators_to_create, 500
                    )
                    for (
                        opencti_indicators_to_create_chunk
                    ) in opencti_indicators_to_create_chunked:
                        try:
                            self.api.post_indicators(opencti_indicators_to_create_chunk)
                            self.helper.connector_logger.info(
                                "[CREATE] Created "
                                + str(len(opencti_indicators_to_create_chunk))
                                + " indicators"
                            )
                        except Exception as e:
                            self.helper.connector_logger.error(
                                "Cannot create indicators", {"error": str(e)}
                            )
                self.helper.set_state(state)
            except Exception as e:
                self.helper.connector_logger.error(
                    "An error occured during the run", {"error": str(e)}
                )
            time.sleep(self.config.interval)
