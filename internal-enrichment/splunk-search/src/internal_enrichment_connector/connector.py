from pycti import OpenCTIConnectorHelper

from .client_api import ConnectorClient
from .config_loader import ConfigConnector
from .converter_to_stix import ConverterToStix

from .splunk_client import SplunkClient
from .splunk_result_parser import parse_observables_and_incident
from .splunk_bundle import full_bundle

import re


class ConnectorTemplate:
    """
    Specifications of the internal enrichment connector

    This class encapsulates the main actions, expected to be run by any internal enrichment connector.
    Note that the attributes defined below will be complemented per each connector type.
    This type of connector aim to enrich a data (Observables) created or modified in the OpenCTI core platform.
    It will create a STIX bundle and send it in a RabbitMQ queue.
    The STIX bundle in the queue will be processed by the workers.
    This type of connector uses the basic methods of the helper.
    Ingesting a bundle allow the connector to be compatible with the playbook automation feature.


    ---

    Attributes
        - `config (ConfigConnector())`:
            Initialize the connector with necessary configuration environment variables

        - `helper (OpenCTIConnectorHelper(config))`:
            This is the helper to use.
            ALL connectors have to instantiate the connector helper with configurations.
            Doing this will do a lot of operations behind the scene.

        - `converter_to_stix (ConnectorConverter(helper))`:
            Provide methods for converting various types of input data into STIX 2.1 objects.

    ---

    Best practices
        - `self.helper.connector_logger.[info/debug/warning/error]` is used when logging a message
        - `self.helper.stix2_create_bundle(stix_objects)` is used when creating a bundle
        - `self.helper.send_stix2_bundle(stix_objects_bundle)` is used to send the bundle to RabbitMQ

    """

    def __init__(self, config: ConfigConnector, helper: OpenCTIConnectorHelper):
        """
        Initialize the Connector with necessary configurations
        """

        # Load configuration file and connection helper
        self.config = config
        self.helper = helper
        self.client = ConnectorClient(self.helper, self.config)
        self.converter_to_stix = ConverterToStix(self.helper)
        self.splunk_client = SplunkClient(
            self.config.api_base_url, self.config.api_key, self.config.verify_ssl
        )

        # Define variables
        self.author = self.converter_to_stix.create_author()
        self.tlp = None
        self.stix_objects_list = []

    def build_param_index(bundle=full_bundle) -> dict:
        params_by_indicator = {}
        for obj in bundle.get("objects", []):
            if obj.get("type") != "note":
                continue
            if "object_refs" not in obj:
                continue
            try:
                params = json.loads(obj.get("content", ""))
            except Exception:
                continue
            for ref in obj["object_refs"]:
                if ref.startswith("indicator--"):
                    params_by_indicator[ref] = params
        return params_by_indicator

    def _splunk_searches(self, obs_type) -> list:
        """
        Perform a Splunk search and return the results as a list of STIX objects.
        This method is expected to be overridden by specific connector implementations.
        """
        label = self.helper.api.label.list(
            filters={
                "mode": "and",
                "filters": [{"key": "value", "values": ["threat-hunting-splunk"]}],
                "filterGroups": [],
            }
        )
        if not label:
            try:
                created_label = self.helper.api.label.create(
                    value="threat-hunting-splunk", color="#FF0000"
                )
                label_id = created_label["id"]
            except Exception as e:
                self.helper.connector_logger.error(
                    "[CONNECTOR] Error creating label", {"error": str(e)}
                )
                return []
        else:
            label_id = label[0]["id"]
        searches = self.helper.api.indicator.list(
            filters={
                "mode": "and",
                "filters": [
                    {
                        "key": "entity_type",
                        "values": ["Indicator"],
                        "operator": "eq",
                        "mode": "or",
                    }
                ],
                "filterGroups": [
                    {
                        "mode": "and",
                        "filters": [
                            {
                                "key": "pattern_type",
                                "operator": "eq",
                                "values": ["splunk"],
                                "mode": "or",
                            },
                            {
                                "key": "objectLabel",
                                "operator": "eq",
                                "values": [label_id],
                                "mode": "or",
                            },
                            {
                                "key": "x_opencti_main_observable_type",
                                "operator": "eq",
                                "values": [obs_type],
                                "mode": "or",
                            },
                        ],
                        "filterGroups": [],
                    }
                ],
            }
        )
        indicators = []
        if not searches:
            self.helper.connector_logger.info(
                "[CONNECTOR] No Splunk searches found, returning predefined indicators."
            )
            for obj in full_bundle.get("objects", []):
                if obj.get("type") != "indicator":
                    self.stix_objects_list.append(obj)
                    continue

                obj_type = obj.get("x_opencti_main_observable_type", "").lower()
                requested_type = obs_type.lower()

                if obj_type == requested_type:
                    self.helper.connector_logger.debug(
                        "Adding predefined indicator", {"object": obj["id"]}
                    )
                    indicators.append(obj)
                else:
                    self.helper.connector_logger.debug(
                        "Skipping indicator due to mismatched type",
                        {
                            "object": obj["id"],
                            "expected": requested_type,
                            "found": obj_type,
                        },
                    )
        else:
            self.helper.connector_logger.info(
                "[CONNECTOR] Found Splunk searches in OpenCTI"
            )
            for search in searches:
                search_id = search["id"]
                export = self.helper.api.stix2.get_stix_bundle_or_object_from_entity_id(
                    entity_id=search_id, entity_type="Indicator", mode="simple"
                )
                indicators.append(export)
        return indicators

    def _render_spl(self, spl: str, value, obs_type: str, indicator_id: str) -> str:
        """
        Render a Splunk SPL template by substituting placeholders with the provided observables.
        Supports both legacy <PLACEHOLDER> tokens and {{token}} style.
        - value: str or List[str]
        - obs_type: e.g., "ipv4-addr", "domain-name", etc.
        - indicator_id: the STIX indicator id
        """
        # Normalize value(s)
        if isinstance(value, list):
            values = [str(v) for v in value]
            value_str = values[0] if values else ""
        else:
            value_str = str(value) if value is not None else ""
            values = [value_str] if value_str else []

        # CSV suitable for SPL IN (...) lists, quoted
        values_csv = ",".join([f'"{v}"' for v in values]) if values else ""

        # Legacy angle-bracket placeholders (back-compat)
        mapping = {
            "<VALUE>": value_str,
            "<VALUE_LIST>": values_csv,
            "<OBS_VALUE>": value_str,
            "<OBS_LIST>": values_csv,
            "<INDICATOR_ID>": indicator_id,
            # Common synonyms
            "<IP_ADDRESS>": value_str,
            "<IP_LIST>": values_csv,
            "<HOSTNAME>": value_str,
            "<HOSTNAME_LIST>": values_csv,
            "<DOMAIN>": value_str,
            "<DOMAIN_LIST>": values_csv,
        }

        for k, v in mapping.items():
            spl = spl.replace(k, v)

        # Mustache-style {{token}} placeholders
        mustache_map = {
            "value": value_str,
            "values_csv": values_csv,
            "indicator_id": indicator_id,
            "obs_type": obs_type,
        }

        def _mustache_sub(match):
            key = match.group(1).strip().lower()
            return mustache_map.get(key, match.group(0))

        spl = re.sub(r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}", _mustache_sub, spl)
        return spl

    def _collect_stix_search(self, value, obs_type) -> list:
        """
        Collect intelligence from the source and convert into STIX object
        :return: List of STIX objects
        """
        self.helper.connector_logger.info("[CONNECTOR] Starting enrichment...")
        self.helper.connector_logger.debug("[CONNECTOR] Building Search List")
        indicators = self._splunk_searches(obs_type)
        search_results = []
        self.helper.connector_logger.debug(
            "[CONNECTOR] Search List built, running Splunk search",
            {"count": len(indicators)},
        )
        parameters = self.build_param_index()
        for indicator in indicators:

            ind_id = indicator["id"]
            search_name = indicator["name"]
            self.stix_objects_list.append(indicator)
            query = self._render_spl(indicator["pattern"], value, obs_type, ind_id)
            self.helper.connector_logger.info(
                "[SEARCH] Running Splunk search", {"name": search_name}
            )
            # Run the Splunk search and parse results
            try:
                results = self.splunk_client.run_search(
                    query, earliest_time=0, latest_time="now"
                )
                self.helper.connector_logger.info(
                    "[SEARCH] Splunk search returned results",
                    {"count": len(results)},
                )
                if results:
                    for result in results:
                        self.helper.connector_logger.debug(
                            "[SEARCH] Processing result", {"result": result}
                        )
                        processed_results = parse_observables_and_incident(
                            result, self.author, self.tlp
                        )
                        # stix_obj = self.converter_to_stix.create_from_result(result)
                        # self.stix_objects_list.append(stix_obj)
                        # Create Sighting object for the original indicator
                        # sighting = self.converter_to_stix.create_sighting(
                        #    ind_id, self.author, self.tlp
                        # )
                        # self.stix_objects_list.append(sighting)
                        # Optionally create an Incident from the result
                        # incident = self.converter_to_stix.create_incident_from_result(
                        #     result, self.author, self.tlp
                        # )
                        # if incident:
                        #    self.stix_objects_list.append(incident)
                        return self.stix_objects_list
                else:
                    self.helper.connector_logger.info(
                        "[SEARCH] Splunk search returned no results",
                        {"name": search_name},
                    )
                    sighting = self.converter_to_stix.create_sighting(
                        ind_id, self.author, self.tlp
                    )
                    return [sighting]

            except Exception as e:
                self.helper.connector_logger.error(
                    "[CONNECTOR] Splunk search failed", {"error": str(e)}
                )
                return []

    def _collect_splunk_search(self, indicator) -> list:
        """
        Collect intelligence from the source and convert into STIX object
        :return: List of STIX objects
        """
        query = indicator["pattern"]
        ind_id = indicator["id"]
        search_name = indicator["name"]
        self.helper.connector_logger.info("[CONNECTOR] Starting enrichment...")
        self.helper.connector_logger.info(
            "[SEARCH] Running Splunk search", {"name": search_name}
        )
        # Run the Splunk search and parse results
        search_results = []
        try:
            results = self.splunk_client.run_search(
                query,
            )
            if results:
                self.helper.connector_logger.info(
                    "[SEARCH] Splunk search returned results",
                    {"count": len(results)},
                )
                search_results.append(incident)
                for result in search_results:
                    stix_obj = self.converter_to_stix.create_from_result(result)
                    self.stix_objects_list.append(stix_obj)
                    # Create Sighting object for the original indicator
                    sighting = self.converter_to_stix.create_sighting(
                        ind_id, self.author, self.tlp
                    )
                    self.stix_objects_list.append(sighting)
                    # Optionally create an Incident from the result
                    incident = self.converter_to_stix.create_incident_from_result(
                        result, self.author, self.tlp
                    )
                    if incident:
                        self.stix_objects_list.append(incident)
                    return self.stix_objects_list
            else:
                self.helper.connector_logger.info(
                    "[SEARCH] Splunk search returned no results",
                    {"name": search_name},
                )
                sighting = self.converter_to_stix.create_sighting(
                    ind_id, self.author, self.tlp
                )
        except Exception as e:
            self.helper.connector_logger.error(
                "[CONNECTOR] Splunk search failed", {"error": str(e)}
            )
        raise NotImplementedError

    def entity_in_scope(self, data) -> bool:
        """
        Security to limit playbook triggers to something other than the initial scope
        :param data: Dictionary of data
        :return: boolean
        """
        scopes = self.helper.connect_scope.lower().replace(" ", "").split(",")
        entity_split = data["entity_id"].split("--")
        entity_type = entity_split[0].lower()

        if entity_type in scopes:
            return True
        else:
            return False

    def extract_and_check_markings(self, opencti_entity: dict) -> None:
        """
        Extract TLP, and we check if the variable "max_tlp" is less than
        or equal to the markings access of the entity from OpenCTI
        If this is true, we can send the data to connector for enrichment.
        :param opencti_entity: Dict of observable from OpenCTI
        :return: Boolean
        """
        if len(opencti_entity["objectMarking"]) != 0:
            for marking_definition in opencti_entity["objectMarking"]:
                if marking_definition["definition_type"] == "TLP":
                    self.tlp = marking_definition["definition"]
                    print(self.tlp)

        valid_max_tlp = self.helper.check_max_tlp(self.tlp, self.config.max_tlp)

        if not valid_max_tlp:
            raise ValueError(
                "[CONNECTOR] Do not send any data, TLP of the observable is greater than MAX TLP,"
                "the connector does not has access to this observable, please check the group of the connector user"
            )

    def process_message(self, data: dict) -> str:
        """
        Get the observable created/modified in OpenCTI and check which type to send for process
        The data passed in the data parameter is a dictionary with the following structure as shown in
        https://docs.opencti.io/latest/development/connectors/#additional-implementations
        :param data: dict of data to process
        :return: string
        """
        try:
            opencti_entity = data["enrichment_entity"]
            self.extract_and_check_markings(opencti_entity)

            # To enrich the data, you can add more STIX object in stix_objects
            self.stix_objects_list = data["stix_objects"]
            indicator = data["stix_entity"]

            # Extract information from entity data
            pattern_type = indicator["pattern_type"]

            info_msg = (
                "[CONNECTOR] Processing indicator for the following pattern type: "
            )
            self.helper.connector_logger.info(info_msg, {"type": {pattern_type}})
            self.helper.connector_logger.debug(
                "[CONNECTOR] Processing indicator", {"indicator": indicator}
            )
            if self.entity_in_scope(data):
                if pattern_type == "stix":
                    ind_standard_id = indicator["id"]
                    ind_value = indicator["x_opencti_observable_values"][0]["value"]
                    ind_type = indicator.get(
                        "x_opencti_main_observable_type", ""
                    ).lower()
                    stix_objects = self._collect_stix_search(ind_value, ind_type)

                elif pattern_type == "splunk":
                    stix_objects = self._collect_intelligence(
                        ind_standard_id, ind_value, ind_type
                    )

                if stix_objects is not None and len(stix_objects):
                    return self._send_bundle(stix_objects)
                else:
                    info_msg = "[CONNECTOR] No information found"
                    return info_msg

                # ===========================
                # === Add your code above ===
                # ===========================
            else:
                if not data.get("event_type"):
                    # If it is not in scope AND entity bundle passed through playbook, we should return the original bundle unchanged
                    self._send_bundle(self.stix_objects_list)
                else:
                    # self.helper.connector_logger.info(
                    #     "[CONNECTOR] Skip the following entity as it does not concern "
                    #     "the initial scope found in the config connector: ",
                    #     {"entity_id": opencti_entity["entity_id"]},
                    # )
                    raise ValueError(
                        f"Failed to process observable, {opencti_entity['entity_type']} is not a supported entity type."
                    )
        except Exception as err:
            # Handling other unexpected exceptions
            return self.helper.connector_logger.error(
                "[CONNECTOR] Unexpected Error occurred", {"error_message": str(err)}
            )

    def _send_bundle(self, stix_objects: list) -> str:
        stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
        bundles_sent = self.helper.send_stix2_bundle(stix_objects_bundle)

        info_msg = (
            "Sending " + str(len(bundles_sent)) + " stix bundle(s) for worker import"
        )
        return info_msg

    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors a message queue associated with a specific connector
        The connector have to listen a specific queue to get and then enrich the information.
        The helper provide an easy way to listen to the events.
        """
        self.helper.listen(message_callback=self.process_message)
