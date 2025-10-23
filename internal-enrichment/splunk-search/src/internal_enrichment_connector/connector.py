from pycti import OpenCTIConnectorHelper

from .client_api import ConnectorClient
from .config_loader import ConfigConnector
from .converter_to_stix import ConverterToStix

from .splunk_client import SplunkClient
from .splunk_result_parser import parse_observables_and_incident
from .splunk_bundle import spl_indicators
from .splunk_indicators import SplunkIndicator, SplunkSearchPlan

import re
import json


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
        self.stix_objects_list = []
        self.tlp = None
        self.sighting_tlp_id = self.converter_to_stix.tlp_red.id
        self.stix_objects_list.append(self.converter_to_stix.tlp_red)
        self.author = self.converter_to_stix.create_author(self.sighting_tlp_id)
        self._send_bundle([self.author, self.converter_to_stix.tlp_red])
        self.stix_objects_list.append(self.author)
        self._load_stix_bundle(spl_indicators)

    def build_param_index(self, bundle=None) -> dict:
        """
        Build an index of parameters keyed by Indicator ID from a STIX bundle.
        If no bundle is provided, default to the module-level `spl_indicators`.
        """
        if bundle is None:
            bundle = spl_indicators

        params_by_indicator = {}
        for obj in bundle:
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

    def _load_stix_bundle(self, bundle=spl_indicators):
        searches = self.helper.api.indicator.list(
            filters={
                "mode": "and",
                "filters": [{"key": "pattern_type", "values": ["spl", "splunk"]}],
                "filterGroups": [],
            }
        )
        if not searches:
            self._send_bundle(bundle)

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
            for obj in spl_indicators:
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
                # `export` may be a STIX bundle. Extract the Indicator and keep non-Indicator
                # objects (e.g., Notes, Relationships) in the working list so they go to the bundle.
                if (
                    isinstance(export, dict)
                    and export.get("type") == "bundle"
                    and "objects" in export
                ):
                    indicator_obj = None
                    for obj in export["objects"]:
                        if obj.get("type") == "indicator" and indicator_obj is None:
                            indicator_obj = obj
                        else:
                            self.stix_objects_list.append(obj)
                    if indicator_obj:
                        indicators.append(indicator_obj)
                else:
                    # Already an indicator-like dict
                    indicators.append(export)
        return indicators

    def _run_splunk_plan(self, plan: SplunkSearchPlan):
        """
        Execute a SplunkSearchPlan and return results list (dicts).
        """
        return self.splunk_client.run_search(
            plan.query,
            earliest_time=plan.earliest,
            latest_time=plan.latest,
        )

    def _collect_stix_search(self, value, obs_type) -> list:
        """
        Collect intelligence from the source and convert into STIX objects.
        Returns the accumulated list of STIX objects (self.stix_objects_list)
        so the caller can create a bundle.
        """
        self.helper.connector_logger.info("[CONNECTOR] Starting enrichment...")
        self.helper.connector_logger.debug("[CONNECTOR] Building Search List")
        indicators = self._splunk_searches(obs_type)
        self.helper.connector_logger.debug(
            "[CONNECTOR] Search List built, running Splunk search",
            {"count": len(indicators)},
        )
        parameters = self.build_param_index()

        # Dedup guard: track IDs already added to the outgoing list
        seen_ids = set()
        for _obj in self.stix_objects_list:
            if isinstance(_obj, dict) and "id" in _obj:
                seen_ids.add(_obj["id"])

        def _add(obj) -> None:
            """Append a STIX object if not already present by id. Accepts dict, stix2 object, or JSON string."""
            if obj is None:
                return
            # Normalize JSON string → dict
            if isinstance(obj, str):
                try:
                    obj = json.loads(obj)
                except Exception:
                    return  # not valid JSON, skip
            # Normalize stix2 object → dict
            try:
                if hasattr(obj, "serialize"):
                    obj = json.loads(obj.serialize())
            except Exception:
                pass
            # Only proceed with dict-like objects that have an id (or at least a type)
            if not isinstance(obj, dict):
                return
            obj_id = obj.get("id")
            if obj_id:
                if obj_id in seen_ids:
                    return
                seen_ids.add(obj_id)
            self.stix_objects_list.append(obj)

        for indicator in indicators:
            try:
                # Normalize bundle → indicator and carry forward non-indicator objects
                if (
                    isinstance(indicator, dict)
                    and indicator.get("type") == "bundle"
                    and "objects" in indicator
                ):
                    inner = next(
                        (
                            o
                            for o in indicator["objects"]
                            if o.get("type") == "indicator"
                        ),
                        None,
                    )
                    if inner:
                        for obj in indicator["objects"]:
                            if obj is not inner:
                                _add(obj)
                        indicator = inner

                ind_id = indicator.get("id")
                search_name = indicator.get("name", "(unnamed indicator)")
                _add(indicator)

                # Insert Indicator handling

                # Guard for indicators missing a `pattern`
                pattern = indicator.get("pattern")
                if not pattern:
                    self.helper.connector_logger.warning(
                        "[SEARCH] Skipping indicator without pattern",
                        {"indicator_id": ind_id, "name": search_name},
                    )
                    continue

                # Construct a SplunkIndicator with the requested obs_type
                si = SplunkIndicator(indicator=indicator, obs_type=obs_type)

                # Load params from OpenCTI Notes (JSON content)
                si.load_params_from_notes(self.helper)

                # (Optional) overlay with defaults coming from the pre-seeded bundle
                # You built this earlier: parameters = self.build_param_index()
                bundle_params = parameters.get(ind_id, {})
                # Decide precedence: let Notes override bundle defaults (most expected)
                si.params = {**bundle_params, **si.params}

                # Render the plan using the value(s) from the observable
                values = [value] if not isinstance(value, list) else value
                try:
                    plan = si.render(values=values)
                except ValueError as e:
                    self.helper.connector_logger.warning(
                        "[SEARCH] Unresolved tokens in SPL template; skipping indicator",
                        {"indicator_id": ind_id, "error": str(e)},
                    )
                    continue

                self.helper.connector_logger.info(
                    "[SEARCH] Running Splunk search",
                    {
                        "name": search_name,
                        "earliest": plan.earliest,
                        "latest": plan.latest,
                    },
                )

                results = self._run_splunk_plan(plan)
                self.helper.connector_logger.info(
                    "[SEARCH] Splunk search returned results",
                    {"count": len(results) if results else 0},
                )

                if results:
                    for result in results:
                        self.helper.connector_logger.debug(
                            "[SEARCH] Processing result", {"result": result}
                        )
                        observables, source_identity, sightings = (
                            parse_observables_and_incident(
                                self.helper,
                                result,
                                self.author,
                                self.tlp,
                                self.sighting_tlp_id,
                            )
                        )
                        self.helper.connector_logger.debug(
                            "[SEARCH] source_identity",
                            {"source_identity": source_identity},
                        )
                        self.helper.connector_logger.debug(
                            "[SEARCH] observables", {"observables": observables}
                        )
                        self.helper.connector_logger.debug(
                            "[SEARCH] sightings", {"sightings": sightings}
                        )

                        if source_identity:
                            _add(source_identity)
                        for obs in observables or []:
                            _add(obs)
                        for s in sightings or []:
                            _add(s)
                else:
                    # Optional benign sighting / “checked but no match”
                    sighting = self.converter_to_stix.create_sighting(
                        ind_id, self.author, self.sighting_tlp_id
                    )
                    if sighting:
                        _add(sighting)

            except Exception as e:
                # Log and continue processing remaining indicators
                self.helper.connector_logger.error(
                    "[CONNECTOR] Splunk search failed",
                    {"error": str(e), "indicator_id": ind_id},
                )
                continue

        # After processing all indicators, return the full accumulated list
        return self.stix_objects_list

    def _collect_splunk_search(self, indicator) -> list:
        """
        Collect intelligence from a straight Splunk-based Indicator (pattern_type="splunk").
        Uses SplunkIndicator to render the SPL (still supports tokens if present),
        then runs and parses results.
        """
        ind_id = indicator.get("id")
        search_name = indicator.get("name", "(unnamed indicator)")
        pattern = indicator.get("pattern")

        self.helper.connector_logger.info("[CONNECTOR] Starting enrichment (SPL)")
        if not pattern:
            self.helper.connector_logger.warning(
                "[SEARCH] SPLUNK indicator missing pattern; skipping",
                {"indicator_id": ind_id, "name": search_name},
            )
            return self.stix_objects_list

        # obs_type may be embedded on the indicator; pass through
        obs_type = indicator.get("x_opencti_main_observable_type", "")
        si = SplunkIndicator(indicator=indicator, obs_type=obs_type)
        si.load_params_from_notes(self.helper)

        # After si.load_params_from_notes(self.helper)
        bundle_params = self.build_param_index().get(ind_id, {})
        # Let OpenCTI Notes override bundle defaults
        si.params = {**bundle_params, **si.params}

        # SPL indicators usually don’t substitute observable values,
        # but render() will also validate there are no unresolved tokens.
        try:
            plan = si.render(values=[])
        except ValueError as e:
            self.helper.connector_logger.warning(
                "[SEARCH] Unresolved tokens in SPL indicator; skipping",
                {"indicator_id": ind_id, "error": str(e)},
            )
            return self.stix_objects_list

        self.helper.connector_logger.info(
            "[SEARCH] Running Splunk search",
            {"name": search_name, "earliest": plan.earliest, "latest": plan.latest},
        )

        try:
            results = self._run_splunk_plan(plan)
        except Exception as e:
            self.helper.connector_logger.error(
                "[CONNECTOR] Splunk search failed", {"error": str(e)}
            )
            return self.stix_objects_list

        seen_ids = {
            o.get("id")
            for o in self.stix_objects_list
            if isinstance(o, dict) and o.get("id")
        }

        def _add(obj):
            if obj is None:
                return
            if isinstance(obj, str):
                try:
                    obj = json.loads(obj)
                except Exception:
                    return
            try:
                if hasattr(obj, "serialize"):
                    obj = json.loads(obj.serialize())
            except Exception:
                pass
            if not isinstance(obj, dict):
                return
            oid = obj.get("id")
            if oid and oid in seen_ids:
                return
            if oid:
                seen_ids.add(oid)
            self.stix_objects_list.append(obj)

        if results:
            self.helper.connector_logger.info(
                "[SEARCH] Splunk search returned results", {"count": len(results)}
            )
            for result in results:
                try:
                    observables, source_identity, sightings = (
                        parse_observables_and_incident(
                            self.helper,
                            result,
                            self.author,
                            self.tlp,
                            self.sighting_tlp_id,
                        )
                    )
                    self.helper.connector_logger.debug(
                        "[SEARCH] source_identity", {"source_identity": source_identity}
                    )
                    self.helper.connector_logger.debug(
                        "[SEARCH] observables", {"observables": observables}
                    )
                    self.helper.connector_logger.debug(
                        "[SEARCH] sightings", {"sightings": sightings}
                    )
                    _add(source_identity)
                    for obs in observables or []:
                        _add(obs)
                    for s in sightings or []:
                        _add(s)
                except Exception as e:
                    self.helper.connector_logger.error(
                        "[CONNECTOR] Result parsing failed", {"error": str(e)}
                    )
                    continue
        else:
            self.helper.connector_logger.info(
                "[SEARCH] Splunk search returned no results", {"name": search_name}
            )

        return self.stix_objects_list

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
                    self.tlp = marking_definition["standard_id"]

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
                    search = self._collect_stix_search(ind_value, ind_type)

                elif pattern_type in ("splunk", "spl"):
                    search = self._collect_splunk_search(indicator)
                self.helper.connector_logger.info(
                    "[CONNECTOR] STIX objects created", {"count": len(search)}
                )

                if search is not None and len(search):
                    self.helper.connector_logger.debug(
                        "[CONNECTOR] STIX objects created", {"objects": search}
                    )
                    return self._send_bundle(self.stix_objects_list)
                else:
                    info_msg = "[CONNECTOR] No information found"
                    return info_msg
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
