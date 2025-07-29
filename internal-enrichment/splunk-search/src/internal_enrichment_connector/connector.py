<<<<<<< HEAD
import re
from copy import deepcopy
from typing import Any

import stix2
from pycti import OpenCTIConnectorHelper

from .services import SplunkClient
from .splunk_bundle import spl_indicators
from .splunk_indicators import SplunkIndicator
from .splunk_result_parser import parse_observables_and_incident


SPLUNK_TEMPLATE_LABEL = "threat-hunting-splunk"
SPLUNK_PATTERN_TYPE = "spl"


class SplunkSearchConnector:
    def __init__(self, helper: OpenCTIConnectorHelper, config):
        self.helper = helper
        self.config = config
        self.splunk_client = SplunkClient(
            host=config.splunk_host,
            port=config.splunk_port,
            token=config.splunk_token,
            app=config.splunk_app,
            scheme=config.splunk_scheme,
            verify=config.splunk_verify_ssl,
        )
        self.author = self._load_author_identity()

    def _load_author_identity(self):
        for obj in spl_indicators:
            if (
                obj.get("type") == "identity"
                and obj.get("identity_class") == "organization"
                and obj.get("name") == "Splunk"
            ):
                return stix2.parse(obj, allow_custom=True)
        raise ValueError("Splunk author identity not found in default bundle")

    @staticmethod
    def _indicator_filters(observable_type: str | None = None) -> dict:
        filters = [
            {"key": "pattern_type", "values": [SPLUNK_PATTERN_TYPE], "operator": "eq"},
            {
                "key": "objectLabel",
                "values": [SPLUNK_TEMPLATE_LABEL],
                "operator": "eq",
            },
        ]
        if observable_type:
            filters.append(
                {
                    "key": "x_opencti_main_observable_type",
                    "values": [observable_type],
                    "operator": "eq",
                }
            )
        return {"mode": "and", "filters": filters, "filterGroups": []}

    def _seed_default_searches(self):
        filters = self._indicator_filters()
        existing = self.helper.api.indicator.list(filters=filters, first=500) or []
        if existing:
            self.helper.connector_logger.info(
                f"Found {len(existing)} existing SPL search templates, skipping seed"
            )
            return

        indicator_ids = [
            obj["id"] for obj in spl_indicators if obj.get("type") == "indicator"
        ]
        bundle_objects = []
        for obj in spl_indicators:
            normalized = deepcopy(obj)
            if normalized.get("type") == "note" and not normalized.get("object_refs"):
                normalized["object_refs"] = indicator_ids
            bundle_objects.append(normalized)

        objects = [stix2.parse(obj, allow_custom=True) for obj in bundle_objects]
        bundle = stix2.Bundle(objects=objects, allow_custom=True)
        self.helper.send_stix2_bundle(bundle.serialize(), update=True)
        seeded_count = len(indicator_ids)
        self.helper.connector_logger.info(
            f"Seeded {seeded_count} default SPL search templates"
        )

    def _get_search_templates(self, observable_type: str) -> list:
        return (
            self.helper.api.indicator.list(
                filters=self._indicator_filters(observable_type),
                first=500,
                orderBy="created_at",
                orderMode="asc",
            )
            or []
        )

    @staticmethod
    def _obj_get(obj: Any, key: str, default=None):
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    @classmethod
    def _extract_from_file(cls, obj) -> list[str]:
        hashes = cls._obj_get(obj, "hashes", {}) or {}
        values = []
        for algo in ("SHA-256", "SHA-1", "MD5"):
            if isinstance(hashes, dict) and hashes.get(algo):
                values.append(str(hashes[algo]))
        return values

    def _extract_observable_values(
        self, entity: dict, stix_objects: list, obs_type: str
    ) -> list:
        type_map = {
            "IPv4-Addr": ("ipv4-addr", "value"),
            "IPv6-Addr": ("ipv6-addr", "value"),
            "Domain-Name": ("domain-name", "value"),
            "Hostname": ("x-opencti-hostname", "value"),
            "Url": ("url", "value"),
            "Email-Addr": ("email-addr", "value"),
        }

        values = []
        expected = type_map.get(obs_type)
        for obj in stix_objects or []:
            obj_type = self._obj_get(obj, "type")
            if obs_type == "StixFile" and obj_type == "file":
                values.extend(self._extract_from_file(obj))
            elif expected and obj_type == expected[0]:
                value = self._obj_get(obj, expected[1])
                if value:
                    values.append(str(value))

        if values:
            return list(dict.fromkeys(values))

        if entity.get("pattern_type") == "stix":
            match = re.search(r"=\s*'([^']+)'", entity.get("pattern", ""))
            if match:
                return [match.group(1)]

        return []

    def _process_message(self, data: dict) -> str:
        entity = data.get("enrichment_entity", {})
        stix_objects = data.get("stix_objects", [])
        pattern_type = entity.get("pattern_type", "")
        obs_type = entity.get("x_opencti_main_observable_type", "")

        if pattern_type == "stix":
            return self._enrich_stix_indicator(entity, stix_objects, obs_type)
        if pattern_type == "spl":
            return self._enrich_spl_indicator(entity, stix_objects, obs_type)

        msg = f"Unsupported pattern_type '{pattern_type}', skipping"
        self.helper.connector_logger.warning(msg)
        return msg

    def _parse_result_rows(self, rows: list[dict]) -> list:
        all_objects = [self.author]
        for row in rows:
            observables, source_identity, sightings = parse_observables_and_incident(
                self.helper,
                row,
                self.author,
                marking_id=self.config.observable_tlp,
                sighting_marking_id=self.config.sighting_tlp,
            )
            all_objects.extend(observables)
            all_objects.extend(sightings)
            if source_identity:
                all_objects.append(source_identity)
        return all_objects

    def _send_results(self, all_objects: list) -> None:
        if len(all_objects) > 1:
            bundle = stix2.Bundle(objects=all_objects, allow_custom=True)
            self.helper.send_stix2_bundle(bundle.serialize(), update=True)

    def _run_search_for_indicator(self, indicator: dict, obs_type: str, values: list):
        splunk_indicator = SplunkIndicator(indicator, obs_type)
        splunk_indicator.load_params_from_notes(self.helper)
        if "earliest_time" in splunk_indicator.params:
            splunk_indicator.params["earliest"] = splunk_indicator.params[
                "earliest_time"
            ]
        if "latest_time" in splunk_indicator.params:
            splunk_indicator.params["latest"] = splunk_indicator.params["latest_time"]
        plan = splunk_indicator.render(values)
        timeout = int(splunk_indicator.params.get("timeout", self.config.splunk_timeout))
        wait_seconds = int(
            splunk_indicator.params.get(
                "wait_seconds", self.config.splunk_wait_seconds
            )
        )
        max_results = int(
            splunk_indicator.params.get("max_results", self.config.splunk_max_results)
        )
        return self.splunk_client.run_search(
            query=plan.query,
            earliest_time=plan.earliest,
            latest_time=plan.latest,
            timeout=timeout,
            wait_seconds=wait_seconds,
            max_results=max_results,
        )

    def _enrich_stix_indicator(self, entity, stix_objects, obs_type) -> str:
        values = self._extract_observable_values(entity, stix_objects, obs_type)
        if not values:
            return f"No observable values found for {obs_type}"

        templates = self._get_search_templates(obs_type)
        if not templates:
            return f"No SPL search templates found for observable type {obs_type}"

        all_objects = [self.author]
        searches_run = 0
        total_results = 0
        for template in templates:
            try:
                results = self._run_search_for_indicator(template, obs_type, values)
                searches_run += 1
                total_results += len(results)
                all_objects.extend(self._parse_result_rows(results)[1:])
            except Exception as exc:
                self.helper.connector_logger.error(
                    f"Search failed for template '{template.get('name', '?')}': {exc}"
                )
                continue

        self._send_results(all_objects)
        return (
            f"Ran {searches_run} searches, {total_results} results, "
            f"{len(all_objects) - 1} STIX objects"
        )

    def _enrich_spl_indicator(self, entity, stix_objects, obs_type) -> str:
        values = (
            self._extract_observable_values(entity, stix_objects, obs_type)
            if obs_type
            else []
        )
        results = self._run_search_for_indicator(entity, obs_type, values)
        all_objects = self._parse_result_rows(results)
        self._send_results(all_objects)
        return f"SPL direct: {len(results)} results, {len(all_objects) - 1} STIX objects"

    def run(self):
        self._seed_default_searches()
        self.helper.listen(message_callback=self._process_message)
=======
from pycti import OpenCTIConnectorHelper

from .client_api import ConnectorClient
from .config_loader import ConfigConnector
from .converter_to_stix import ConverterToStix

from .splunk_client import SplunkClient
from .splunk_result_parser import parse_observables_and_incident
from .splunk_searches import OpenCTIIndicatorFetcher


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
        self.splunk_client = SplunkClient(self.config)

        # Define variables
        self.author = self.converter_to_stix.create_author()
        self.tlp = None
        self.stix_objects_list = []

    def _collect_intelligence(self, value, obs_type) -> list:
        """
        Collect intelligence from the source and convert into STIX object
        :return: List of STIX objects
        """
        self.helper.connector_logger.info("[CONNECTOR] Starting enrichment...")

        searches = OpenCTIIndicatorFetcher.fetch_indicators(self.helper, obs_type)

        try:
            results = self.splunk_client.run_search(query)
        except Exception as e:
            self.helper.connector_logger.error(
                "[CONNECTOR] Splunk search failed", {"error": str(e)}
            )
            return []

        for result in results:
            stix_obj = self.converter_to_stix.create_from_result(result)
            self.stix_objects_list.append(stix_obj)
            # Create Sighting object for the original indicator
            sighting = self.converter_to_stix.create_sighting(
                obs_id, self.author, self.tlp
            )
            self.stix_objects_list.append(sighting)
            # Optionally create an Incident from the result
            incident = self.converter_to_stix.create_incident_from_result(
                result, self.author, self.tlp
            )
            if incident:
                self.stix_objects_list.append(incident)
            return self.stix_objects_list
        # ===========================
        # === Add your code below ===
        # ===========================

        # EXAMPLE
        # === Get entities from external sources based on entity value
        # entities = self.client.get_entity(value)

        # === Create the author
        # self.author = self.converter.create_author()

        # === Convert into STIX2 object and add it to the stix_object_list
        # entity_to_stix = self.converter_to_stix.create_obs(value,obs_id)
        # self.stix_object_list.append(entity_to_stix)

        # return self.stix_objects_list

        # ===========================
        # === Add your code above ===
        # ===========================
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
            observable = data["stix_entity"]

            # Extract information from entity data
            obs_standard_id = observable["id"]
            obs_value = observable["value"]
            obs_type = observable["type"]

            info_msg = (
                "[CONNECTOR] Processing observable for the following entity type: "
            )
            self.helper.connector_logger.info(info_msg, {"type": {obs_type}})

            if self.entity_in_scope(data):
                # Performing the collection of intelligence and enrich the entity
                # ===========================
                # === Add your code below ===
                # ===========================

                # EXAMPLE Collect intelligence and enrich current STIX object
                stix_objects = self._collect_intelligence(obs_value, obs_type)

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
>>>>>>> 7a60e94c2a (Init splunk-search connector)
