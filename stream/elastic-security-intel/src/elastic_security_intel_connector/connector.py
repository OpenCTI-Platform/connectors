"""
Elastic Security Intel Stream Connector

This connector streams threat intelligence from OpenCTI to Elastic Security,
creating, updating, and deleting threat indicators in Elastic's threat intelligence index.
It also supports custom pattern types for Elastic query languages.
"""

import json
from json import JSONDecodeError
from typing import Dict, List, Optional

from pycti import OpenCTIConnectorHelper

from .api_handler import ElasticApiHandler, ElasticApiHandlerError
from .config_variables import ConfigConnector
from .utils import FILE_HASH_TYPES_MAPPER, is_observable, is_stix_indicator


class ElasticSecurityIntelConnector:
    """
    Elastic Security Intel Stream Connector

    This connector listens to the OpenCTI live stream and synchronizes threat intelligence
    indicators with Elastic Security's threat intelligence index and creates SIEM rules
    for pattern-based indicators.
    """

    def __init__(self):
        """Initialize the connector with necessary configurations"""

        # Load configuration and create helper
        self.config = ConfigConnector()
        self.helper = OpenCTIConnectorHelper(self.config.load)
        self.api = ElasticApiHandler(self.helper, self.config)

        # Test connection on startup (optional - log warning if fails but continue)
        if not self.api.test_connection():
            self.helper.connector_logger.warning(
                "Could not verify connection to Elastic Security. Will attempt operations anyway."
            )

        # Setup index template with proper mappings
        if self.api.setup_index_template():
            self.helper.connector_logger.info("Index template configured successfully")
        else:
            self.helper.connector_logger.warning(
                "Failed to setup index template - will continue with default mappings"
            )

        # Initialize vocabulary for Elastic pattern types
        self._initialize_pattern_type_vocabulary()

        self.helper.connector_logger.info(
            "Elastic Security Intel connector initialized",
            {
                "elastic_url": self.config.elastic_url,
                "index_name": self.config.elastic_index_name,
            },
        )

    def _initialize_pattern_type_vocabulary(self) -> None:
        """
        Create vocabulary entries for Elastic-specific pattern types
        """
        pattern_types = [
            {
                "name": "kql",
                "description": "Kibana Query Language (KQL) - Simplified query syntax for Kibana",
            },
            {
                "name": "lucene",
                "description": "Lucene Query Syntax - Full Lucene query language for advanced searching",
            },
            {
                "name": "eql",
                "description": "Event Query Language (EQL) - Language for event-based searches and correlations",
            },
            {
                "name": "esql",
                "description": "Elasticsearch SQL (ES|QL) - SQL-like query language for Elasticsearch",
            },
        ]

        for pattern_type in pattern_types:
            try:
                # Create or get the vocabulary entry
                vocab = self.helper.api.vocabulary.read(
                    filters={
                        "mode": "and",
                        "filters": [
                            {"key": "category", "values": ["pattern_type_ov"]},
                            {"key": "name", "values": [pattern_type["name"]]},
                        ],
                        "filterGroups": [],
                    }
                )

                if vocab is None:
                    vocab = self.helper.api.vocabulary.create(
                        name=pattern_type["name"],
                        description=pattern_type["description"],
                        category="pattern_type_ov",
                    )
                    self.helper.connector_logger.info(
                        f"Created pattern type vocabulary: {pattern_type['name']}"
                    )
                else:
                    self.helper.connector_logger.debug(
                        f"Pattern type vocabulary already exists: {pattern_type['name']}"
                    )

            except Exception as e:
                self.helper.connector_logger.warning(
                    f"Failed to create pattern type vocabulary for {pattern_type['name']}: {str(e)}"
                )

    def _check_stream_id(self) -> None:
        """
        Validate that stream_id is properly configured
        :raises ValueError: If stream_id is missing or invalid
        """
        if (
            self.helper.connect_live_stream_id is None
            or self.helper.connect_live_stream_id == "ChangeMe"
        ):
            raise ValueError("Missing stream ID, please check your configurations.")

    def _convert_indicator_to_observables(self, data: dict) -> List[dict]:
        """
        Convert an OpenCTI indicator to its corresponding observables
        :param data: OpenCTI indicator data
        :return: List of observable data dictionaries
        """
        try:
            observables = []
            parsed_observables = self.helper.get_attribute_in_extension(
                "observable_values", data
            )

            if parsed_observables:
                for observable in parsed_observables:
                    observable_data = {}
                    observable_data.update(data)
                    x_opencti_observable_type = observable.get("type", "").lower()

                    if x_opencti_observable_type != "stixfile":
                        observable_data["type"] = x_opencti_observable_type
                        observable_data["value"] = observable.get("value")
                        observables.append(observable_data)
                    else:
                        # Handle file observables with hashes
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

        except Exception as e:
            indicator_id = OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
            self.helper.connector_logger.warning(
                f"Cannot convert STIX indicator {indicator_id}: {str(e)}"
            )
            return []

    def _process_observable_batch(
        self, observables: List[dict], operation: str
    ) -> None:
        """
        Process a batch of observables
        :param observables: List of observables to process
        :param operation: Operation type (create, update, delete)
        """
        if not observables:
            return

        batch_size = self.config.batch_size

        for i in range(0, len(observables), batch_size):
            batch = observables[i : i + batch_size]

            try:
                if operation == "create" and len(batch) > 1:
                    # Use bulk operation for multiple creates
                    result = self.api.bulk_create_indicators(batch)
                    self.helper.connector_logger.info(
                        f"Bulk created {result['created']} indicators",
                        {"errors": len(result.get("errors", []))},
                    )
                else:
                    # Process individually
                    for observable in batch:
                        if operation == "create":
                            self.api.create_indicator(observable)
                        elif operation == "update":
                            self.api.update_indicator(observable)
                        elif operation == "delete":
                            self.api.delete_indicator(observable)

            except ElasticApiHandlerError as e:
                self.helper.connector_logger.error(
                    f"Batch operation failed: {e.msg}", e.metadata
                )

    def _handle_create_event(self, data: dict) -> None:
        """
        Handle create event by creating threat indicators and/or SIEM rules in Elastic
        :param data: Streamed data (observable or indicator)
        """
        opencti_id = OpenCTIConnectorHelper.get_attribute_in_extension("id", data)

        if is_stix_indicator(data):
            # Check if this is a pattern-based indicator
            if "pattern" in data:
                # Process as SIEM rule and threat intel
                self.helper.connector_logger.info(
                    f"[CREATE] Processing pattern-based indicator",
                    {
                        "opencti_id": opencti_id,
                        "pattern_type": data.get("pattern_type", "stix"),
                    },
                )
                self.api.process_indicator(data, "create")
            else:
                # Convert to observables for threat intel only
                observables = self._convert_indicator_to_observables(data)
                if observables:
                    self.helper.connector_logger.info(
                        f"[CREATE] Processing {len(observables)} observables from indicator",
                        {"opencti_id": opencti_id},
                    )
                    self._process_observable_batch(observables, "create")
        elif is_observable(data):
            self.helper.connector_logger.info(
                f"[CREATE] Processing observable",
                {"opencti_id": opencti_id, "type": data.get("type")},
            )
            self._process_observable_batch([data], "create")

    def _handle_update_event(self, data: dict) -> None:
        """
        Handle update event by updating threat indicators and/or SIEM rules in Elastic
        :param data: Streamed data (observable or indicator)
        """
        opencti_id = OpenCTIConnectorHelper.get_attribute_in_extension("id", data)

        if is_stix_indicator(data):
            # Check if this is a pattern-based indicator
            if "pattern" in data:
                # Process as SIEM rule and threat intel
                self.helper.connector_logger.info(
                    f"[UPDATE] Processing pattern-based indicator",
                    {
                        "opencti_id": opencti_id,
                        "pattern_type": data.get("pattern_type", "stix"),
                    },
                )
                self.api.process_indicator(data, "update")
            else:
                # Convert to observables for threat intel only
                observables = self._convert_indicator_to_observables(data)
                if observables:
                    self.helper.connector_logger.info(
                        f"[UPDATE] Processing {len(observables)} observables from indicator",
                        {"opencti_id": opencti_id},
                    )
                    self._process_observable_batch(observables, "update")
        elif is_observable(data):
            self.helper.connector_logger.info(
                f"[UPDATE] Processing observable",
                {"opencti_id": opencti_id, "type": data.get("type")},
            )
            self._process_observable_batch([data], "update")

    def _handle_delete_event(self, data: dict) -> None:
        """
        Handle delete event by removing threat indicators and/or SIEM rules from Elastic
        :param data: Streamed data (observable or indicator)
        """
        opencti_id = OpenCTIConnectorHelper.get_attribute_in_extension("id", data)

        if is_stix_indicator(data):
            # Check if this is a pattern-based indicator
            if "pattern" in data:
                # Process as SIEM rule and threat intel
                self.helper.connector_logger.info(
                    f"[DELETE] Processing pattern-based indicator",
                    {
                        "opencti_id": opencti_id,
                        "pattern_type": data.get("pattern_type", "stix"),
                    },
                )
                self.api.process_indicator(data, "delete")
            else:
                # Convert to observables for threat intel only
                observables = self._convert_indicator_to_observables(data)
                if observables:
                    self.helper.connector_logger.info(
                        f"[DELETE] Processing {len(observables)} observables from indicator",
                        {"opencti_id": opencti_id},
                    )
                    self._process_observable_batch(observables, "delete")
        elif is_observable(data):
            self.helper.connector_logger.info(
                f"[DELETE] Processing observable",
                {"opencti_id": opencti_id, "type": data.get("type")},
            )
            self._process_observable_batch([data], "delete")

    def validate_json(self, msg) -> Dict:
        """
        Validate and parse JSON data from the stream
        :param msg: Message event from stream
        :return: Parsed JSON data
        :raises JSONDecodeError: If JSON data cannot be parsed
        """
        try:
            parsed_msg = json.loads(msg.data)
            return parsed_msg
        except json.JSONDecodeError:
            self.helper.connector_logger.error(
                "Data cannot be parsed to JSON", {"msg_data": msg.data}
            )
            raise JSONDecodeError("Data cannot be parsed to JSON", msg.data, 0)

    def process_message(self, msg) -> None:
        """
        Process incoming stream messages

        The data structure follows the OpenCTI stream format documented at:
        https://docs.opencti.io/latest/development/connectors/#additional-implementations

        :param msg: Message event from stream
        """
        try:
            self._check_stream_id()

            parsed_msg = self.validate_json(msg)
            data = parsed_msg.get("data", {})

            # Log the event type and entity
            entity_type = data.get("type", "unknown")
            entity_id = OpenCTIConnectorHelper.get_attribute_in_extension("id", data)

            self.helper.connector_logger.debug(
                f"Processing {msg.event} event",
                {
                    "event": msg.event,
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                },
            )

            # Route to appropriate handler based on event type
            if msg.event == "create":
                self._handle_create_event(data)
            elif msg.event == "update":
                self._handle_update_event(data)
            elif msg.event == "delete":
                self._handle_delete_event(data)
            else:
                self.helper.connector_logger.debug(f"Ignoring event type: {msg.event}")

        except ElasticApiHandlerError as e:
            self.helper.connector_logger.error(
                f"Elastic API error: {e.msg}", e.metadata
            )
        except Exception as e:
            self.helper.connector_logger.error(
                f"Failed processing message: {str(e)}", {"msg": str(msg)}
            )

    def run(self) -> None:
        """
        Run the main connector process

        Continuously listens to the OpenCTI live stream and processes events
        """
        self.helper.connector_logger.info(
            "Starting Elastic Security Intel stream connector",
            {
                "connector_id": self.helper.connect_id,
                "stream_id": self.helper.connect_live_stream_id,
            },
        )

        # Start listening to the stream
        self.helper.listen_stream(message_callback=self.process_message)
