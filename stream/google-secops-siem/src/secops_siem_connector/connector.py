import json
import sys
from json import JSONDecodeError

from pycti import OpenCTIConnectorHelper
from secops_siem_services import ConfigConnector, CTIConverter, SecOpsEntitiesClient


class SecOpsSIEMConnector:

    def __init__(self):
        """
        Initialize the Connector with necessary configurations
        """

        self.config = ConfigConnector()
        self.helper = OpenCTIConnectorHelper(self.config.load)
        self.converter = CTIConverter(self.helper, self.config)
        self.api_client = SecOpsEntitiesClient(self.helper, self.config)

    def check_stream_id(self) -> None:
        """
        Validates the presence of a stream ID in the configuration.

        This method ensures that the `connect_live_stream_id` is properly set and
        does not contain a placeholder value (e.g., "changeme").

        :raises ValueError:
            Raised if the `connect_live_stream_id` is missing or contains an invalid placeholder value.

        Example Usage:
            self.check_stream_id()  # Ensures the stream ID is properly configured.
        """
        if (
            not self.helper.connect_live_stream_id
            or self.helper.connect_live_stream_id.lower() == "changeme"
        ):
            raise ValueError("Missing stream ID, please check your configurations.")

    def handle_logger_info(self, data: dict, event_context: dict = None) -> None:
        """
        Updates the connector logger with information about the current action being processed.

        Depending on whether an event context is provided, this method distinguishes between
        an "UPDATE" action or a "CREATE" action and logs the respective indicator details.

        :param data:
            A dictionary containing the data streamed by OpenCTI. This must include an "id" key
            corresponding to the indicator being processed.

        :param event_context:
            An optional dictionary providing additional context for an "UPDATE" event. If not provided,
            the action is assumed to be a "CREATE" event.

        :return:
            None

        Logging:
            Logs the action type ("CREATE" or "UPDATE") and the ID of the indicator being processed
            using `self.helper.connector_logger.info`.

        Example Usage:
            self.handle_logger_info(data={"id": "indicator--bf32b2a0-3830-4769-ae0f-9fe50c04d02f"})
            # Logs: [CREATE] Processing Indicator with ID indicator--bf32b2a0-3830-4769-ae0f-9fe50c04d02f

            self.handle_logger_info(data={"id": "indicator--bf32b2a0-3830-4769-ae0f-9fe50c04d05b"}, event_context={"type": "update"})
            # Logs: [UPDATE] Processing Indicator with ID indicator--bf32b2a0-3830-4769-ae0f-9fe50c04d05b
        """

        self.helper.connector_logger.info(
            f"{'[UPDATE]' if event_context else '[CREATE]'} Processing Indicator",
            {"indicator_id": data["id"]},
        )

    def validate_json(self, msg) -> dict | JSONDecodeError:
        """
        Validate the JSON data from the stream
        :param msg: Message event from stream
        :return: Parsed JSON data or raise JSONDecodeError if JSON data cannot be parsed
        """
        try:
            parsed_msg = json.loads(msg.data)
            return parsed_msg
        except json.JSONDecodeError:
            self.helper.connector_logger.error(
                "[ERROR] Data cannot be parsed to JSON", {"msg_data": msg.data}
            )
            raise JSONDecodeError("Data cannot be parsed to JSON", msg.data, 0)

    def _upsert_ioc_rule(self, indicator: dict) -> None:
        """
        Convert each indicator's observable to a UDM entity and upsert it in Chronicle.
        :param indicator: Indicator to upsert
        """
        udm_entities = self.converter.create_udm_entities_from_indicator(indicator)
        if udm_entities:
            entities_ingested = self.api_client.ingest(udm_entities)

            if entities_ingested:
                self.helper.connector_logger.info(
                    "[API] Entities have been successfully ingested",
                )
            else:
                self.helper.connector_logger.error(
                    "[API] Error while ingesting indicator"
                )

    def process_message(self, msg) -> None:
        """
        Processes a message event received from the OpenCTI stream.

        This is the main method responsible for handling messages streamed by OpenCTI. It validates the incoming
        data, checks the stream ID, and processes the event based on its type ("create" or "update" or "delete").

        The method is specifically designed to handle entities of type 'Indicator' with a pattern type of 'stix'.

        The msg passed in the data parameter is a dictionary with the following structure as shown in
        https://docs.opencti.io/latest/development/connectors/#additional-implementations

        :param msg:
            The message event received from the OpenCTI stream. This is expected to contain the event type
            ("create" or "update") and the associated data.

        :return:
            None

        Example Usage:
            self.process_message(msg)

        Workflow:
            1. Validates the stream ID.
            2. Parses and validates the message as JSON.
            3. Extracts the data and processes it if the entity type is 'Indicator'.
            4. Handles 'create' and 'update' events differently:
               - Logs the action.
               - Calls `_upsert_ioc_rule` to process the IOC (Indicator of Compromise).

        Error Handling:
            - Gracefully handles keyboard interrupts and system exits, logging an appropriate message.
            - Logs any unexpected exceptions as errors.
        """
        try:
            self.check_stream_id()

            parsed_msg = self.validate_json(msg)
            data = parsed_msg["data"]

            # When an IOC is updated, get the context of the update event
            event_context = parsed_msg["context"] if "context" in parsed_msg else None

            # Extract data and handle only entity type 'Indicator' from stream
            if data["type"] == "indicator" and data["pattern_type"] in ["stix"]:
                self.helper.connector_logger.info(
                    "Starting to extract data...",
                    {"pattern_type": data["pattern_type"]},
                )

                # Handle creation
                if msg.event == "create":
                    self.handle_logger_info(data)
                    self._upsert_ioc_rule(data)

                # Handle update
                if msg.event == "update":
                    self.handle_logger_info(data, event_context)
                    self._upsert_ioc_rule(data)

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(str(err))

    def run(self):
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors messages from the platform
        The connector have the capability to listen a live stream from the platform.
        The helper provide an easy way to listen to the events.
        """
        self.helper.listen_stream(message_callback=self.process_message)
