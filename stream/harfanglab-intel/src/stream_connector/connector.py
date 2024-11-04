import json

from pycti import OpenCTIConnectorHelper

from .config_variables import ConfigConnector


class StreamConnector:
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

    def process_message(self, msg) -> None:
        """
        Main process if connector successfully works
        The data passed in the data parameter is a dictionary with the following structure as shown in
        https://docs.opencti.io/latest/development/connectors/#additional-implementations
        :param msg: Message event from stream
        :return: string
        """
        try:
            data = json.loads(msg.data)["data"]
        except json.JSONDecodeError:
            self.helper.connector_logger.error(
                "[ERROR] Cannot parse message's data", {"msg_data": msg.data}
            )
            return

        if msg.event == "create":
            if data["type"] == "indicator":
                if data["type"] == "indicator":
                    if data["pattern_type"] == "yara":
                        self.create_indicator(
                            msg, "yara", "YaraFile", self.yara_list_id
                        )
                    elif data["pattern_type"] == "sigma":
                        self.create_indicator(
                            msg, "sigma", "SigmaRule", self.sigma_list_id
                        )
                    elif data["pattern_type"] == "stix":
                        self.create_indicator(msg, "stix", "IOCRule", self.stix_list_id)
                    else:
                        self.helper.connector_logger.error(
                            "[ERROR] Unsupported Pattern Type",
                            {"pattern_type": data["pattern_type"]},
                        )
            if data["type"] == "relationship":
                self.helper.connector_logger.info("[CREATE]")
                if data["relationship_type"] == "based-on":
                    self.create_observable(data, "stix", "IOCRule", self.stix_list_id)

        if msg.event == "update":
            if data["type"] == "indicator":
                self.helper.connector_logger.info("[UPDATE]")
                if data["pattern_type"] == "yara":
                    self.update_indicator(msg, "yara", "YaraFile", self.yara_list_id)
                elif data["pattern_type"] == "sigma":
                    self.update_indicator(msg, "sigma", "SigmaRule", self.sigma_list_id)
                elif data["pattern_type"] == "stix":
                    self.update_indicator(msg, "stix", "IOCRule", self.stix_list_id)
                else:
                    self.helper.connector_logger.error(
                        "[ERROR] Unsupported Pattern Type",
                        {"pattern_type": data["pattern_type"]},
                    )
            if data["type"] == "relationship":
                self.helper.connector_logger.info("[UPDATE]")
                # Do something
                raise NotImplementedError

        if msg.event == "delete":
            if data["type"] == "indicator":
                self.helper.connector_logger.info("[DELETE]")
                if data["pattern_type"] == "yara":
                    self.delete_indicator(msg, "yara", "YaraFile", self.yara_list_id)
                elif data["pattern_type"] == "sigma":
                    self.delete_indicator(msg, "sigma", "SigmaRule", self.sigma_list_id)
                elif data["pattern_type"] == "stix":
                    self.delete_indicator(msg, "stix", "IOCRule", self.stix_list_id)
                else:
                    self.helper.connector_logger.error(
                        "[ERROR] Unsupported Pattern Type",
                        {"pattern_type": data["pattern_type"]},
                    )
            if data["type"] == "relationship":
                if data["relationship_type"] == "based-on":
                    self.delete_observable(data, "stix", "IOCRule", self.stix_list_id)

    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors messages from the platform
        The connector have the capability to listen a live stream from the platform.
        The helper provide an easy way to listen to the events.
        """
        self.helper.listen_stream(message_callback=self.process_message)
