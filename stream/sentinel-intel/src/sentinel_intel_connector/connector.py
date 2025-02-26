import json

from pycti import OpenCTIConnectorHelper
from stix_shifter.stix_translation import stix_translation

from .api_handler import SentinelApiHandler, SentinelApiHandlerError
from .config_variables import ConfigConnector
from .utils import (
    get_hash_type,
    get_hash_value,
    get_ioc_type,
    is_observable,
    is_stix_indicator,
)


class SentinelIntelConnector:
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
        self.api = SentinelApiHandler(self.helper, self.config)

    def _check_stream_id(self) -> None:
        """
        In case of stream_id configuration is missing, raise Value Error
        :return: None
        """
        if (
            self.helper.connect_live_stream_id is None
            or self.helper.connect_live_stream_id == "ChangeMe"
        ):
            raise ValueError("Missing stream ID, please check your configurations.")

    def _convert_indicator_to_observables(self, data) -> list[dict]:
        """
        Convert an OpenCTI indicator to its corresponding observables.
        :param data: OpenCTI indicator data
        :return: Observables data
        """
        try:
            observables = []
            translation = stix_translation.StixTranslation()
            parsed = translation.translate("splunk", "parse", "{}", data["pattern"])
            if "parsed_stix" in parsed:
                results = parsed["parsed_stix"]
                for result in results:
                    observable_data = {}
                    observable_data.update(data)

                    network_attributes = [
                        "domain-name:value",
                        "hostname:value",
                        "ipv4-addr:value",
                        "ipv6-addr:value",
                        "url:value",
                    ]
                    file_attributes = [
                        "file:hashes.'SHA-256'",
                        "file:hashes.'SHA-1'",
                        "file:hashes.MD5",
                    ]
                    if result["attribute"] in network_attributes:
                        stix_type = result["attribute"].replace(":value", "")
                        observable_data["type"] = stix_type
                        observable_data["value"] = result["value"]
                        observables.append(observable_data)
                    elif result["attribute"] in file_attributes:
                        hash_type = result["attribute"].split(".")[1].replace("'", "")
                        observable_data["type"] = "file"
                        observable_data["hashes"] = {hash_type: result["value"]}
                        observables.append(observable_data)
            return observables
        except:
            indicator_opencti_id = OpenCTIConnectorHelper.get_attribute_in_extension(
                "id", data
            )
            self.helper.connector_logger.warning(
                "[CREATE] Cannot convert STIX indicator { " + indicator_opencti_id + "}"
            )

    def _create_sentinel_indicator(self, observable_data):
        """
        Create a Threat Intelligence Indicator on Sentinel from an OpenCTI observable.
        :param observable_data: OpenCTI observable data
        :return: True if the indicator has been successfully created, False otherwise
        """
        result = self.api.post_indicator(observable_data)
        if result:
            observable_opencti_id = OpenCTIConnectorHelper.get_attribute_in_extension(
                "id", observable_data
            )
            self.helper.connector_logger.info(
                "[CREATE] Indicator created",
                {"sentinel_id": result["id"], "opencti_id": observable_opencti_id},
            )

            # Update OpenCTI SDO external references
            external_reference = self.helper.api.external_reference.create(
                source_name=self.config.target_product.replace("Azure", "Microsoft"),
                external_id=result["id"],
                description="Intel within the Microsoft platform.",
            )
            # If observable was built from an OpenCTI Indicator
            if "pattern" in observable_data:
                self.helper.api.stix_domain_object.add_external_reference(
                    id=observable_opencti_id,
                    external_reference_id=external_reference["id"],
                )
            else:
                self.helper.api.stix_cyber_observable.add_external_reference(
                    id=observable_opencti_id,
                    external_reference_id=external_reference["id"],
                )
        return result

    def _find_sentinel_indicator(self, observable_data: dict) -> dict | None:
        """
        Find a Threat Intelligence Indicator on Sentinel from an OpenCTI observable.
        :param observable_data: OpenCTI observable data
        :return: Found Sentinel indicator or None
        """
        opencti_id = OpenCTIConnectorHelper.get_attribute_in_extension(
            "id", observable_data
        )
        indicators_data = self.api.search_indicators(opencti_id=opencti_id)
        for indicator_data in indicators_data:
            if observable_data["type"] == "file":
                observable_hash_type = get_hash_type(observable_data)
                observable_hash_value = get_hash_value(observable_data).lower()
                indicator_hash_type = indicator_data.get("fileHashType")
                indicator_hash_value = indicator_data.get("fileHashValue", "").lower()
                if (
                    indicator_hash_type == observable_hash_type
                    and indicator_hash_value == observable_hash_value
                ):
                    return indicator_data
            else:
                observable_type = get_ioc_type(observable_data)
                observable_value = observable_data["value"]
                indicator_value = indicator_data.get(observable_type)
                if indicator_value == observable_value:
                    return indicator_data
        return None

    def _update_sentinel_indicator(self, observable_data) -> bool:
        """
        Update a Threat Intelligence Indicator on Sentinel from an OpenCTI observable.
        :param observable_data: OpenCTI observable data
        :return: True if the indicator has been successfully updated, False otherwise
        """
        indicator_data = self._find_sentinel_indicator(observable_data)
        if indicator_data is None:
            return False

        updated = self.api.patch_indicator(observable_data, indicator_data["id"])
        if updated:
            self.helper.connector_logger.info(
                "[UPDATE] Indicator updated",
                {
                    "sentinel_id": indicator_data["id"],
                    "opencti_id": indicator_data["externalId"],
                },
            )

    def _delete_sentinel_indicator(self, observable_data) -> bool:
        """
        Delete Threat Intelligence Indicators on Sentinel corresponding to an OpenCTI observable.
        :param observable_data: OpenCTI observable data
        :return: True if the indicators have been successfully deleted, False otherwise
        """
        did_delete = False

        opencti_id = OpenCTIConnectorHelper.get_attribute_in_extension(
            "id", observable_data
        )
        indicators_data = self.api.search_indicators(opencti_id=opencti_id)
        for indicator_data in indicators_data:
            if indicator_data["externalId"] == opencti_id:
                result = self.api.delete_indicator(indicator_data["id"])
                # TODO: should we delete external references on OpenCTI too?
                if result:
                    self.helper.connector_logger.info(
                        "[DELETE] Indicator deleted",
                        {"sentinel_id": indicator_data["id"], "opencti_id": opencti_id},
                    )
                did_delete = result
        return did_delete

    def _handle_create_event(self, data):
        """
        Handle create event by trying to create the corresponding Threat Intelligence Indicator on Sentinel.
        :param data: Streamed data (representing either an observable or an indicator)
        """
        if is_stix_indicator(data):
            observables = self._convert_indicator_to_observables(data)
            for observable in observables:
                self._create_sentinel_indicator(observable)
        elif is_observable(data):
            self._create_sentinel_indicator(data)

    def _handle_update_event(self, data):
        """
        Handle update event by trying to update the corresponding Threat Intelligence Indicator on Sentinel.
        :param data: Streamed data (representing either an observable or an indicator)
        """

        if is_stix_indicator(data):
            observables = self._convert_indicator_to_observables(data)
            for observable in observables:
                self._update_sentinel_indicator(observable)
        elif is_observable(data):
            self._update_sentinel_indicator(data)

    def _handle_delete_event(self, data):
        """
        Handle delete event by trying to delete the corresponding Threat Intelligence Indicators on Sentinel.
        :param data: Streamed data (representing either an observable or an indicator)
        """
        opencti_id = OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
        did_delete = self._delete_sentinel_indicator(data)
        if not did_delete:
            self.helper.connector_logger.info(
                "[DELETE] Indicator not found on "
                + self.config.target_product.replace("Azure", "Microsoft"),
                {"opencti_id": opencti_id},
            )

    def process_message(self, msg) -> None:
        """
        Main process if connector successfully works
        The data passed in the data parameter is a dictionary with the following structure as shown in
        https://docs.opencti.io/latest/development/connectors/#additional-implementations
        :param msg: Message event from stream
        :return: string
        """
        try:
            self._check_stream_id()

            try:
                data = json.loads(msg.data)["data"]
            except json.JSONDecodeError:
                self.helper.connector_logger.error(
                    "[ERROR] Cannot process the message", {"msg_data": msg.data}
                )
                return None

            if msg.event == "create":
                self._handle_create_event(data)
            if msg.event == "update":
                self._handle_update_event(data)
            if msg.event == "delete":
                self._handle_delete_event(data)

        except SentinelApiHandlerError as err:
            self.helper.connector_logger.error(err.msg, err.metadata)

        except Exception as err:
            self.helper.connector_logger.error(
                "[ERROR] Failed processing data {" + str(err) + "}"
            )
            self.helper.connector_logger.error(
                "[ERROR] Message data {" + str(msg) + "}"
            )
        finally:
            return None

    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors messages from the platform
        The connector have the capability to listen a live stream from the platform.
        The helper provide an easy way to listen to the events.
        """
        self.helper.listen_stream(message_callback=self.process_message)
