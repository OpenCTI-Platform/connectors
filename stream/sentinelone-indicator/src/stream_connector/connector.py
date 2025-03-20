import json
import logging
import time
from datetime import datetime
from threading import Thread
from typing import Optional, Tuple

from pycti import OpenCTIConnectorHelper

from .config_variables import ConfigConnector
from .custom_exceptions import SentinelOnePermissionError
from .s1_client import SentinelOneClient

# The substring found in REDIS messages when Indicators are created
INDICATOR_CREATION_SUBSTRING = "creates a Indicator"

# The maximum number of indicators that can be in the buffer before being sent
MAX_BUFFER_SIZE = 20

# The maximum time (seconds) between receiving indicators before a non-full buffer will be sent
BUFFER_TIMEOUT = 20

# The interval (seconds) at which the connector will log a statistics message at the info level
INFO_HEARTBEAT_INTERVAL = 5 * 60

# Heartbeat messages used at the debug level for consistent assurance of health
DEBUG_HEARTBEAT_MESSAGES = [
    "[<3] I'm alive!",
    "[<3] I'm still here!",
    "[<3] I'm not dead yet!",
]


# The Mappings of OpenCTI Type : SentinelOne Type case Sensitive for hashes
HASH_TYPES_MAPPING = {"SHA-1": "SHA1", "SHA-256": "SHA256", "MD5": "MD5"}

# The Mappings of OpenCTI Type : SentinelOne Type case Sensitive for observables
OBSERVABLE_TYPES_MAPPING = {
    "IPv4-Addr": "IPV4",
    "Domain-Name": "DNS",
    "Hostname": "URL",
    "Url": "URL",
}


class IndicatorConnector:
    def __init__(self):
        self.config = ConfigConnector()
        self.helper = OpenCTIConnectorHelper(self.config.load)

        # FOR DEVELOPMENT ONLY:
        self._setup_development_environment(self.helper)

        self.s1_client = SentinelOneClient(self.helper.connector_logger, self.config)
        self.indicator_creation_identifier = INDICATOR_CREATION_SUBSTRING
        self.buffer = IndicatorBuffer(
            self.helper.connector_logger, self.s1_client.send_indicators
        )
        self.helper.connector_logger.info(
            "Indicator Connector Initialised Successfully."
        )

    def _setup_development_environment(self, helper):
        # Force the connector to read from the first REDIS event
        helper.set_state(
            {
                "start_from": "0-0",
                "recover_until": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        )
        # Override the gross json logging system for more clarity
        logging.basicConfig(
            format="%(levelname)s %(asctime)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            level=logging.DEBUG,
            force=True,
        )
        # Override the default log level names with our custom prefixes
        logging.addLevelName(logging.DEBUG, "[*]")
        logging.addLevelName(logging.INFO, "[+]")
        logging.addLevelName(logging.WARNING, "[?]")
        logging.addLevelName(logging.ERROR, "[!]")
        logging.addLevelName(logging.CRITICAL, "[⚠️]")

    def run(self) -> None:
        """
        Continuous run of consuming stream, calling back to
        our processing function.
        """
        self.helper.listen_stream(message_callback=self._process_message)

    def _process_message(self, msg: dict) -> None:
        """
        The method triggered as a callback upon
        the consumption of a message from the stream
        (which is parsed in as a dict).

        It handles filtration as follows:
         - Only look for creation events.
         - Look for Indicator creation substring
           in the message.
        This effectively filters out the Indicators
        that need processing amongst all messages.
        """
        try:
            self._check_stream_id()
            if msg.event == "create":
                message_dict = json.loads(msg.data)
                if self.indicator_creation_identifier in message_dict.get(
                    "message", ""
                ):
                    if len(self.buffer.buffer) == 0:
                        self.helper.connector_logger.info(
                            "Listening for new Indicators..."
                        )
                    self.helper.connector_logger.debug(
                        "New indicator to process found."
                    )
                    if indicator_payload := self._validate_and_extract_indicator(
                        message_dict
                    ):
                        self.buffer.add_item(indicator_payload)
        except SentinelOnePermissionError:
            raise
        except Exception as e:
            self.helper.connector_logger.error(
                f"Connector cannot process consumed message, error: {e}"
            )
            pass

    def _validate_and_extract_indicator(self, message_dict: dict) -> Optional[dict]:
        """
        Overarching handler for the creation of an
        indicator 'payload'.

        """
        ioc_type, ioc_value = self._extract_indicator_info(message_dict)
        if not ioc_type or not ioc_value:
            self.helper.connector_logger.debug(
                f"Unsupported indicator type: {message_dict.get('data', {}).get('pattern', 'Pattern Unknown')}, skipping."
            )
            self.helper.connector_logger.debug(
                message_dict.get("data", {}).get("id", "ID Unknown")
            )
            return None
        indicator_data = message_dict.get("data", {})
        return self._build_indicator_payload(indicator_data, ioc_type, ioc_value)

    def _extract_indicator_info(
        self, message_dict: dict
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Crawls through the extensions of the indicator,
        locating it's pattern. If the pattern is stix,
        it is sent off to be deconstructed.

        Returns the indicator type and value as a tuple of
        either strings (success) or None (failure)
        """

        if message_dict.get("data", {}).get("pattern_type") == "stix":
            for extension_data in (
                message_dict.get("data", {}).get("extensions", {}).values()
            ):
                if observable_values_list := extension_data.get(
                    "observable_values", []
                ):
                    for observable_values in observable_values_list:
                        if (
                            "type" in observable_values.keys()
                            and "value" in observable_values.keys()
                        ) or ("hashes" in observable_values.keys()):
                            ioc_type, ioc_value = self._extract_indicator_type_value(
                                observable_values
                            )
                            if ioc_type and ioc_value:
                                return ioc_type, ioc_value

        return None, None

    def _extract_indicator_type_value(
        self, observable_values: dict
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Extract types and values from indicators adhering
        to the mapping (a reflection of both the 6 types s1
        accepts, as well as the case sensitive titles
        the s1 api requires adherence to)

        Returns perfect, s1 adhering, indicator type and value
        as strings in a tuple. As such, issues, incompatibilities
        and failures mean either value could also be returned
        as None
        """

        hashes = observable_values.get("hashes", {})
        for hash_key, indicator_type in HASH_TYPES_MAPPING.items():
            if value := hashes.get(hash_key):
                return indicator_type, value

        obs_type = observable_values.get("type", "")
        if indicator_type := OBSERVABLE_TYPES_MAPPING.get(obs_type):
            return indicator_type, observable_values.get("value", "")

        return None, None

    def _build_indicator_payload(
        self, indicator_data: dict, ioc_type: str, ioc_value: str
    ) -> dict:
        """
        Constructs a singular indicator 'payload' based on
        the available information and s1 formatting. Each
        indicator 'payload' is appended to a list that goes
        under the 'data' key of the actual payload sent to s1.

        Returns a dictionary of the indicator's keys and values
        for present data.
        """

        payload = {
            "type": ioc_type,
            "value": ioc_value,
            "name": indicator_data.get("name"),
            "description": indicator_data.get("description"),
            "externalId": indicator_data.get("id"),
            "pattern": indicator_data.get("pattern"),
            "patternType": indicator_data.get("pattern_type"),
            "source": self.helper.connector.name,
            "validUntil": indicator_data.get("valid_until"),
            "creationTime": indicator_data.get("created"),
            "method": "EQUALS",
            "creator": "OpenCTI Indicator Stream Connector",
            "labels": indicator_data.get("labels"),
        }
        return {
            s1_key: ioc_value
            for s1_key, ioc_value in payload.items()
            if ioc_value is not None
        }

    def _check_stream_id(self) -> None:
        """
        Provided method for raising against stream ID
        configuration errors.

        Returns nothing, instead halting execution if
        there is an issue.
        """

        if (
            self.helper.connect_live_stream_id is None
            or self.helper.connect_live_stream_id == "ChangeMe"
        ):
            raise ValueError("Missing stream ID, please check your configurations.")


class IndicatorBuffer:
    """
    A buffer-esque structure that handles the processing
    of indicators post their being extracted and converted
    into payloads.

    Handles appending to and clearing the buffer as well as
    sending it off to SentinelOne either when its maximum
    size is exceed or a timeout is reached.

    The timeout is implemented via its own thread that
    checks at intervals to ensure that an existing buffer
    with an amount of Indicators less than the maximum amount
    will eventually be sent to s1 even if no new Indicators
    come through (via a timeout).
    """

    def __init__(self, helper_logger: logging.Logger, send_indicators_fcn):
        self.logger = helper_logger

        # The actual buffer structure, size and function to send it
        self.buffer = []
        self.max_buffer_size = MAX_BUFFER_SIZE
        self.send_buffer = send_indicators_fcn

        # Handling cases of no indicators coming through for a while
        self.last_indicator_appended_time = datetime.now()
        self.buffer_timeout = BUFFER_TIMEOUT

        self.heartbeat_messages = DEBUG_HEARTBEAT_MESSAGES
        self.heartbeat_messages_index = 0
        self.info_heartbeat_interval = INFO_HEARTBEAT_INTERVAL

        # Runtime statistics and caps for values (in long running cases)
        self.MAX_COUNTER_VALUE = 1 * 10**6
        self.indicators_sent = 0
        self.buffers_failed = 0

        self.logger.info("Buffer initialised successfully, starting monitoring.")
        self._start_buffer_monitor()

    def add_item(self, indicator: dict) -> None:
        """
        Appends and indicator payload to the buffer,
        ensuring that if the maximum buffer size is
        exceeded, the buffer is sent off to s1.
        """

        self.buffer.append(indicator)
        self.last_indicator_appended_time = datetime.now()
        self.logger.debug(
            f"IOC with OpenCTI ID: {indicator.get('externalId')} added to Buffer. Current size: {len(self.buffer)}"
        )

        if self._should_send_size():
            self.logger.info(
                f"{self.max_buffer_size} Indicators processed. Preparing to send to SentinelOne."
            )
            self._send_and_clear()

    def _start_buffer_monitor(self) -> None:
        """
        Innitiates the thread used to monitor timeouts
        for the buffer.
        """
        self.buffer_thread = Thread(target=self._buffer_monitor)
        self.buffer_thread.daemon = True
        self.buffer_thread.start()

    def _buffer_monitor(self) -> None:
        """
        Monitors the buffer and sends it off to s1
        when the timeout condition is met. As well
        as this, includes internal heartbeats at the
        info and debug levels.
        """

        last_info_heartbeat = datetime.now()

        while True:
            current_time = datetime.now()

            # Debug the heartbeat
            self.logger.debug(self.heartbeat_messages[self.heartbeat_messages_index])
            self.heartbeat_messages_index = (self.heartbeat_messages_index + 1) % len(
                self.heartbeat_messages
            )

            # Reset counters if they exceed the maximum value (for long, long running cases.)
            for counter_name, counter_value in [
                ("indicators_sent", self.indicators_sent),
                ("buffers_failed", self.buffers_failed),
            ]:
                if counter_value >= self.MAX_COUNTER_VALUE:
                    setattr(self, counter_name, 0)
                    self.logger.warning(
                        f"{counter_name} counter reached maximum value, resetting to 0"
                    )

            # Info stats/heartbeat
            if (
                current_time - last_info_heartbeat
            ).total_seconds() >= self.info_heartbeat_interval:
                self.logger.info("Indicator Connector is alive. Session stats:")
                self.logger.info(
                    f"Connector has Sent {self.indicators_sent} Indicators."
                )
                self.logger.info(
                    f"Connector has Failed to Send {self.buffers_failed} Bundles."
                )
                last_info_heartbeat = current_time

            if self._should_send_timeout():
                self._send_and_clear()
            time.sleep(self.buffer_timeout)

    def _should_send_size(self) -> bool:
        """
        Checks if the buffer should be sent off to s1
        based on the maximum buffer size.
        """
        return len(self.buffer) >= self.max_buffer_size

    def _should_send_timeout(self) -> bool:
        """
        Checks if the buffer should be sent off to s1
        based on the timeout.
        """
        return (
            self.buffer
            and (datetime.now() - self.last_indicator_appended_time).total_seconds()
            >= self.buffer_timeout
        )

    def _send_and_clear(self) -> None:
        """
        Sends the buffer off to s1 and clears it.
        """
        if not self.buffer:
            return

        self.logger.debug(
            f"Sending bundle of {len(self.buffer)} Indicators to SentinelOne."
        )
        if self.send_buffer(self.buffer):
            self.logger.info(
                f"Bundle of {len(self.buffer)} Indicators sent successfully."
            )
            self.indicators_sent += len(self.buffer)
        else:
            self.logger.error(
                "Error, unable to send Bundle to SentinelOne. Set logging level to debug for more information."
            )
            self.logger.debug(
                f"IDs of Indicators that failed to send: {', '.join([indicator.get('externalId') for indicator in self.buffer])}"
            )
            self.buffers_failed += 1

        # Clear the buffer, reset the timer and halt momentarily.
        self.buffer.clear()
        self.last_indicator_appended_time = datetime.now()
        time.sleep(0.1)
