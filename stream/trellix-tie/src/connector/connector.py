import json

from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper
from trellix_tie_client import TrellixTieAPIError, TrellixTieClient, extract_hashes


class TrellixTieConnector:
    """
    Stream connector that pushes OpenCTI file-hash indicators to Trellix TIE as
    enterprise file reputations over OpenDXL.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        self.client = TrellixTieClient(
            helper, dxl_config_path=self.config.trellix_tie.dxl_config_path
        )
        self.trust_level = self.config.trellix_tie.trust_level
        self.comment = self.config.trellix_tie.comment

    def check_stream_id(self) -> None:
        """Raise a ValueError if the live stream ID is missing or left as a placeholder."""
        stream_id = self.helper.connect_live_stream_id
        if (
            stream_id is None
            or not str(stream_id).strip()
            or str(stream_id).strip().lower() == "changeme"
        ):
            raise ValueError("Missing stream ID, please check your configurations.")

    def _handle_indicator(self, data: dict) -> None:
        if data.get("type") != "indicator":
            return
        hashes = extract_hashes(data.get("pattern", ""))
        if not hashes:
            self.helper.connector_logger.debug(
                "[TIE] Indicator has no file hash, skipping."
            )
            return
        name = data.get("name") or ""
        self.client.set_file_reputation(
            self.trust_level, hashes, filename=name, comment=self.comment
        )
        self.helper.connector_logger.info(
            "[TIE] File reputation set in Trellix TIE",
            meta={"name": name, "trust_level": self.trust_level},
        )

    def process_message(self, msg) -> None:
        try:
            data = json.loads(msg.data)["data"]
        except (json.JSONDecodeError, KeyError, TypeError) as err:
            raise ValueError(f"Cannot process the message: {err}") from err

        try:
            if msg.event in ("create", "update"):
                self._handle_indicator(data)
            elif msg.event == "delete":
                self.helper.connector_logger.debug(
                    "[TIE] Delete event ignored (TIE reputations are not removed)."
                )
        except TrellixTieAPIError as err:
            self.helper.connector_logger.error(
                "[TIE] Failed to set reputation", meta={"error": str(err)}
            )

    def run(self) -> None:
        # Validate the live stream id up front so a placeholder/blank id fails fast
        # at startup, before entering the blocking listen_stream loop.
        self.check_stream_id()
        self.helper.listen_stream(message_callback=self.process_message)
