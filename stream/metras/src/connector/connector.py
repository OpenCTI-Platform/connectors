"""Metras Stream connector (STREAM).

Forwards OpenCTI Indicator create/update/delete events to Metras custom
blocklists. Only indicators that carry a file name/path are convertible (Metras
blocklists accept file paths only); IP/domain/hash indicators are skipped + logged.
"""

import json
import time

from connector.converter_to_external import ConverterToExternal
from connector.settings import ConnectorSettings
from metras_client import MetrasAPIError, MetrasClient
from pycti import OpenCTIConnectorHelper


class MetrasStreamConnector:
    def __init__(
        self, config: ConnectorSettings, helper: OpenCTIConnectorHelper
    ) -> None:
        self.config = config
        self.helper = helper
        cfg = config.metras
        self.client = MetrasClient(
            helper=helper,
            base_url=str(cfg.api_base_url),
            api_key=cfg.api_key.get_secret_value(),
            verify_ssl=cfg.verify_ssl,
        )
        self.converter = ConverterToExternal(
            action=cfg.blocklist_action,
            platform=cfg.blocklist_platform,
            severity=cfg.blocklist_severity,
        )

    # ------------------------------------------------------------------ #
    def run(self) -> None:
        try:
            self.client.ping()
            self.helper.connector_logger.info(
                "[CONNECTOR] Metras API connection verified"
            )
        except MetrasAPIError as exc:
            self.helper.connector_logger.error(
                "[CONNECTOR] Metras API ping failed at startup", {"error": str(exc)}
            )
            # Continue: the stream still registers; pushes will log errors.

        if not getattr(self.helper, "connect_live_stream_id", None):
            raise ValueError(
                "CONNECTOR_LIVE_STREAM_ID is not set. Create and activate a live "
                "stream in OpenCTI (Data > Data sharing > Live streams) and set its "
                "UUID as CONNECTOR_LIVE_STREAM_ID."
            )

        self.helper.connector_logger.info("[CONNECTOR] Starting Metras stream listener")
        # listen_stream() spawns a daemon thread and returns — keep the main
        # thread alive so the process does not exit.
        self.helper.listen_stream(message_callback=self._process_event)
        try:
            while True:
                time.sleep(60)
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("[CONNECTOR] Stopping")

    # ------------------------------------------------------------------ #
    def _process_event(self, msg) -> None:
        try:
            parsed = json.loads(msg.data)
        except (ValueError, TypeError) as exc:
            self.helper.connector_logger.error(
                "[CONNECTOR] Could not parse stream event", {"error": str(exc)}
            )
            return

        stix_data = parsed.get("data", {})
        event_type = msg.event  # create | update | delete
        if stix_data.get("type") != "indicator":
            return  # Only indicators are actionable for blocklists.

        indicator_id = stix_data.get("id", "unknown")
        self.helper.connector_logger.info(
            "[CONNECTOR] Indicator event",
            {"event": event_type, "id": indicator_id},
        )

        try:
            if event_type in ("create", "update"):
                self._handle_upsert(event_type, stix_data)
            elif event_type == "delete":
                self._handle_delete(stix_data)
        except MetrasAPIError as exc:
            self.helper.connector_logger.error(
                "[CONNECTOR] Metras push failed (continuing)",
                {"id": indicator_id, "error": str(exc)},
            )
        except Exception as exc:  # noqa: BLE001 — never crash the stream
            self.helper.connector_logger.error(
                "[CONNECTOR] Unexpected error (continuing)",
                {"id": indicator_id, "error": str(exc)},
            )

    # ------------------------------------------------------------------ #
    def _handle_upsert(self, event_type: str, stix_data: dict) -> None:
        item = self.converter.build_item(stix_data)
        if item is None:
            self.helper.connector_logger.info(
                "[CONNECTOR] Indicator has no file name/path; not pushable to Metras blocklist",
                {"id": stix_data.get("id")},
            )
            return

        name = item["name"]
        existing_id = self._resolve_blocklist_id(name)
        if existing_id:
            self.client.update_blocklist(
                existing_id,
                {
                    "description": item["description"],
                    "action": item["action"],
                    "severity": item["severity"],
                    "file_paths": item["file_paths"],
                },
            )
            self.helper.connector_logger.info(
                "[CONNECTOR] Updated Metras blocklist",
                {"name": name, "paths": len(item["file_paths"])},
            )
        else:
            self.client.create_blocklist([item])
            self.helper.connector_logger.info(
                "[CONNECTOR] Created Metras blocklist",
                {"name": name, "paths": len(item["file_paths"])},
            )

    def _handle_delete(self, stix_data: dict) -> None:
        name = self.converter.blocklist_name(stix_data)
        existing_id = self._resolve_blocklist_id(name)
        if existing_id:
            self.client.delete_blocklist(existing_id)
            self.helper.connector_logger.info(
                "[CONNECTOR] Deleted Metras blocklist", {"name": name}
            )
        else:
            self.helper.connector_logger.info(
                "[CONNECTOR] No matching Metras blocklist to delete", {"name": name}
            )

    def _resolve_blocklist_id(self, name: str) -> str | None:
        """Find a blocklist id by its deterministic name."""
        payload = self.client.list_blocklists(name=name)
        for item in payload.get("data") or []:
            if item.get("name") == name:
                return item.get("id") or item.get("custom_blocklist_id")
        return None
