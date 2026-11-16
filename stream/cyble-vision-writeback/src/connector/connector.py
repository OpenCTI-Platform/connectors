"""STREAM connector: OpenCTI Incident updates → Cyble Vision PUT /y/alerts."""

from __future__ import annotations

import json
from typing import Any

from connector.mapping import build_update, changed_fields, creator_ids
from connector.settings import ConnectorSettings
from cyble_client import CybleVisionClient
from pycti import OpenCTIConnectorHelper

INCIDENT_TYPES = {"incident", "x-opencti-incident"}


class CybleVisionWritebackConnector:
    """Listen for Incident updates and write severity/status back to Vision.

    Only Incidents created by the Cyble Vision import connector's user are
    considered. They carry the Vision alert ID in a "Cyble Vision" external
    reference and the Vision service in a ``cyble:<service>`` label.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        cfg = config.cyble_vision_writeback
        # The user(s) the import connector runs as: their Incidents are the
        # only ones written back, and their own updates are never echoed.
        self.import_user_ids = {
            user_id.strip() for user_id in cfg.import_user_ids if user_id.strip()
        }
        self.client = CybleVisionClient(
            base_url=str(cfg.api_base_url),
            api_token=cfg.api_token.get_secret_value(),
            logger=self.helper.connector_logger,
        )

    def check_stream_id(self) -> None:
        """Raise when the live stream ID is missing."""
        if (
            self.helper.connect_live_stream_id is None
            or self.helper.connect_live_stream_id == "ChangeMe"
        ):
            raise ValueError("Missing stream ID, please check your configurations.")

    def process_message(self, msg) -> None:
        """Handle one stream event."""
        if getattr(msg, "event", None) != "update":
            return

        payload = self._payload_from_message(msg)
        entity = payload.get("data") if isinstance(payload.get("data"), dict) else None
        if entity is None:
            return
        entity_type = str(entity.get("type") or entity.get("entity_type") or "")
        if entity_type.lower() not in INCIDENT_TYPES:
            return
        if self._is_import_user(payload):
            self.helper.connector_logger.debug(
                "Skipping write-back for an update made by the import connector"
            )
            return

        context = payload.get("context")
        fields = changed_fields(
            context.get("patch") if isinstance(context, dict) else None
        )
        if not fields:
            self.helper.connector_logger.debug(
                "Skipping write-back, neither severity nor workflow status changed",
                {"id": entity.get("id")},
            )
            return

        snapshot = self._refresh_incident(entity) or entity
        # Labels and external references can be edited by any user with write
        # access, so they alone must not decide which Vision alert is changed.
        if not (creator_ids(snapshot) | creator_ids(entity)) & self.import_user_ids:
            self.helper.connector_logger.debug(
                "Skipping write-back, Incident was not created by the import connector",
                {"id": entity.get("id")},
            )
            return

        update = build_update(snapshot, fields) or build_update(entity, fields)
        if update is None:
            self.helper.connector_logger.debug(
                "Skipping write-back, Incident has no Vision alert ID or service",
                {"id": entity.get("id")},
            )
            return

        self.helper.connector_logger.info(
            "Writing Incident change back to Cyble Vision",
            update,
        )
        self.client.update_alerts([update])

    def run(self) -> None:
        """Listen to the live stream until the connector stops."""
        self.check_stream_id()
        # Recovery comes from CONNECTOR_LIVE_STREAM_RECOVER(_ISO_DATE) via the
        # helper config, so it is not overridden here.
        self.helper.listen_stream(message_callback=self.process_message)

    @staticmethod
    def _payload_from_message(msg) -> dict[str, Any]:
        raw = getattr(msg, "data", None)
        payload = json.loads(raw) if isinstance(raw, str) else raw
        return payload if isinstance(payload, dict) else {}

    def _is_import_user(self, payload: dict[str, Any]) -> bool:
        """True when the update was made by the import connector's user.

        Without this check an import that changes severity would be echoed
        back to Vision as a customer override. Live stream events identify
        the author under ``origin``: ``user_id``, plus ``applicant_id`` when a
        worker writes on behalf of a connector.
        """
        origin = payload.get("origin")
        if not isinstance(origin, dict):
            return False
        actors = {origin.get("user_id"), origin.get("applicant_id")} - {None}
        return bool(actors & self.import_user_ids)

    def _refresh_incident(self, entity: dict[str, Any]) -> dict[str, Any] | None:
        """Reload the Incident, since stream update events can be partial."""
        entity_id = (
            entity.get("id") or entity.get("standard_id") or entity.get("x_opencti_id")
        )
        if not entity_id:
            return None
        try:
            live = self.helper.api.incident.read(id=entity_id)
        except Exception as err:
            self.helper.connector_logger.warning(
                "Could not reload Incident from OpenCTI, using stream payload",
                {"error": str(err)},
            )
            return None
        return live if isinstance(live, dict) else None
