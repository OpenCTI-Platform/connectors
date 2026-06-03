"""Core implementation of the Dark Web Informer external-import connector.

Passthrough mode: fetches Dark Web Informer's prebuilt STIX 2.1 bundles and
sends them to OpenCTI as-is, without re-deriving the mapping. DWI publishes
valid, field-complete bundles (identities, indicators, observables, malware,
intrusion-sets, reports and their relationships), so no conversion layer is
needed. Deduplication is handled by OpenCTI via the deterministic STIX IDs.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from connector.settings import ConnectorSettings
from dark_web_informer_client import DarkWebInformerClient
from pycti import OpenCTIConnectorHelper

__all__ = ["DarkWebInformerConnector"]

_STATE_LAST_RUN = "last_run"


class DarkWebInformerConnector:
    """External-import connector ingesting Dark Web Informer STIX bundles."""

    def __init__(
        self, helper: OpenCTIConnectorHelper, settings: ConnectorSettings
    ) -> None:
        self.helper = helper
        self.settings = settings
        config = settings.dark_web_informer

        self.client = DarkWebInformerClient(
            helper=helper,
            base_url=str(config.base_url),
            api_key=config.api_key.get_secret_value(),
        )
        self.sources = list(config.sources)
        self.use_preview = config.use_preview_endpoint
        self.preview_limit = config.preview_limit

    def _send_bundle(self, bundle: dict, work_id: str) -> int:
        """Forward a native DWI STIX bundle to OpenCTI unchanged.

        Returns the number of objects in the bundle (0 if empty/invalid).
        """
        objects = bundle.get("objects") if isinstance(bundle, dict) else None
        if not objects:
            return 0
        self.helper.send_stix2_bundle(json.dumps(bundle), work_id=work_id)
        return len(objects)

    def process_message(self) -> None:
        now = datetime.now(timezone.utc)
        self.helper.connector_logger.info(
            "Starting Dark Web Informer run", {"sources": self.sources}
        )
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, "Dark Web Informer run"
        )
        try:
            total = 0
            for source in self.sources:
                if self.use_preview:
                    bundle = self.client.get_stix_preview(
                        source=source, limit=self.preview_limit
                    )
                else:
                    bundle = self.client.get_stix_bundle(source)
                count = self._send_bundle(bundle, work_id)
                self.helper.connector_logger.info(
                    "Sent bundle", {"source": source, "objects": count}
                )
                total += count

            self.helper.set_state({_STATE_LAST_RUN: now.isoformat()})
            self.helper.api.work.to_processed(
                work_id, f"Dark Web Informer run complete ({total} objects)"
            )
        except Exception as err:
            self.helper.connector_logger.error(
                "Dark Web Informer run failed", {"error": str(err)}
            )
            self.helper.api.work.to_processed(
                work_id, f"Run failed: {err}", in_error=True
            )

    def run(self) -> None:
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.settings.connector.duration_period,
        )
