"""SDK ``BaseDataProcessor`` for one Threat Library object-type import."""

from __future__ import annotations

import time
from typing import Any, Dict, List

from connector.connector import RSTThreatLibrary
from connector.settings import ConnectorSettings
from connector.state import ConnectorState
from connectors_sdk import BaseDataProcessor
from pycti import OpenCTIConnectorHelper


class ThreatObjectImportProcessor(BaseDataProcessor[ConnectorSettings, ConnectorState]):
    """Import one Threat Library object type via the SDK work lifecycle.

    Business logic lives in ``RSTThreatLibrary._cycle_type``. This processor
    owns WorkManager sending and ``ConnectorState`` persistence so the engine
    no longer schedules itself or opens works directly.
    """

    def __init__(self, obj_type: str) -> None:
        self.obj_type = obj_type
        self.work_name = f"RST Threat Library [{obj_type}]"
        self._helper: OpenCTIConnectorHelper
        self.engine: RSTThreatLibrary

    def inject_dependencies(
        self,
        settings: ConnectorSettings,
        helper: OpenCTIConnectorHelper,
        state: ConnectorState,
    ) -> None:
        super().inject_dependencies(settings, helper, state)
        self._helper = helper

    def post_init(self) -> None:
        self.engine = RSTThreatLibrary(config=self.settings, helper=self._helper)
        self.engine._state_persist = self._persist_state_dict
        self.engine._send_bundle = self._send_via_work_manager

    def _persist_state_dict(self, state_dict: Dict[str, Any]) -> None:
        """Apply engine mutations in memory only.

        Persistence is deferred to ``ExternalImportConnector.callback()`` so
        state is saved atomically after all processors succeed.
        """
        self.state.apply_mutable_dict(state_dict)

    def _send_via_work_manager(self, stix_objects: List[Any], obj_type: str) -> bool:
        _ = obj_type
        if not stix_objects:
            return True
        self.work_manager.send(
            stix_objects,
            self.work_name,
            cleanup_inconsistent_bundle=True,
        )
        self.logger.info(
            "Sent STIX bundle via WorkManager",
            meta={"work_name": self.work_name, "objects_count": len(stix_objects)},
        )
        return True

    def collect(self) -> list[Any]:
        """Unused when ``process`` is overridden; required by ``BaseDataProcessor``."""
        return []

    def transform(self, data: Any) -> list[Any]:
        """Unused when ``process`` is overridden; required by ``BaseDataProcessor``."""
        _ = data
        return []

    def process(self) -> None:
        """Run one object-type delta import inside a WorkManager context."""
        self.logger.info(
            "Threat object import starting",
            meta={"object_type": self.obj_type},
        )
        state_dict = self.state.to_mutable_dict()
        timestamp = int(time.time())
        client = self.engine.build_client()
        seed = self.engine._seed_cursor()

        with self.work_manager:
            success = self.engine._cycle_type(
                client, self.obj_type, state_dict, timestamp, seed
            )

        self.state.apply_mutable_dict(state_dict)
        if not success:
            raise RuntimeError(
                f"RST Threat Library import failed for object type '{self.obj_type}'"
            )
        self.logger.info(
            "Threat object import completed",
            meta={"object_type": self.obj_type},
        )
