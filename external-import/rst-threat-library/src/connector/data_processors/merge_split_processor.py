"""SDK ``BaseDataProcessor`` for alias merge/split reconcile."""

from __future__ import annotations

import time
from typing import Any, Dict, List

from connector.connector import RSTThreatLibrary
from connector.settings import ConnectorSettings
from connector.state import ConnectorState
from connectors_sdk import BaseDataProcessor
from pycti import OpenCTIConnectorHelper


class MergeSplitProcessor(BaseDataProcessor[ConnectorSettings, ConnectorState]):
    """Run alias merge/split after object-type imports.

    Merge/split uses OpenCTI GraphQL (``stix.merge`` / alias updates) in
    addition to STIX upserts, so ``process()`` is overridden instead of the
    pure collect → transform → send path.
    """

    work_name = "RST Threat Library merge/split"

    def __init__(self) -> None:
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
        """Apply engine mutations in memory only; SDK saves after full run."""
        self.state.apply_mutable_dict(state_dict)

    def _send_via_work_manager(self, stix_objects: List[Any], obj_type: str) -> bool:
        if not stix_objects:
            return True
        work_name = f"{self.work_name} [{obj_type}]"
        self.work_manager.send(
            stix_objects,
            work_name,
            cleanup_inconsistent_bundle=True,
        )
        self.logger.info(
            "Sent merge/split STIX bundle via WorkManager",
            meta={"work_name": work_name, "objects_count": len(stix_objects)},
        )
        return True

    def collect(self) -> list[Any]:
        return []

    def transform(self, data: Any) -> list[Any]:
        _ = data
        return []

    def process(self) -> None:
        if not self.settings.rst_threat_library.merge_split:
            self.logger.info("Merge/split disabled; skipping processor")
            return

        self.logger.info("Merge/split reconcile starting")
        state_dict = self.state.to_mutable_dict()
        timestamp = int(time.time())
        client = self.engine.build_client()

        with self.work_manager:
            success = self.engine._apply_merge_split(client, state_dict, timestamp)
            # Raise inside the context so WorkManager marks the work in_error.
            if not success:
                raise RuntimeError("RST Threat Library merge/split reconcile failed")

        self.state.apply_mutable_dict(state_dict)
        self.logger.info("Merge/split reconcile completed")
