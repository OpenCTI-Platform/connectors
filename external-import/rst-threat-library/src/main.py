"""RST Threat Library connector entry point (connectors-sdk lifecycle).

Wires ``ConnectorSettings``, ``ConnectorState``, and
``BaseDataProcessor`` instances into ``ExternalImportConnector.start()``,
which owns scheduling, work lifecycle, and ``last_run`` persistence.
"""

from __future__ import annotations

import traceback

from connector import ConnectorSettings, ConnectorState, RSTThreatLibrary
from connector.data_processors import MergeSplitProcessor, ThreatObjectImportProcessor
from connectors_sdk import BaseDataProcessor, ExternalImportConnector


class RSTThreatLibraryConnector(
    ExternalImportConnector[ConnectorSettings, ConnectorState]
):
    """External-import connector with Threat Library startup logging."""

    def _init_dependencies(self) -> None:
        super()._init_dependencies()
        engine = RSTThreatLibrary(config=self.settings, helper=self._helper)
        engine.log_startup_config()


def build_data_processors(
    settings: ConnectorSettings,
) -> list[BaseDataProcessor[ConnectorSettings, ConnectorState]]:
    """Register one import processor per object type, then optional merge/split."""
    processors: list[BaseDataProcessor[ConnectorSettings, ConnectorState]] = []
    for raw in settings.rst_threat_library.object_types:
        obj_type = str(raw).strip()
        if obj_type:
            processors.append(ThreatObjectImportProcessor(obj_type))
    if settings.rst_threat_library.merge_split:
        processors.append(MergeSplitProcessor())
    return processors


if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        state = ConnectorState()
        data_processors = build_data_processors(settings)
        if not data_processors:
            raise ValueError(
                "No data processors configured; set RST_THREAT_LIBRARY_OBJECT_TYPES"
            )

        connector = RSTThreatLibraryConnector(
            settings=settings,
            state=state,
            data_processors=data_processors,
        )
        connector.start()
    except Exception:
        traceback.print_exc()
        raise SystemExit(1) from None
