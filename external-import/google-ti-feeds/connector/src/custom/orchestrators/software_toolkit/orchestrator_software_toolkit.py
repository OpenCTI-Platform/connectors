"""Software toolkit-specific orchestrator for fetching and processing software toolkit data."""

from collections.abc import AsyncIterator
from datetime import timedelta
from typing import Any

from connector.src.custom.configs import SOFTWARE_TOOLKIT_BATCH_PROCESSOR_CONFIG
from connector.src.custom.convert_to_stix.software_toolkit.convert_to_stix_software_toolkit import (
    ConvertToSTIXSoftwareToolkit,
)
from connector.src.custom.orchestrators.collection_orchestrator import (
    CollectionOrchestrator,
)


class OrchestratorSoftwareToolkit(CollectionOrchestrator):
    """Software toolkit-specific orchestrator for fetching and processing software toolkit data."""

    LOG_PREFIX = "[OrchestratorSoftwareToolkit]"
    collection = "software_toolkit"
    progress_label = "software toolkits"
    converter_class = ConvertToSTIXSoftwareToolkit
    converter: ConvertToSTIXSoftwareToolkit
    batch_processor_config = SOFTWARE_TOOLKIT_BATCH_PROCESSOR_CONFIG

    def _subentity_types(self) -> list[str]:
        return list(self.config.software_toolkit_subentities)

    def _import_start_date(self) -> timedelta:
        return self.config.software_toolkit_import_start_date

    def _fetch(self, initial_state: dict[str, Any] | None) -> AsyncIterator[Any]:
        return self.client_api.fetch_software_toolkits(initial_state)

    def _convert(self, entity: Any) -> list[Any]:
        return self.converter.convert_software_toolkit_to_stix(entity)

    def _progress_total(self) -> int | None:
        return self.client_api.real_total_software_toolkits
