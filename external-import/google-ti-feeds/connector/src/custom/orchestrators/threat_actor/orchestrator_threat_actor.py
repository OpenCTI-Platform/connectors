"""Threat actor-specific orchestrator for fetching and processing threat actor data."""

from collections.abc import AsyncIterator
from datetime import timedelta
from typing import Any

from connector.src.custom.configs import THREAT_ACTOR_BATCH_PROCESSOR_CONFIG
from connector.src.custom.convert_to_stix.threat_actor.convert_to_stix_threat_actor import (
    ConvertToSTIXThreatActor,
)
from connector.src.custom.orchestrators.collection_orchestrator import (
    CollectionOrchestrator,
)


class OrchestratorThreatActor(CollectionOrchestrator):
    """Threat actor-specific orchestrator for fetching and processing threat actor data."""

    LOG_PREFIX = "[OrchestratorThreatActor]"
    collection = "threat_actor"
    progress_label = "threat actors"
    converter_class = ConvertToSTIXThreatActor
    converter: ConvertToSTIXThreatActor
    batch_processor_config = THREAT_ACTOR_BATCH_PROCESSOR_CONFIG

    def _subentity_types(self) -> list[str]:
        return list(self.config.threat_actor_subentities)

    def _import_start_date(self) -> timedelta:
        return self.config.threat_actor_import_start_date

    def _fetch(self, initial_state: dict[str, Any] | None) -> AsyncIterator[Any]:
        return self.client_api.fetch_threat_actors(initial_state)

    def _convert(self, entity: Any) -> list[Any]:
        return self.converter.convert_threat_actor_to_stix(entity)

    def _progress_total(self) -> int | None:
        return self.client_api.real_total_threat_actors
