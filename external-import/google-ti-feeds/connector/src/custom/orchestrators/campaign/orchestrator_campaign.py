"""Campaign-specific orchestrator for fetching and processing campaign data."""

from collections.abc import AsyncIterator
from datetime import timedelta
from typing import Any

from connector.src.custom.configs import CAMPAIGN_BATCH_PROCESSOR_CONFIG
from connector.src.custom.convert_to_stix.campaign.convert_to_stix_campaign import (
    ConvertToSTIXCampaign,
)
from connector.src.custom.convert_to_stix.convert_to_stix_base import (
    ioc_data_by_value,
)
from connector.src.custom.orchestrators.collection_orchestrator import (
    CollectionOrchestrator,
)


class OrchestratorCampaign(CollectionOrchestrator):
    """Campaign-specific orchestrator for fetching and processing campaign data."""

    LOG_PREFIX = "[OrchestratorCampaign]"
    collection = "campaign"
    progress_label = "campaigns"
    converter_class = ConvertToSTIXCampaign
    converter: ConvertToSTIXCampaign
    batch_processor_config = CAMPAIGN_BATCH_PROCESSOR_CONFIG

    def _subentity_types(self) -> list[str]:
        return list(self.config.campaign_subentities)

    def _import_start_date(self) -> timedelta:
        return self.config.campaign_import_start_date

    def _fetch(self, initial_state: dict[str, Any] | None) -> AsyncIterator[Any]:
        return self.client_api.fetch_campaigns(initial_state)

    def _convert(self, entity: Any) -> list[Any]:
        return self.converter.convert_campaign_to_stix(entity)

    def _progress_total(self) -> int | None:
        return self.client_api.real_total_campaigns

    def _link_co_occurring_entities(
        self,
        main_entities: list[Any],
        subentity_stix: list[Any],
        subentities: dict[str, list[Any]] | None = None,
    ) -> list[Any]:
        """Create the enabled co-occurrence relationships.

        IOCs are already linked to the campaign itself by the converters.

        Args:
            main_entities: STIX objects of the campaign.
            subentities: GTI sub-entities, for the IOC evidence.
            subentity_stix: Converted sub-entities of the campaign.

        Returns:
            The created relationships.

        """
        relationship_types = self._co_occurrence_relationship_types(
            ("intrusion-set", "malware")
        )
        if not relationship_types:
            return []
        return self.converter.create_co_occurrence_relationships(
            subentity_stix,
            relationship_types,
            container=self._main_entity(main_entities, "campaign"),
            ioc_data=ioc_data_by_value(subentities or {}),
        )
