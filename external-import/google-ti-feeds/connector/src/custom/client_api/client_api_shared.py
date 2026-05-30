"""Shared client API class for common subentity fetching methods."""

import logging
from typing import Any

from connector.src.custom.client_api.client_api_base import BaseClientAPI

LOG_PREFIX = "[FetcherShared]"


class ClientAPIShared(BaseClientAPI):
    """Shared client API class for common subentity fetching methods."""

    def __init__(
        self,
        config: Any,
        logger: logging.Logger,
        api_client: Any = None,
        fetcher_factory: Any = None,
    ):
        """Initialize Shared Client API."""
        super().__init__(config, logger, api_client, fetcher_factory)

    async def fetch_subentities(
        self, entity_name: str, entity_id: str, subentity_types: list[str]
    ) -> dict[str, list[Any]]:
        """Fetch related subentities with full payloads from the API.

        Args:
            entity_name (str): The name of the entity.
            entity_id (str): The ID of the entity.
            subentity_types (list[str]): The type of subentities to fetch.

        Returns:
            dict[str, list[Any]]: Related subentities grouped by type.

        """
        subentities: dict[str, list[Any]] = {}
        total_collection_calls = 0

        relationships_fetcher = self.fetcher_factory.create_fetcher_by_name(
            "relationships", base_url=self.config.api_url.unicode_string()
        )
        try:
            for subentity_type in subentity_types:
                all_entities: list[Any] = []

                params = {
                    entity_name: entity_id,
                    "entity_type": subentity_type,
                    "limit": 40,
                }

                try:
                    async for page_data in self._paginate_with_cursor(
                        relationships_fetcher, params, f"{subentity_type} relationships"
                    ):
                        total_collection_calls += 1
                        if isinstance(page_data, list):
                            all_entities.extend(page_data)
                        elif isinstance(page_data, dict) and "data" in page_data:
                            data = page_data["data"]
                            if isinstance(data, list):
                                all_entities.extend(data)
                            elif isinstance(data, dict):
                                all_entities.append(data)
                        elif isinstance(page_data, dict):
                            all_entities.append(page_data)

                except Exception as e:
                    self.logger.debug(
                        "Error fetching relationships",
                        {
                            "prefix": LOG_PREFIX,
                            "subentity_type": subentity_type,
                            "error": str(e),
                        },
                    )

                if all_entities:
                    typed_entities = self._deserialize_subentities(
                        subentity_type, all_entities
                    )
                    self.logger.info(
                        "Retrieved related entities",
                        {
                            "prefix": LOG_PREFIX,
                            "count": len(typed_entities),
                            "subentity_type": subentity_type,
                            "entity_name": entity_name,
                            "entity_id": entity_id,
                        },
                    )
                    subentities[subentity_type] = typed_entities
                else:
                    self.logger.debug(
                        "No related entities found",
                        {
                            "prefix": LOG_PREFIX,
                            "subentity_type": subentity_type,
                            "entity_name": entity_name,
                            "entity_id": entity_id,
                        },
                    )

        except Exception as e:
            self.logger.error(
                "Failed to gather relationships",
                {
                    "prefix": LOG_PREFIX,
                    "entity_name": entity_name,
                    "entity_id": entity_id,
                    "error": str(e),
                },
            )
            return {entity_type: [] for entity_type in subentity_types}
        else:
            self.logger.info(
                "Finished gathering relationships",
                {
                    "prefix": LOG_PREFIX,
                    "entity_name": entity_name,
                    "entity_id": entity_id,
                },
            )
            return subentities

    def _deserialize_subentities(
        self, subentity_type: str, entities: list[Any]
    ) -> list[Any]:
        """Deserialize related entities to their configured model when available."""
        try:
            fetcher = self.fetcher_factory.create_fetcher_by_name(
                subentity_type, base_url=self.config.api_url.unicode_string()
            )
            response_model = fetcher.config.response_model
        except Exception as e:
            self.logger.debug(
                "Could not create typed fetcher for related entities",
                {
                    "prefix": LOG_PREFIX,
                    "subentity_type": subentity_type,
                    "error": str(e),
                },
            )
            response_model = None

        deserialized_entities: list[Any] = []
        for entity in entities:
            if response_model and isinstance(entity, dict):
                try:
                    deserialized_entities.append(response_model.model_validate(entity))
                    continue
                except Exception as e:
                    self.logger.debug(
                        "Failed to deserialize related entity, keeping raw payload",
                        {
                            "prefix": LOG_PREFIX,
                            "subentity_type": subentity_type,
                            "error": str(e),
                        },
                    )
            deserialized_entities.append(entity)

        return deserialized_entities
