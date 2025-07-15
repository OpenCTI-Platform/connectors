"""Shared client API class for common subentity fetching methods."""

import logging
from typing import Any, Dict, List

from connector.src.custom.client_api.client_api_base import BaseClientAPI
from connector.src.utils.api_engine.exceptions.api_http_error import ApiHttpError

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

    async def fetch_subentities_ids(
        self, entity_name: str, entity_id: str, subentity_types: list[str]
    ) -> Dict[str, List[str]]:
        """Fetch subentities IDs from the API.

        Args:
            entity_name (str): The name of the entity.
            entity_id (str): The ID of the entity.
            subentity_types (list[str]): The type of subentities to fetch.

        Returns:
            Dict[str, List[str]]: The fetched subentities IDs.

        """
        subentities_ids = {}

        relationships_fetcher = self.fetcher_factory.create_fetcher_by_name(
            "relationships", base_url=self.config.api_url
        )
        try:
            for subentity_type in subentity_types:
                all_ids = []

                params = {entity_name: entity_id, "entity_type": subentity_type}

                try:
                    async for page_data in self._paginate_with_cursor(
                        relationships_fetcher, params, f"{subentity_type} relationships"
                    ):
                        if isinstance(page_data, list):
                            all_ids.extend(
                                [
                                    item["id"]
                                    for item in page_data
                                    if isinstance(item, dict) and item.get("id")
                                ]
                            )
                        elif isinstance(page_data, dict) and "data" in page_data:
                            data = page_data["data"]
                            if isinstance(data, list):
                                all_ids.extend(
                                    [
                                        item["id"]
                                        for item in data
                                        if isinstance(item, dict) and item.get("id")
                                    ]
                                )

                except Exception as e:
                    self.logger.debug(
                        f"{LOG_PREFIX} Error fetching {subentity_type} relationships: {str(e)}"
                    )

                if all_ids:
                    self.logger.info(
                        f"{LOG_PREFIX} Retrieved {len(all_ids)} {subentity_type} relationship IDs for {entity_name} {entity_id}"
                    )
                    subentities_ids[subentity_type] = all_ids
                else:
                    self.logger.debug(
                        f"{LOG_PREFIX} No {subentity_type} relationship IDs found for {entity_name} {entity_id}"
                    )

            return subentities_ids
        except Exception as e:
            self.logger.error(
                f"{LOG_PREFIX} Failed to gather relationships for {entity_name} {entity_id}: {str(e)}"
            )
            return {entity_type: [] for entity_type in subentity_types}
        finally:
            self.logger.info(
                f"{LOG_PREFIX} Finished gathering relationships for {entity_name} {entity_id}"
            )

    async def fetch_subentity_details(
        self, subentity_ids: Dict[str, List[str]]
    ) -> Dict[str, List[Any]]:
        """Fetch subentity details in parallel for multiple IDs.

        Args:
            subentity_ids: Dictionary mapping entity types to lists of IDs

        Returns:
            Dictionary mapping entity types to lists of fetched entities

        """
        subentities: Dict[str, List[Any]] = {}
        total_to_fetch = sum(len(ids) for ids in subentity_ids.values())

        if total_to_fetch > 0:
            self.logger.info(
                f"{LOG_PREFIX} Fetching details for {total_to_fetch} subentities..."
            )

        for entity_type, ids in subentity_ids.items():
            if not ids:
                subentities[entity_type] = []
                continue

            try:
                fetcher = self.fetcher_factory.create_fetcher_by_name(
                    entity_type, base_url=self.config.api_url
                )
                entities = await fetcher.fetch_multiple(ids)
                subentities[entity_type] = entities
                self.logger.debug(
                    f"{LOG_PREFIX} Fetched {len(entities)} {entity_type} entities"
                )

            except ApiHttpError as e:
                if e.status_code == 404 and entity_type == "files":
                    self.logger.info(
                        f"{LOG_PREFIX} 404 errors expected for files (files may no longer exist in VirusTotal). Treating as normal behavior."
                    )
                    subentities[entity_type] = []
                else:
                    self.logger.error(
                        f"{LOG_PREFIX} HTTP {e.status_code} error fetching {entity_type} details: {str(e)}"
                    )
                    subentities[entity_type] = []
            except Exception as e:
                self.logger.error(
                    f"{LOG_PREFIX} Failed to fetch {entity_type} details: {str(e)}"
                )
                subentities[entity_type] = []

        if total_to_fetch > 0:
            fetched_summary = ", ".join(
                [f"{k}: {len(v)}" for k, v in subentities.items() if len(v) > 0]
            )
            if fetched_summary:
                self.logger.info(f"{LOG_PREFIX} Fetched details {{{fetched_summary}}}")

        return subentities
