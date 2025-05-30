"""Relationship fetcher for Google Threat Intelligence API.

This module provides functionality to fetch relationship IDs between reports
and their related entities (malware families, threat actors, attack techniques, vulnerabilities).
"""

from typing import List

from connector.src.custom.exceptions import GTIRelationshipFetchError
from connector.src.custom.fetchers.base_fetcher import BaseFetcher
from connector.src.utils.api_engine.exceptions.api_network_error import ApiNetworkError


class RelationshipFetcher(BaseFetcher):
    """Fetcher for relationship IDs between reports and their related entities."""

    async def fetch_relationship_ids(
        self, report_id: str, relationship_type: str
    ) -> List[str]:
        """Fetch IDs of entities related to a report through a specific relationship.

        Args:
            report_id: ID of the report
            relationship_type: Type of relationship (e.g., "malware_families", "threat_actors")

        Returns:
            List of entity IDs

        Raises:
            GTIRelationshipFetchError: If there's an error fetching relationship IDs

        """
        entity_ids = []
        endpoint = f"{self.config.api_url}/collections/{report_id}/relationships/{relationship_type}"

        try:
            self.logger.info(
                f"Fetching {relationship_type} for report {report_id} from {endpoint}"
            )

            response = await self.api_client.call_api(
                url=endpoint,
                headers=self.headers,
                params={"limit": 40},
                timeout=60,
            )

            self.logger.debug(
                f"Response for {relationship_type} ({report_id}): {response}"
            )

            if response and isinstance(response, dict) and "data" in response:
                data_length = (
                    len(response["data"]) if isinstance(response["data"], list) else 0
                )
                self.logger.info(
                    f"API returned {data_length} items in data array for {relationship_type} ({report_id})"
                )

                for item in response["data"]:
                    if isinstance(item, dict) and "id" in item:
                        entity_type = item.get("type", "unknown")
                        entity_ids.append(item["id"])
                        self.logger.debug(
                            f"Found entity ID: {item['id']} (type: {entity_type}) for {relationship_type} ({report_id})"
                        )

                if len(entity_ids) > 0:
                    self.logger.info(
                        f"Found {len(entity_ids)} {relationship_type} for report {report_id}: {entity_ids}"
                    )
                return entity_ids
            return []

        except ApiNetworkError as net_err:
            error_msg = f"Network error fetching {relationship_type} IDs for report {report_id}: {str(net_err)}"
            self._log_error(
                error_msg,
                entity_type=relationship_type,
                entity_id=report_id,
                error=net_err,
            )
            self.logger.error(
                f"Network failure for {relationship_type} ({report_id}) at {endpoint}: {str(net_err)}"
            )
            raise GTIRelationshipFetchError(
                f"Network error: {str(net_err)}",
                source_id=report_id,
                relationship_type=relationship_type,
                endpoint=endpoint,
            ) from net_err
        except Exception as e:
            error_msg = f"Error fetching {relationship_type} IDs for report {report_id}: {str(e)}"
            self._log_error(
                error_msg,
                entity_type=relationship_type,
                entity_id=report_id,
                error=e,
            )
            self.logger.error(
                f"General error for {relationship_type} ({report_id}) at {endpoint}: {str(e)}"
            )
            raise GTIRelationshipFetchError(
                f"Failed to fetch relationship IDs: {str(e)}",
                source_id=report_id,
                relationship_type=relationship_type,
                endpoint=endpoint,
            ) from e
