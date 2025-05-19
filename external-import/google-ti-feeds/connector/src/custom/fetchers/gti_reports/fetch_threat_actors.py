"""Fetcher to gather information about threat actors related to reports from Google TI feeds.

This class is responsible for fetching threat actors related to reports from Google TI feeds.
It inherits from the BaseFetcher class and implements the fetch method.
"""

import logging
from typing import TYPE_CHECKING, Dict, List, Optional

from connector.src.custom.interfaces.base_fetcher import BaseFetcher
from connector.src.custom.meta.gti_reports.reports_meta import (
    THREAT_ACTORS_BROKER,
)
from connector.src.custom.models.gti_reports.gti_threat_actor_model import (
    GTIThreatActorData,
    GTIThreatActorResponse,
)
from connector.src.custom.utils.paginate_helper import _fetch_paginated_data
from connector.src.octi.pubsub import broker
from connector.src.utils.api_engine.exceptions.api_network_error import ApiNetworkError

if TYPE_CHECKING:
    from logging import Logger

    from connector.src.custom.configs.gti_config import GTIConfig
    from connector.src.custom.models.gti_reports.gti_report_model import (
        GTIReportData,
    )
    from connector.src.utils.api_engine.api_client import ApiClient

LOG_PREFIX = "[Fetch Threat Actors]"


class FetchThreatActors(BaseFetcher):
    """Fetcher to gather information about threat actors related to reports from Google TI feeds.

    This class is responsible for fetching threat actors related to reports from Google TI feeds.
    It inherits from the BaseFetcher class and implements the fetch method.
    """

    def __init__(
        self,
        gti_config: "GTIConfig",
        api_client: "ApiClient",
        report: "GTIReportData",
        logger: Optional["Logger"] = None,
    ) -> None:
        """Initialize the FetchThreatActors class.

        Args:
            gti_config (GTIConfig): The configuration object for the Google TI feeds.
            api_client (ApiClient): The API client for making requests.
            report (GTIReportData): The report data object.
            logger (Optional[Logger], optional): The logger object for logging. Defaults to None.

        """
        self._gti_config = gti_config
        self._api_client = api_client
        self._report = report
        self._report_id = report.id
        self._logger = logger or logging.getLogger(__name__)

    async def fetch(self) -> bool:
        """Fetch threat actors related to a specific report from Google TI feeds."""
        try:
            self._logger.debug(
                f"{LOG_PREFIX} Fetching threat actors for report {self._report_id}..."
            )
            await self._fetch_report_threat_actors()
        except ApiNetworkError as e:
            self._logger.error(
                f"{LOG_PREFIX} Network connectivity issue during fetch. Please check your internet connection: {str(e)}",
                meta={"error": str(e), "is_network_error": True},
            )  # type: ignore[call-arg]
            raise
        except Exception as e:
            self._logger.error(
                f"{LOG_PREFIX} Error fetching threat actors for report {self._report_id}.",
                meta={"error": str(e), "report_id": self._report_id},
            )  # type: ignore[call-arg]
            return False
        return True

    async def _fetch_report_threat_actors(self) -> None:
        """Fetch threat actors related to a specific report from Google TI feeds.

        It uses the '/collections/{id}/relationships/threat_actors' endpoint to get related threat actor IDs,
        then fetches full details for each threat actor.

        Raises:
            ApiNetworkError: If a network connectivity issue occurs.
            Exception: For any other errors during fetching.

        """
        self.base_url = self._gti_config.api_url
        relationships_endpoint = (
            f"{self.base_url}/collections/{self._report_id}/relationships/threat_actors"
        )
        self._logger.debug(
            f"{LOG_PREFIX} Fetching threat actors for report {self._report_id} from endpoint: {relationships_endpoint}"
        )

        self.headers = {
            "X-Apikey": self._gti_config.api_key,
            "accept": "application/json",
        }
        query_params = {"limit": 40}

        await self._fetch_threat_actor_ids(relationships_endpoint, query_params)

    async def _fetch_threat_actor_ids(
        self, endpoint: str, params: Dict[str, int]
    ) -> None:
        """Fetch threat actor IDs related to a report.

        Args:
            endpoint (str): The endpoint to fetch data from.
            params (Dict[str, int]): The query parameters to use for the request.

        """
        await _fetch_paginated_data(
            api_client=self._api_client,
            model=None,
            url=endpoint,
            headers=self.headers,
            params=params,
            data_processor=self.process_ids_data,
            logger=self._logger,
        )

    async def process_ids_data(
        self,
        response_data: Dict,
        retrieved_count: int,
        total_count: int,
    ) -> None:
        """Process the threat actor IDs from the API response.

        Args:
            response_data (Dict): The response data from the API.
            retrieved_count (int): The count of retrieved items.
            total_count (int): The total count of items.

        """
        threat_actor_ids: List[str] = []
        if "data" not in response_data or response_data["data"] == []:
            self._logger.debug(f"{LOG_PREFIX} No data in response.")
            return

        for item in response_data.get("data", []):
            if isinstance(item, dict) and item.get("id"):
                id: str = str(item.get("id"))
                threat_actor_ids.extend([id])

        if len(threat_actor_ids) > 0:
            self._logger.info(
                f"{LOG_PREFIX} Found {len(threat_actor_ids)} threat actor IDs."
            )
            await self._fetch_threat_actor_details(
                threat_actor_ids, self.base_url, self.headers
            )

    async def _fetch_threat_actor_details(
        self, threat_actor_ids: List[str], base_url: str, headers: Dict[str, str]
    ) -> None:
        """Fetch details for each threat actor ID.

        Args:
            threat_actor_ids (List[str]): List of threat actor IDs to fetch details for.
            base_url (str): The base URL for the API.
            headers (Dict[str, str]): The headers to use for the request.

        """
        threat_actor_details = []
        for actor_id in threat_actor_ids:
            try:
                endpoint = f"{base_url}/collections/{actor_id}"
                self._logger.info(
                    f"{LOG_PREFIX} Fetching details for threat actor {actor_id}"
                )

                gti_threat_actor_response = await self._api_client.call_api(
                    url=endpoint,
                    headers=headers,
                    model=GTIThreatActorResponse,
                    timeout=60,
                )
                threat_actor_details.append(gti_threat_actor_response.data)
            except Exception as e:
                self._logger.error(
                    f"{LOG_PREFIX} Error fetching details for threat actor {actor_id}: {str(e)}",
                    meta={"error": str(e), "actor_id": actor_id},
                )  # type: ignore[call-arg]
            await self._publish_threat_actors(threat_actor_details)

    async def _publish_threat_actors(
        self, threat_actors: List[GTIThreatActorData]
    ) -> None:
        """Publish the fetched threat actors into the pubsub broker for further processing.

        Args:
            threat_actors (List[GTIThreatActorData]): The threat actor data to publish.

        """
        await broker.publish(THREAT_ACTORS_BROKER, (self._report, threat_actors))
        self._logger.info(
            f"{LOG_PREFIX} Threat actors for {self._report_id} published to broker for processing."
        )
