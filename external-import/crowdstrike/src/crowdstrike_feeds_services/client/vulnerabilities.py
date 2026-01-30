from typing import List

from .base_api import BaseCrowdstrikeClient


class VulnerabilitiesAPI(BaseCrowdstrikeClient):
    def __init__(self, helper):
        super().__init__(helper)

    def query_vulnerabilities(self, limit: int, offset: int, sort: str, filter: str):
        """
        Query vulnerability IDs that match provided FQL filters.
        :param limit: Maximum number of records to return (Max: 5000) in integer
        :param offset: Starting index of overall result set from which to return ids in integer
        :param sort: The property to sort by. (Ex: created_timestamp|desc) in str
        :param filter: FQL query expression that should be used to limit the results in str
        :return: Dict object containing API response with vulnerability IDs
        """

        response = self.cs_intel.query_vulnerabilities(
            limit=limit, offset=offset, sort=sort, filter=filter
        )

        self.handle_api_error(response)
        self.helper.connector_logger.info("Getting vulnerability IDs...")

        return response.get("body") if response else {"resources": []}

    def get_vulnerabilities(self, ids: List[str]):
        """
        Get detailed vulnerability information by IDs.
        :param ids: List of vulnerability IDs to retrieve detailed information for
        :return: Dict object containing API response with detailed vulnerability data
        """

        response = self.cs_intel.get_vulnerabilities(ids=ids)

        self.handle_api_error(response)
        self.helper.connector_logger.info(
            f"Getting detailed vulnerability data for {len(ids)} vulnerabilities..."
        )

        return response.get("body") if response else {"resources": []}
