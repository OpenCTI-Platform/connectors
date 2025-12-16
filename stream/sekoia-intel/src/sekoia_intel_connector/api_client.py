import requests

from .models import sekoia


class SekoiaClient:
    def __init__(self, helper, config):
        """
        Init Sekoia API client.
        :param helper: Connector's helper from PyCTI
        :param config: Connector's config
        """
        self.helper = helper
        self.config = config

        # Define headers in session and update when needed
        headers = {
            "Authorization": "Bearer " + self.config.sekoia_apikey,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self.session = requests.Session()
        self.session.headers.update(headers)
        self.api_base_url = self.config.sekoia_url
        self.collection_id = self.config.sekoia_ioc_collection_uuid

    def check_ioc_collection_exist(self) -> bool:
        """
        Get the UUID of the IOC collection according to SEKOIA_INTEL_IOC_COLLECTION_NAME.
        If the IOC collection is not existing, a new one is created first.
        """
        url = f"{self.api_base_url}/{self.collection_id}"
        try:
            response = self.session.request(method="GET", url=url)
            response.raise_for_status()

        except requests.RequestException as err:
            self.helper.connector_logger.error(
                "[API] Error while requesting : ",
                {"url_path": f"GET {url}", "error": str(err)},
            )
            return False

        return True

    def send_ioc_in_collection(self, indicator: sekoia.IOCImport):
        """
        Send IOCs in the sekoia collection
        """
        url = f"{self.api_base_url}/{self.collection_id}/indicators/text"
        try:
            response = self.session.request(
                method="POST", url=url, json=indicator.to_dict()
            )
            response.raise_for_status()

            if response.content:
                return response.json()
        except requests.RequestException as err:
            self.helper.connector_logger.error(
                "[API] Error while requesting : ",
                {"url_path": f"POST {url}", "error": str(err)},
            )
            raise err

    def get_ioc_in_collection(self, term: str) -> list:
        """
        Get IOC from the sekoia collection
        """
        url = f"{self.api_base_url}/{self.collection_id}/indicators?term={term}"
        try:
            response = self.session.request(method="GET", url=url)
            response.raise_for_status()
            ioc_data = response.json()
            return ioc_data.get("items", []) if ioc_data else []
        except requests.RequestException as err:
            self.helper.connector_logger.error(
                "[API] Error while requesting : ",
                {"url_path": f"GET {url}", "error": str(err)},
            )
            raise err

    def delete_ioc_in_collection(self, indicator_id: str) -> dict | None:
        """
        Delete IOC from the sekoia collection by its ID
        :param indicator_id: ID of the IOC to delete
        :return: Response from the API or None if no content
        """
        url = f"{self.api_base_url}/{self.collection_id}/indicators/{indicator_id}"
        try:
            response = self.session.request(method="DELETE", url=url)
            if response.status_code == 404:
                return None
            response.raise_for_status()
            return response.json() if response.content else None
        except requests.RequestException as err:
            self.helper.connector_logger.error(
                "[API] Error while requesting : ",
                {"url_path": f"DELETE {url}", "error": str(err)},
            )
            raise err

    def delete_iocs_in_collection(self, indicator: sekoia.IOCImport):
        """
        Delete IOC from the sekoia collection
        """
        terms = indicator.indicators.split("\n")
        if not terms:
            self.helper.connector_logger.info(
                "[API] No IOC to delete",
                {"indicator": indicator.indicators},
            )
            return None

        iocs = []
        # Fetch all IOCs matching the terms
        for term in terms:
            if term != "":
                current_iocs = self.get_ioc_in_collection(term)
                iocs.extend(
                    [ioc for ioc in current_iocs if not ioc.get("revoked", False)]
                )
        if iocs:
            for ioc in iocs:
                self.delete_ioc_in_collection(ioc["id"])
