import requests

from .utils import (
    is_cidr,
    is_full_network,
    is_private_cidr,
    is_private_ip,
    networkcidr_to_list,
)


class ConnectorClient:
    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config

        headers = {"Bearer": self.config.api_key}
        self.session = requests.Session()
        if self.config.api_key and self.config.api_key != "":
            self.session.headers.update(headers)

    def _request_data(self, api_url: str, params=None):
        """
        Internal method to handle API requests
        :return: Response in JSON format
        """
        try:
            response = self.session.get(api_url, params=params)

            self.helper.connector_logger.info(
                "[API] HTTP Get Request to endpoint", {"url_path": api_url}
            )

            response.raise_for_status()
            if response.ok:
                return response
            return None

        except requests.RequestException as err:
            error_msg = "[API] Error while fetching data: "
            self.helper.connector_logger.error(
                error_msg, {"url_path": {api_url}, "error": {str(err)}}
            )
            return None

    def get_entities(self, params=None) -> list:
        """
        If params is None, retrieve all IPs in the Github Repository
        :param params: Optional Params to filter what list to return
        :return: A list of IPs
        """
        ips = []
        try:
            response = self._request_data(self.config.api_base_url, params=params)
            if response is not None:
                for line in response.text.splitlines():
                    if not line.startswith("#"):
                        ip = line.strip()
                        if is_cidr(ip):
                            if is_full_network(ip) or is_private_cidr(ip):
                                continue
                            network_ips = networkcidr_to_list(ip)
                            ips.extend(network_ips)
                        else:
                            if not is_private_ip(ip):
                                ips.append(ip)
            return ips
        except Exception as err:
            self.helper.connector_logger.error(err)
