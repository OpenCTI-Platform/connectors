import logging
import requests

from urllib.parse import urljoin
from typing import Any
from pydantic import ValidationError

from .model import CortexAnalyzer

logger = logging.getLogger(__name__)


class CortexClient:

    IP_ANALYZERS = []
    DOMAIN_ANALYZERS = []

    def __init__(self, api_url: str, api_key: str, verify_ssl=False) -> None:
        """Initialize Cortex API client."""

        if (api_url == "" or api_url is None) or (api_key == "" or api_key is None):
            logger.fatal("cortex api url and key are required!")
            return None
        else:
            self.api_url = urljoin(api_url, "api/")
        self.api_key = api_key
        self.verify_ssl = verify_ssl

        # Initial creation of the analyzer lists per observable type
        self.refresh_analyzers

    def query(self, sub_url: str) -> Any:
        url = urljoin(self.api_url, sub_url)
        headers = {"Authorization": "Bearer " + self.api_key}
        req = requests.get(url, headers=headers, verify=self.verify_ssl)

        if req.status_code == 200:
            return req.json()
        elif req.status_code == 401:
            raise Exception("Access to CORTEX refused. Please check your API key !")
        else:
            raise Exception(
                "error while performing CORTEX query: " + str(req.status_code)
            )

    def refresh_analyzers(self):
        response = self.query("analyzer")
        for ana in response:
            try:
                analyzer = CortexAnalyzer.parse_obj(ana)
            except ValidationError as e:
                self.helper.log_error(f"error marshaling sample data for {ana}: {e}")
                continue
            if "ip" in analyzer.data_type_list:
                self.IP_ANALYZERS += analyzer.analyzer_definition_id
            if "domain" in analyzer.data_type_list:
                self.DOMAIN_ANALYZERS += analyzer.analyzer_definition_id
