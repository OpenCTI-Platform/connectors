# -*- coding: utf-8 -*-
"""Virustotal client module."""
import json
import logging
from typing import Any, Optional

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

# Custom type to simulate a JSON format.
JSONType = dict[str, Any]


class VirusTotalClient:
    """VirusTotal client."""

    def __init__(self, base_url: str, token: str) -> None:
        """Initialize Virustotal client."""
        # Drop the ending slash if present.
        self.url = base_url[:-1] if base_url[-1] == "/" else base_url
        logger.info(f"[VirusTotal] URL: {self.url}")
        self.headers = {
            "x-apikey": token,
            "accept": "application/json",
            "content-type": "application/json",
        }

    def _query(self, url: str) -> Optional[JSONType]:
        """
        Execute a query to the Virustotal api.

        The authentication is done using the headers with the token given
        during the creation of the client.

        Retries are done if the query fails.

        Parameters
        ----------
        url : str
            Url to query.

        Returns
        -------
        JSON or None
            The result of the query, as JSON or None in case of failure.
        """
        # Configure the adapter for the retry strategy.
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["HEAD", "GET", "OPTIONS"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        http = requests.Session()
        http.mount("https://", adapter)
        response = None
        try:
            response = http.get(url, headers=self.headers)
            response.raise_for_status()
        except requests.exceptions.HTTPError as errh:
            logger.error(f"[VirusTotal] Http error: {errh}")
        except requests.exceptions.ConnectionError as errc:
            logger.error(f"[VirusTotal] Error connecting: {errc}")
        except requests.exceptions.Timeout as errt:
            logger.error(f"[VirusTotal] Timeout error: {errt}")
        except requests.exceptions.RequestException as err:
            logger.error(f"[VirusTotal] Something else happened: {err}")
        except Exception as err:
            logger.error(
                f"[VirusTotal] Unknown error {err}"
            )
        try:
            return response.json()
        except json.JSONDecodeError as err:
            logger.error(
                f"[VirusTotal] Error decoding the json: {err} - {response.text}"
            )
            return None

    def get_file_info(self, hash: str) -> Optional[JSONType]:
        """
        Retrieve file information based on the given hash-256.

        Parameters
        ----------
        hash : str
            Hash of the file to retrieve.

        Returns
        -------
        JSON
            File information, as JSON.
        """
        url = f"{self.url}/files/{hash}"
        return self._query(url)

    def get_yara_ruleset(self, ruleset_id: str) -> Optional[JSONType]:
        """
        Retrieve the YARA rules based on the given ruleset id.

        Parameters
        ----------
        ruleset_id : str
            Ruleset id to retrieve.

        Returns
        -------
        JSON
            YARA ruleset objects, as JSON.
        """
        url = f"{self.url}/yara_rulesets/{ruleset_id}"
        return self._query(url)
