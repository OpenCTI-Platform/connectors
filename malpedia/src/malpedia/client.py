# -*- coding: utf-8 -*-
"""OpenCTI Malpedia client module."""
import logging
import requests

from urllib.parse import urljoin
from typing import Any

logger = logging.getLogger(__name__)


class MalpediaClient:

    _DEFAULT_API_URL = "https://malpedia.caad.fkie.fraunhofer.de/api/"

    def __init__(self, api_key: str) -> None:
        """Initialize Malpedia api client."""
        self.api_url = self._DEFAULT_API_URL
        self.api_key = api_key

        if self.api_key == "" or self.api_key is None:
            self.unauthenticated = True
        else:
            self.unauthenticated = False
            if not self.token_check():
                logger.fatal("error verifying Malpedia token")

    def query(self, url_path: str) -> Any:
        url = urljoin(self._DEFAULT_API_URL, url_path)
        try:
            if self.unauthenticated:
                r = requests.get(url)
                data = r.json()
            else:
                r = requests.get(
                    url, headers={"Authorization": "apitoken " + self.api_key},
                )
                data = r.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"error in malpedia query: {e}")
            return None
        return data

    def token_check(self) -> bool:
        response_json = self.query("check/apikey")
        if "Valid token" in response_json["detail"]:
            return True

    def current_version(self) -> int:
        response_json = self.query("get/version")
        if response_json is None:
            return 0
        return int(response_json["version"])
