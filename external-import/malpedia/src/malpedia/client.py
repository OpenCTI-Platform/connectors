# -*- coding: utf-8 -*-
"""OpenCTI Malpedia client module."""
from typing import Any
from urllib.parse import urljoin

import requests
from pycti import OpenCTIConnectorHelper


class MalpediaClient:

    _DEFAULT_API_URL = "https://malpedia.caad.fkie.fraunhofer.de/api/"

    def __init__(self, helper: OpenCTIConnectorHelper, api_key: str) -> None:
        """Initialize Malpedia api client."""
        self.helper = helper
        self.api_url = self._DEFAULT_API_URL
        self.api_key = api_key

        if self.api_key == "" or self.api_key is None:
            self.unauthenticated = True
        else:
            self.unauthenticated = False
            if not self.token_check():
                self.helper.log_error("error verifying Malpedia token")

    def query(self, url_path: str) -> Any:
        url = urljoin(self._DEFAULT_API_URL, url_path)
        try:
            if self.unauthenticated:
                r = requests.get(url)
                data = r.json()
            else:
                r = requests.get(
                    url, headers={"Authorization": "apitoken " + self.api_key}
                )
                data = r.json()
        except requests.exceptions.RequestException as e:
            self.helper.log_error(f"error in malpedia query: {e}")
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
