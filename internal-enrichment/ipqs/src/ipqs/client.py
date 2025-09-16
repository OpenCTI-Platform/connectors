"""IPQS client module."""

import re
from typing import Any, Dict, Optional

from pycti import OpenCTIConnectorHelper
from requests import Response, session
from requests.exceptions import ConnectTimeout, HTTPError, InvalidURL, ProxyError

from .constants import (
    IP_ENRICH_FIELDS,
    URL_ENRICH_FIELDS,
    EMAIL_ENRICH_FIELDS,
    PHONE_ENRICH_FIELDS,
)


class IPQSClient:
    """IPQS client."""

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        base_url: str,
        api_key: str,
    ) -> None:
        """Initialize IPQS client."""
        self.helper = helper
        self.url = base_url
        self.headers = {"IPQS-KEY": api_key}
        self.session = session()
        self.api_key = api_key

        self.ip_enrich_fields = IP_ENRICH_FIELDS
        self.url_enrich_fields = URL_ENRICH_FIELDS
        self.email_enrich_fields = EMAIL_ENRICH_FIELDS
        self.phone_enrich_fields = PHONE_ENRICH_FIELDS

    def _query(
        self, url: str, params: Optional[Dict[str, Any]] = None
    ) -> Response | None:
        """General get method to fetch the response from ipqs."""
        try:
            response = self.session.get(url, headers=self.headers, params=params).json()
            if str(response["success"]) != "True":
                msg = response["message"]
                self.helper.log_error(f"Error: {msg}")
                return None
            return response
        except (ConnectTimeout, ProxyError, InvalidURL) as error:
            msg = "Error connecting with the ipqs."
            self.helper.log_error(f"{msg} Error: {error}")
            return None

    def get_ipqs_info(self, enrich_type, enrich_value):
        """Returns the IPQS data."""
        url = f"{self.url}/{enrich_type}"
        params = {enrich_type: enrich_value}
        try:
            response = self._query(url, params)
        except HTTPError as error:
            msg = (
                f"Error when requesting data from ipqs."
                f" {error.response}: {error.response.reason}"
            )
            self.helper.log_error(msg)
            raise
        return response

    def get_dark_info(self, enrich_type, enrich_value):
        """Returns IPQS Darkweb Leak Data"""
        email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        """Decide email vs username."""
        if enrich_type == "username_email":
            query_type = (
                "email" if re.fullmatch(email_regex, enrich_value) else "username"
            )
        else:
            query_type = "password"
        post_data = {query_type: enrich_value}

        # API key must be in the URL path for the leaked endpoint

        url = f"{self.url}/leaked/{query_type}/{self.api_key}"

        try:
            resp = self.session.post(url, json=post_data, timeout=15)
            resp.raise_for_status()
            data = resp.json()

            if not data.get("success", False):
                self.helper.log_error(
                    f"IPQS leaked API error: " f"{data.get('message')}"
                )
                return None
            return data

        except (ConnectTimeout, ProxyError, InvalidURL) as e:
            self.helper.log_error(f"Error connecting to IPQS leaked API: {e}")
            return None
