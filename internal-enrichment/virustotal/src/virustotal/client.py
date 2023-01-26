# -*- coding: utf-8 -*-
"""Virustotal client module."""
import asyncio
import hashlib
import json
import urllib.parse

import requests
from pycti import OpenCTIConnectorHelper
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry


class VirusTotalClient:
    """VirusTotal client."""

    def __init__(
        self, helper: OpenCTIConnectorHelper, base_url: str, token: str
    ) -> None:
        """Initialize Virustotal client."""
        self.helper = helper
        # Drop the ending slash if present.
        self.url = base_url[:-1] if base_url[-1] == "/" else base_url
        self.helper.log_info(f"[VirusTotal] URL: {self.url}")
        self.headers = {
            "x-apikey": token,
            "accept": "application/json",
        }

    def _query(self, url):
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
            response = http.get(
                url, headers=self.headers | {"content-type": "application/json"}
            )
            response.raise_for_status()
        except requests.exceptions.HTTPError as errh:
            self.helper.log_error(f"[VirusTotal] Http error: {errh}")
        except requests.exceptions.ConnectionError as errc:
            self.helper.log_error(f"[VirusTotal] Error connecting: {errc}")
        except requests.exceptions.Timeout as errt:
            self.helper.log_error(f"[VirusTotal] Timeout error: {errt}")
        except requests.exceptions.RequestException as err:
            self.helper.log_error(f"[VirusTotal] Something else happened: {err}")
        except Exception as err:
            self.helper.log_error(f"[VirusTotal] Unknown error {err}")
        try:
            self.helper.log_debug(f"[VirusTotal] data retrieved: {response.json()}")
            return response.json()
        except json.JSONDecodeError as err:
            self.helper.log_error(
                f"[VirusTotal] Error decoding the json: {err} - {response.text}"
            )
            return None

    def _post(self, url, data=None, files=None, additional_headers=None):
        """
        Execute a post to the Virustotal api.

        Parameters
        ----------
        url : str
            Url to post to.
        data : str
            Data payload to be passed with the post.
        files : json
            A JSON object with the files to be posted to VirusTotal.
        additional_headers : dict
            Headers to be added to the self.headers with the request.

        Returns
        -------
        JSON or None
            The result of the query, as JSON or None in case of failure.
        """
        response = None
        headers = (
            self.headers
            if additional_headers == None
            else self.headers | additional_headers
        )
        try:
            response = requests.post(url, data=data, files=files, headers=headers)
            response.raise_for_status()
        except requests.exceptions.HTTPError as errh:
            self.helper.log_error(f"[VirusTotal] Http error: {errh}")
        except requests.exceptions.ConnectionError as errc:
            self.helper.log_error(f"[VirusTotal] Error connecting: {errc}")
        except requests.exceptions.Timeout as errt:
            self.helper.log_error(f"[VirusTotal] Timeout error: {errt}")
        except requests.exceptions.RequestException as err:
            self.helper.log_error(f"[VirusTotal] Something else happened: {err}")
        except Exception as err:
            self.helper.log_error(f"[VirusTotal] Unknown error {err}")
        try:
            self.helper.log_debug(f"[VirusTotal] data retrieved: {response.json()}")
            return response.json()
        except json.JSONDecodeError as err:
            self.helper.log_error(
                f"[VirusTotal] Error decoding the json: {err} - {response.text}"
            )
            return None

    def get_file_info(self, hash256) -> dict:
        """
        Retrieve file information based on the given hash-256.

        Parameters
        ----------
        hash256 : str
            Hash of the file to retrieve.

        Returns
        -------
        dict
            File object, see https://developers.virustotal.com/reference/files
        """
        url = f"{self.url}/files/{hash256}"
        return self._query(url)

    def upload_artifact(self, artifact_name, artifact) -> str:
        """
        Upload an artifact to VirusTotal for analysis

        Parameters
        ----------
        artifact_name : str
            The name of the artifact being uploaded
        artifact : bytes
            The artifact to be uploaded in bytes type

        Returns
        -------
        str
            Analysis id, see https://developers.virustotal.com/reference/analysis
        """
        url = f"{self.url}/files"
        files = {"file": (artifact_name, artifact)}
        return self._post(url, files=files)["data"]["id"]

    def get_yara_ruleset(self, ruleset_id) -> dict:
        """
        Retrieve the YARA rules based on the given ruleset id.

        Parameters
        ----------
        ruleset_id : str
            Ruleset id to retrieve.

        Returns
        -------
        dict
            YARA ruleset objects, see https://developers.virustotal.com/reference/yara-rulesets
        """
        url = f"{self.url}/yara_rulesets/{ruleset_id}"
        return self._query(url)

    def get_ip_info(self, ip):
        """
        Retrieve IP report based on the given IP.

        Parameters
        ----------
        ip : str
            IP address.

        Returns
        -------
        dict
            IP address object, see https://developers.virustotal.com/reference/ip-object
        """
        url = f"{self.url}/ip_addresses/{ip}"
        return self._query(url)

    def get_domain_info(self, domain):
        """
        Retrieve Domain report based on the given Domain.

        Parameters
        ----------
        domain : str
            Domain name.

        Returns
        -------
        dict
            Domain Object, see https://developers.virustotal.com/reference/domains-1
        """
        url = f"{self.url}/domains/{domain}"
        return self._query(url)

    def get_url_info(self, url):
        """
        Retrieve URL report based on the given URL.

        Parameters
        ----------
        url : str
            Url.

        Returns
        -------
        dict
            URL Object, see https://developers.virustotal.com/reference/url-object
        """
        endpoint_url = f"{self.url}/urls/{hashlib.sha256(url.encode()).hexdigest()}"
        return self._query(endpoint_url)

    def upload_url(self, url) -> str:
        """
        Upload a URL to VirusTotal for analysis

        Parameters
        ----------
        url : str
            The URL being uploaded

        Returns
        -------
        str
            Analysis id, see https://developers.virustotal.com/reference/analysis
        """
        endpoint_url = f"{self.url}/urls"
        payload = f"url={urllib.parse.quote(url, safe='')}"
        headers = {"content-type": "application/x-www-form-urlencoded"}
        return self._post(endpoint_url, data=payload, additional_headers=headers)[
            "data"
        ]["id"]

    async def check_upload_status(self, upload_type, name, analysis_id):
        """
        Wait for the uploaded queued artifact or URL to finish being analyzed

        Parameters
        ----------
        upload_type : str
            The type of the upload (artifact || URL)
        name : str
            The name of the upload
        analysis_id : str
            The ID returned by VirusTotal for the analysis job of the upload
        """
        url = f"{self.url}/analyses/{analysis_id}"
        retry_delay = 30 if upload_type == "artifact" else 2  # in seconds
        minimum_retry_delay = 60 if upload_type == "artifact" else 1  # in seconds
        maximum_retry_delay = 180 if upload_type == "artifact" else 10  # in seconds
        total_attempts = 10
        i = 0
        while i < total_attempts:
            current_status = self._query(url)["data"]["attributes"]["status"]
            current_retry_delay = min(
                (i * retry_delay + minimum_retry_delay), maximum_retry_delay
            )
            i += 1
            if not current_status == "completed":
                self.helper.log_debug(
                    f"[VirusTotal] Uploaded {upload_type} {name} current VirusTotal "
                    f"analysis status: {current_status}. Checking status update "
                    f"attempt #{i} of {total_attempts} in {current_retry_delay} seconds."
                )
                await asyncio.sleep(current_retry_delay)
            else:
                return
        raise ValueError(
            f"The uploaded {upload_type} {name} was not analyzed by VirusTotal before the "
            f"timeout was reached. Please try enriching the {upload_type} again at a later time."
        )
