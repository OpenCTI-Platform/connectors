import random
import time
from typing import Any, Dict, List, Optional

import requests
from connector.utils import (
    _IOC_GENERIC_PATH,
    _IOC_TAILORED_PATH,
    _TA_SEARCH_PATH,
    _VUL_GENERIC_PATH,
    _VUL_TAILORED_PATH,
    CYFIRMA_EXTENSION_DEFINITION_ID,
    CYFIRMA_INDICATOR_EXTENSION_DEFINITION_ID,
    OPENCTI_EXTENSION_DEFINITION_ID,
    get_request_headers,
    get_request_params,
)
from pycti import OpenCTIConnectorHelper
from pydantic import HttpUrl

_RETRY_STATUS = {429, 500, 502, 503, 504}
_MAX_ATTEMPTS = 5
_BACKOFF_BASE = 5  # seconds; waits ~5, 10, 20, 40 (+ jitter)
_BACKOFF_MAX = 120
_TIMEOUT = (10, 120)  # (connect, read)
_PAGE_DELAY = 1.0  # pause between pages and feeds


class CyfirmaClient:
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        base_url: HttpUrl,
        api_key: str,
        tailored_iocs: bool = True,
        look_back_days: int = 7,
        tailored_vulnerabilities: bool = False,
        last_run: str = "",
    ):
        """
        Initialize the Cyfirma API client.

        Args:
            helper (OpenCTIConnectorHelper): The helper of the connector. Used for logging.
            base_url (HttpUrl): The external API base URL.
            api_key (str): The API key to authenticate the connector to the external API.
            tailored_iocs (bool): Whether to fetch tailored IOCs.
            look_back_days (int): Number of days to look back for fetching IOCs.
            tailored_vulnerabilities (bool): Whether to fetch tailored vulnerabilities.
            last_run (str): The timestamp of the last run.
        """
        self.helper = helper
        self.base_url = str(base_url).rstrip("/")
        self.tailored_iocs = tailored_iocs
        self.api_key = api_key
        self.look_back_days = look_back_days
        self.tailored_vulnerabilities = tailored_vulnerabilities
        self.last_run = last_run
        self.session = requests.Session()
        # self.session.headers.update(self.headers)

    def _request_data(self, api_url: str, params=None, headers=None) -> dict[str, Any]:

        last_err: Optional[Exception] = None

        for attempt in range(1, _MAX_ATTEMPTS + 1):
            wait = None
            try:
                response = self.session.get(
                    api_url, params=params, headers=headers, timeout=_TIMEOUT
                )

                self.helper.connector_logger.debug(
                    "CYFIRMA -- HTTP Get Request to endpoint",
                    {"url_path": api_url, "status": response.status_code},
                )

                if response.status_code in _RETRY_STATUS:
                    last_err = requests.HTTPError(
                        f"{response.status_code} for url: {response.url}",
                        response=response,
                    )
                    wait = self._retry_after(response)
                else:
                    response.raise_for_status()  # 4xx (not 429) fail immediately
                    if response.status_code == 200 and response.content:
                        return response.json()
                    return {}

            except (requests.Timeout, requests.ConnectionError) as err:
                last_err = err

            except requests.RequestException as err:
                self.helper.connector_logger.error(
                    "[CONNECTOR] Request failed", {"error": str(err)}
                )
                raise

            if attempt == _MAX_ATTEMPTS:
                break

            if wait is None:
                wait = min(_BACKOFF_MAX, _BACKOFF_BASE * 2 ** (attempt - 1))

            wait += random.uniform(0, 1)

            self.helper.connector_logger.warning(
                "CYFIRMA -- Retryable failure, backing off",
                {"attempt": attempt, "wait_s": round(wait, 1), "error": str(last_err)},
            )
            time.sleep(wait)

        self.helper.connector_logger.error(
            "CYFIRMA -- Request failed after retries", {"error": str(last_err)}
        )
        raise last_err

    @staticmethod
    def _retry_after(response) -> Optional[float]:
        value = response.headers.get("Retry-After")
        try:
            return min(float(value), _BACKOFF_MAX) if value else None
        except ValueError:  # HTTP-date form: fall back to exponential backoff
            return None

    def _fetch_all_pages(self, url: str, params: dict, label: str) -> list:
        results = []
        while True:
            data = self._request_data(url, params=params, headers=self.headers)
            objects = data.get("objects", [])

            self.helper.connector_logger.info(
                f"CYFIRMA --  {label} fetched {len(objects)} from API on page {params['page']}"
            )

            if not objects:
                return results
            results.extend(objects)
            params["page"] += 1
            time.sleep(_PAGE_DELAY)

    def get_indicators_feeds(self):
        try:
            self.headers = get_request_headers(self.api_key)
            self.session.headers.update(self.headers)

            ioc_api_path = (
                _IOC_TAILORED_PATH if self.tailored_iocs else _IOC_GENERIC_PATH
            )

            ioc_request_params = get_request_params(self.look_back_days, self.last_run)

            ti_api_path = f"{self.base_url}{ioc_api_path}"
            ta_api_path = f"{self.base_url}{_TA_SEARCH_PATH}"

            self.helper.connector_logger.info(
                f"CYFIRMA -- API with params: {ti_api_path} with params: {ioc_request_params}"
            )

            return_data = self._fetch_all_pages(
                ti_api_path, ioc_request_params, "Indicators"
            )

            self.helper.connector_logger.info(
                f"CYFIRMA -- Successfully fetched {len(return_data)} entities from API"
            )

            ta_names = {
                name.strip()
                for indicator in return_data
                if indicator.get("type") == "indicator"
                for name in (
                    (indicator.get("extensions") or {})
                    .get(CYFIRMA_INDICATOR_EXTENSION_DEFINITION_ID, {})
                    .get("threat_actors")
                    or ""
                ).split(",")
                if name.strip()
            }

            self.helper.connector_logger.info(
                f"CYFIRMA -- Found {len(ta_names)} unique threat actor names associated with the fetched indicators"
            )

            self.helper.connector_logger.info(
                f"CYFIRMA -- Fetching entities from TA API: {ta_api_path} with params: {list(ta_names)}"
            )

            if ta_names:
                try:
                    ta_res_data = self._request_data(
                        ta_api_path,
                        params={"values": list(ta_names)},
                        headers=self.headers,
                    )
                    return_data.extend(
                        obj
                        for obj in (ta_res_data or {}).get("objects", [])
                        if obj.get("type") != "threat-actor"
                    )
                except requests.RequestException as err:
                    self.helper.connector_logger.error(
                        f"CYFIRMA -- TA enrichment failed, continuing with indicators only: {str(err)}"
                    )

            return return_data

        except Exception as err:
            self.helper.connector_logger.error(str(err))
            raise

    def get_vulnerabilities_feeds(self):
        try:
            self.headers = get_request_headers(self.api_key)
            self.session.headers.update(self.headers)

            vul_api_path = (
                _VUL_TAILORED_PATH
                if self.tailored_vulnerabilities
                else _VUL_GENERIC_PATH
            )

            vul_request_params = get_request_params(self.look_back_days, self.last_run)

            vul_api_url = f"{self.base_url}{vul_api_path}"

            self.helper.connector_logger.info(
                f"CYFIRMA -- Fetching vulnerabilities from API: {vul_api_url} with params: {vul_request_params}"
            )

            return_data = self._fetch_all_pages(
                vul_api_url, vul_request_params, "Vulnerabilities"
            )

            self.helper.connector_logger.info(
                f"CYFIRMA -- Successfully fetched {len(return_data)} vulnerabilities from API"
            )

            for vuln in return_data:
                if vuln.get("type") == "vulnerability":
                    self._convert_to_opencti_vulnerabilities(vuln)

            return return_data
        except Exception as err:
            self.helper.connector_logger.error(str(err))
            raise

    def _convert_to_opencti_vulnerabilities(self, vuln: dict) -> Dict[str, Any]:
        """Convert vulnerability to OpenCTI format."""

        try:
            new_extension_props = {}

            ext_props = vuln.get("extensions", {}).get(
                CYFIRMA_EXTENSION_DEFINITION_ID, {}
            )

            cvss_version = ext_props.get("cvss_version", "")

            if "3" in cvss_version:
                new_extension_props["cvss_base_score"] = float(
                    ext_props.get("cvss_base_score", 0.0)
                )
                new_extension_props["cvss_base_severity"] = ext_props.get(
                    "severity", ""
                )
                new_extension_props["cvss_attack_vector"] = ext_props.get(
                    "attack_vector", ""
                )
                new_extension_props["cvss_integrity_impact"] = ext_props.get(
                    "integrity_impact", ""
                )
                new_extension_props["cvss_vector_string"] = str(
                    ext_props.get("cvss_vector", "")
                )
                new_extension_props["cvss_attack_complexity"] = ext_props.get(
                    "attack_complexity", ""
                )
                new_extension_props["cvss_privileges_required"] = ext_props.get(
                    "privileges_required", ""
                )
                new_extension_props["cvss_user_interaction"] = ext_props.get(
                    "user_interaction", ""
                )
                new_extension_props["cvss_scope"] = ext_props.get("scope", "")
                new_extension_props["cvss_confidentiality_impact"] = ext_props.get(
                    "confidentiality_impact", ""
                )
                new_extension_props["cvss_availability_impact"] = ext_props.get(
                    "availability_impact", ""
                )

            elif "2" in cvss_version:
                new_extension_props["cvss_v2_base_score"] = float(
                    ext_props.get("cvss_base_score")
                )
                new_extension_props["cvss_v2_base_severity"] = ext_props.get(
                    "severity", ""
                )
                new_extension_props["cvss_v2_attack_vector"] = ext_props.get(
                    "attack_vector", ""
                )
                new_extension_props["cvss_v2_integrity_impact"] = ext_props.get(
                    "integrity_impact", ""
                )
                new_extension_props["cvss_v2_vector_string"] = ext_props.get(
                    "cvss_vector", ""
                )
                new_extension_props["cvss_v2_attack_complexity"] = ext_props.get(
                    "attack_complexity", ""
                )
                new_extension_props["cvss_v2_privileges_required"] = ext_props.get(
                    "privileges_required", ""
                )
                new_extension_props["cvss_v2_user_interaction"] = ext_props.get(
                    "user_interaction", ""
                )
                new_extension_props["cvss_v2_scope"] = ext_props.get("scope", "")
                new_extension_props["cvss_v2_confidentiality_impact"] = ext_props.get(
                    "confidentiality_impact", ""
                )
                new_extension_props["cvss_v2_availability_impact"] = ext_props.get(
                    "availability_impact", ""
                )

            extensions = vuln.setdefault("extensions", {})
            extensions.pop(CYFIRMA_EXTENSION_DEFINITION_ID, None)

            opencti_extension = extensions.setdefault(
                OPENCTI_EXTENSION_DEFINITION_ID,
                {"extension_type": "property-extension"},
            )

            opencti_extension.update(new_extension_props)

            return vuln
        except Exception as ex:
            self.helper.connector_logger.error(
                f"Error converting vulnerability {vuln.get('id')}: {ex}"
            )
            raise

    def get_entities(self):
        """
        Fetch entities from the Cyfirma API.

        :return: List of entities or an empty list if an error occurs
        """
        try:
            indicators = self.get_indicators_feeds()
            vulnerabilities = self.get_vulnerabilities_feeds()

            time.sleep(_PAGE_DELAY)

            return indicators + vulnerabilities
        except Exception as err:
            self.helper.connector_logger.error(
                "[API] Error while fetching entities: " + str(err)
            )
            raise
