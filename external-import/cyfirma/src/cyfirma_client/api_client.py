import json
from typing import Any, Dict

import requests
from pycti import OpenCTIConnectorHelper
from pydantic import HttpUrl

from connector.utils import (
    _IOC_GENERIC_PATH,
    _IOC_TAILORED_PATH,
    _VUL_GENERIC_PATH,
    _VUL_TAILORED_PATH,
    _ALERTS_API_PATH,
    CYFIRMA_EXTENSION_DEFINITION_ID,
    OPENCTI_EXTENSION_DEFINITION_ID,
    get_request_headers,
    get_request_params,
)

import uuid


class CyfirmaClient:
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        base_url: HttpUrl,
        api_key: str,
        tailored_iocs: bool,
        look_back_days: int = 7,
        tailored_vulnerabilities: bool = False,
        alerts_look_back_days: int = 90,
    ):
        """
        Initialize the Cyfirma API client.

        Args:
            helper (OpenCTIConnectorHelper): The helper of the connector. Used for logging.
            base_url (HttpUrl): The external API base URL.
            api_key (str): The API key to authenticate the connector to the external API.
            iocs_data_type (bool): Whether to fetch tailored IOCs.
            look_back_days (int): Number of days to look back for fetching IOCs.
            tailored_vulnerabilities (bool): Whether to fetch tailored vulnerabilities.
        """
        self.helper = helper
        self.base_url = str(base_url)
        self.tailored_iocs = tailored_iocs
        self.api_key = api_key
        self.look_back_days = look_back_days
        self.tailored_vulnerabilities = tailored_vulnerabilities
        self.alerts_look_back_days = alerts_look_back_days

        self.session = requests.Session()
        # self.session.headers.update(self.headers)

    def _request_data(
        self, api_url: str, params=None, headers=None
    ) -> requests.Response:
        """
        Internal method to handle API requests.

        :param api_url: Target URL
        :param params: Query parameters
        :return: Response object or None if an error occurs
        """
        try:
            response = self.session.get(
                api_url, params=params, headers=headers, timeout=30
            )

            self.helper.connector_logger.debug(
                "CYFIRMA>> HTTP Get Request to endpoint", {"url_path": api_url}
            )

            response.raise_for_status()
            if response.status_code == 200 and response.content:
                return response.json()

            return {}

        except requests.RequestException as err:
            error_msg = "[API] Error while fetching data: "
            self.helper.connector_logger.error(
                error_msg, {"url_path": api_url, "error": str(err)}
            )
            return None

    def get_entities(self):
        """
        Fetch entities from the Cyfirma API.

        :return: List of entities or an empty list if an error occurs
        """
        try:
            indicators = []  # self.get_indicators_feeds() or []
            vulnerabilities = []  # self.get_vulnerabilities_feeds() or []
            as_alerts = self.get_asm() or []

            if indicators is None and vulnerabilities is None and as_alerts is None:
                self.helper.connector_logger.error(
                    "[API] Error while fetching entities: No data returned from API"
                )
                return []

            # return indicators + vulnerabilities + as_alerts
            return as_alerts
        except Exception as err:
            self.helper.connector_logger.error(
                "[API] Error while fetching entities: " + str(err)
            )
            return []

    def get_indicators_feeds(self):
        try:
            self.headers = get_request_headers(self.api_key)
            self.session.headers.update(self.headers)

            ioc_api_path = (
                _IOC_TAILORED_PATH if self.tailored_iocs else _IOC_GENERIC_PATH
            )

            ioc_request_params = get_request_params(self.look_back_days)

            ti_api_path = f"{self.base_url}{ioc_api_path}"

            return_data = []
            while True:
                data = self._request_data(
                    ti_api_path, params=ioc_request_params, headers=self.headers
                )

                res_data = data.get("objects", [])
                self.helper.connector_logger.info(
                    f"CYFIRMA -- Fetched {len(res_data)} entities from API on page {ioc_request_params['page']}"
                )

                if res_data:
                    return_data.extend(res_data)
                    ioc_request_params["page"] += 1
                else:
                    break

            self.helper.connector_logger.info(
                f"CYFIRMA connector -- Successfully fetched {len(return_data)} entities from API"
            )

            return return_data

        except Exception as err:
            self.helper.connector_logger.error(str(err))
            return {}

    def get_vulnerabilities_feeds(self):
        try:
            self.headers = get_request_headers(self.api_key)
            self.session.headers.update(self.headers)

            vul_api_path = (
                _VUL_TAILORED_PATH
                if self.tailored_vulnerabilities
                else _VUL_GENERIC_PATH
            )

            vul_request_params = get_request_params(self.look_back_days)

            vul_api_url = f"{self.base_url}{vul_api_path}"

            return_data = []
            while True:
                data = self._request_data(
                    vul_api_url, params=vul_request_params, headers=self.headers
                )

                res_data = data.get("objects", [])
                self.helper.connector_logger.info(
                    f"CYFIRMA -- Fetched {len(res_data)} vulnerabilities from API on page {vul_request_params['page']}"
                )

                if res_data:
                    return_data.extend(res_data)
                    vul_request_params["page"] += 1
                else:
                    break

            self.helper.connector_logger.info(
                f"CYFIRMA connector -- Successfully fetched {len(return_data)} vulnerabilities from API"
            )

            for vuln in return_data:
                self._convert_to_opencti_vulnerabilities(vuln)

            return return_data

        except Exception as err:
            self.helper.connector_logger.error(str(err))
            return {}

    def _convert_to_opencti_vulnerabilities(self, vuln: dict) -> Dict[str, Any]:
        """Convert vulnerability to OpenCTI format."""
        try:
            # extension_key = next(iter(vuln.get("extensions", {})), None)
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
                new_extension_props["cvss_vector"] = str(
                    ext_props.get("cvss_vector", "")
                ).replace("3.0", "3.1")
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
                # new_extension_props["cvss_exploit_code_maturity"] = ext_props.get("exploitability_score", "0.0")
            elif "2" in cvss_version:
                new_extension_props["x_opencti_cvss_v2_base_score"] = float(
                    ext_props.get("cvss_base_score", 0.0)
                )
                new_extension_props["x_opencti_cvss_v2_base_severity"] = ext_props.get(
                    "severity", ""
                )
                new_extension_props["x_opencti_cvss_v2_attack_vector"] = ext_props.get(
                    "attack_vector", ""
                )
                new_extension_props["x_opencti_cvss_v2_integrity_impact"] = (
                    ext_props.get("integrity_impact", "")
                )
                new_extension_props["x_opencti_cvss_v2_vector_string"] = ext_props.get(
                    "cvss_vector", ""
                )
                new_extension_props["x_opencti_cvss_v2_attack_complexity"] = (
                    ext_props.get("attack_complexity", "")
                )
                new_extension_props["x_opencti_cvss_v2_privileges_required"] = (
                    ext_props.get("privileges_required", "")
                )
                new_extension_props["x_opencti_cvss_v2_user_interaction"] = (
                    ext_props.get("user_interaction", "")
                )
                new_extension_props["x_opencti_cvss_v2_scope"] = ext_props.get(
                    "scope", ""
                )
                new_extension_props["x_opencti_cvss_v2_confidentiality_impact"] = (
                    ext_props.get("confidentiality_impact", "")
                )
                new_extension_props["x_opencti_cvss_v2_availability_impact"] = (
                    ext_props.get("availability_impact", "")
                )
                # new_extension_props["x_opencti_cvss_v2_exploit_code_maturity"] = ext_props.get("exploitability_score", "0.0")

            vuln["extensions"] = {OPENCTI_EXTENSION_DEFINITION_ID: new_extension_props}
            vuln["external_references"] = []
            return vuln
        except Exception as ex:
            self.helper.connector_logger.error(
                f"Error converting vulnerability {vuln.get('id')}: {ex}"
            )
            return vuln

    def get_asm(self):
        try:
            self.headers = get_request_headers(self.api_key)
            self.session.headers.update(self.headers)

            params = get_request_params(self.alerts_look_back_days)

            api_path = f"{self.base_url}{_ALERTS_API_PATH}"

            return_data = []
            while True:
                data = self._request_data(api_path, params=params, headers=self.headers)

                res_data = data.get("objects", [])
                self.helper.connector_logger.info(
                    f"CYFIRMA -- Fetched {len(res_data)} ASM alerts from API on page {params['page']}"
                )

                if res_data:
                    return_data.extend(res_data)
                    params["page"] += 1
                else:
                    break

            self.helper.connector_logger.info(
                f"CYFIRMA connector -- Successfully fetched {len(return_data)} ASM alerts from API"
            )

            for alert in return_data:
                # Convert the alert to OpenCTI format if needed
                if "incident" in alert.get("type", "").lower():
                    alert["incident_type"] = "alert"

            return return_data

        except Exception as err:
            self.helper.connector_logger.error(str(err))
            return {}
