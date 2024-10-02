import requests
from pycti import OpenCTIConnectorHelper

from .utils import (
    get_action,
    get_description,
    get_expiration_datetime,
    get_hash_type,
    get_hash_value,
    get_ioc_type,
    get_tags,
    get_threat_type,
    get_tlp_level,
)


class SentinelApiHandler:
    def __init__(self, helper, config):
        """
        Init Tanium API handler.
        :param helper: PyCTI helper instance
        :param config: Connector config variables
        """
        self.helper = helper
        self.config = config

        self.headers = None
        self._set_authorization_header()

    def _set_authorization_header(self):
        """
        Get an OAuth access token and set it as Authorization header in headers.
        """
        try:
            url = f"https://login.microsoftonline.com/{self.config.tenant_id}/oauth2/v2.0/token"
            body = {
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
                "grant_type": "client_credentials",
                "scope": "https://graph.microsoft.com/.default",
            }
            response = requests.post(url, data=body)
            response_json = response.json()
            oauth_token = response_json["access_token"]

            self.headers = {"Authorization": oauth_token}
        except Exception as e:
            raise ValueError("[ERROR] Failed generating oauth token {" + str(e) + "}")

    def _build_request_body(self, observable: dict) -> dict:
        """
        Build Sentinel POST/PATCH request's body from an observable.
        :param observable: Observable to build body from
        :return: Dict containing keys/values required for POST/PATCH requests on Sentinel.
        """
        body = {
            "threatType": get_threat_type(observable),
            "description": get_description(observable),
            "tags": get_tags(observable),
            "confidence": observable.get("confidence", 50),
            "externalId": OpenCTIConnectorHelper.get_attribute_in_extension(
                "id", observable
            ),
            "lastReportedDateTime": OpenCTIConnectorHelper.get_attribute_in_extension(
                "updated_at", observable
            ),
            "expirationDateTime": get_expiration_datetime(
                observable, int(self.config.expire_time)
            ),
            "action": self.config.action or get_action(observable),
            "tlpLevel": self.config.tlp_level or get_tlp_level(observable),
            "passiveOnly": "true" if self.config.passive_only else "false",
            "targetProduct": self.config.target_product,
        }

        network_types = ["ipv4-addr", "ipv6-addr", "domain-name", "url"]
        if observable["type"] in network_types:
            ioc_type = get_ioc_type(observable)
            body[ioc_type] = observable.get("value", None)
        elif observable["type"] == "email-addr":
            body["emailSenderAddress"] = observable.get("value", None)
            body["emailSenderName"] = observable.get("display_name", None)
        elif observable["type"] == "file":
            body["fileHashType"] = get_hash_type(observable)
            body["fileHashValue"] = get_hash_value(observable)
            body["fileName"] = observable.get("name", None)
            body["fileSize"] = observable.get("size", 0)
            body["fileCreatedDateTime"] = (
                OpenCTIConnectorHelper.get_attribute_in_extension(
                    "created_at", observable
                )
            )
        else:
            body = {}
        return body

    def get_indicators(self) -> list[dict] | None:
        """
        Get Threat Intelligence Indicators from Sentinel.
        :return: List of Threat Intelligence Indicators if request is succesful, None otherwise
        """
        try:
            response = requests.get(
                f"{self.config.resource_url}{self.config.request_url}",
                headers=self.headers,
            )
            response.raise_for_status()

            self.helper.connector_logger.info(
                f"[API] HTTP GET Request to endpoint",
                {"url_path": self.config.request_url},
            )

            return response.json()["value"]
        except requests.RequestException as err:
            self.helper.connector_logger.error(
                "[API] Error while fetching data: ",
                {"url_path": f"GET {self.config.request_url}", "error": str(err)},
            )
            return None

    def search_indicator(self, observable_opencti_id: str) -> dict | None:
        """
        Search a Threath Intelligence Indicator on Sentinel that corresponds to an OpenCTI observable.
        :param observable_opencti_id: OpenCTI ID of the observable to get Threat Intelligence Indicator for
        :return: Threat Intelligence Indicator if request is succesful, None otherwise
        """
        try:
            params = f"$filter=externalId eq '{observable_opencti_id}'"
            response = requests.get(
                f"{self.config.resource_url}{self.config.request_url}",
                params=params,
                headers=self.headers,
            )
            response.raise_for_status()

            self.helper.connector_logger.info(
                f"[API] HTTP GET Request to endpoint",
                {"url_path": self.config.request_url},
            )

            response_json = response.json()
            if len(response_json["value"]) == 1:
                return response_json["value"][0]
        except requests.RequestException as err:
            self.helper.connector_logger.error(
                "[API] Error while fetching data: ",
                {"url_path": f"GET {self.config.request_url}", "error": str(err)},
            )
            return None

    def post_indicator(self, observable: dict) -> dict | None:
        """
        Create a Threat Intelligence Indicator on Sentinel from an OpenCTI observable.
        :param observable: OpenCTI observable to create Threat Intelligence Indicator for
        :return: Threat Intelligence Indicator if request is succesful, None otherwise
        """
        try:
            response = requests.post(
                f"{self.config.resource_url}{self.config.request_url}",
                json=self._build_request_body(observable),
                headers=self.headers,
            )
            response.raise_for_status()

            self.helper.connector_logger.info(
                f"[API] HTTP POST Request to endpoint",
                {"url_path": self.config.request_url},
            )

            return response.json()
        except requests.RequestException as err:
            self.helper.connector_logger.error(
                "[API] Error while sending data: ",
                {"url_path": f"POST {self.config.request_url}", "error": str(err)},
            )
            return None

    def patch_indicator(self, observable: dict) -> bool:
        """
        Update a Threat Intelligence Indicator on Sentinel from an OpenCTI observable.
        :param observable: OpenCTI observable to update Threat Intelligence Indicator from
        :return: True if request is succesful, False otherwise
        """
        try:
            indicator_external_id = OpenCTIConnectorHelper.get_attribute_in_extension(
                "id", observable
            )
            indicator_data = self.search_indicator(indicator_external_id)
            indicator_id = indicator_data["id"]

            response = requests.patch(
                f"{self.config.resource_url}{self.config.request_url}/{indicator_id}",
                json=self._build_request_body(observable),
                headers=self.headers,
            )
            response.raise_for_status()

            self.helper.connector_logger.info(
                f"[API] HTTP PATCH Request to endpoint",
                {"url_path": self.config.request_url},
            )

            return True
        except requests.RequestException as err:
            self.helper.connector_logger.error(
                "[API] Error while sending data: ",
                {"url_path": f"PATCH {self.config.request_url}", "error": str(err)},
            )
            return False

    def delete_indicator(self, indicator_id: str) -> bool:
        """
        Delete a Threat Intelligence Indicator on Sentinel corresponding to an OpenCTI observable.
        :param indicator_id: OpenCTI observable to delete Threat Intelligence Indicator for
        :return: True if request is succesful, False otherwise
        """
        try:
            response = requests.delete(
                f"{self.config.resource_url}{self.config.request_url}/{indicator_id}",
                headers=self.headers,
            )
            response.raise_for_status()

            self.helper.connector_logger.info(
                f"[API] HTTP DELETE Request to endpoint",
                {"url_path": f"{self.config.request_url}/{indicator_id}"},
            )

            return True
        except requests.RequestException as err:
            self.helper.connector_logger.error(
                "[API] Error while fetching data: ",
                {"url_path": f"DELETE {self.config.request_url}", "error": str(err)},
            )
            return False
