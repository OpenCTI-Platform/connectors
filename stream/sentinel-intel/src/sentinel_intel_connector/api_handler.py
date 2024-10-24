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

        # Define headers in session and update when needed
        oauth_token = self._get_authorization_header()
        headers = {"Authorization": oauth_token}
        self.session = requests.Session()
        self.session.headers.update(headers)

    def _get_authorization_header(self):
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
            return oauth_token
        except Exception as e:
            raise ValueError("[ERROR] Failed generating oauth token {" + str(e) + "}")

    def _send_request(self, method: str, url: str, **kwargs) -> dict | None:
        """
        Send a request to Sentinel API.
        :param method: Request HTTP method
        :param url: Request URL
        :param kwargs: Any arguments valid for session.requests() method
        :return: Any data returned by the API
        """
        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()

            self.helper.connector_logger.info(
                f"[API] HTTP {method.upper()} Request to endpoint",
                {"url_path": url},
            )

            if response.content:
                return response.json()
        except requests.RequestException as err:
            self.helper.connector_logger.error(
                "[API] Error while requesting : ",
                {"url_path": f"{method.upper()} {url}", "error": str(err)},
            )
            return None

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
            "additionalInformation": OpenCTIConnectorHelper.get_attribute_in_extension(
                "score", observable
            )
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
        data = self._send_request(
            "get", f"{self.config.base_url}{self.config.resource_path}"
        )
        return data["value"]

    def search_indicator(self, observable_opencti_id: str) -> dict | None:
        """
        Search a Threath Intelligence Indicator on Sentinel that corresponds to an OpenCTI observable.
        :param observable_opencti_id: OpenCTI ID of the observable to get Threat Intelligence Indicator for
        :return: Threat Intelligence Indicator if request is succesful, None otherwise
        """
        params = f"$filter=externalId eq '{observable_opencti_id}'"

        data = self._send_request(
            "get", f"{self.config.base_url}{self.config.resource_path}", params=params
        )
        if len(data["value"]) == 1:
            return data["value"][0]

    def post_indicator(self, observable: dict) -> dict | None:
        """
        Create a Threat Intelligence Indicator on Sentinel from an OpenCTI observable.
        :param observable: OpenCTI observable to create Threat Intelligence Indicator for
        :return: Threat Intelligence Indicator if request is succesful, None otherwise
        """
        request_body = self._build_request_body(observable)
        if not request_body:
            return None

        data = self._send_request(
            "post",
            f"{self.config.base_url}{self.config.resource_path}",
            json=request_body,
        )
        return data

    def patch_indicator(self, observable: dict) -> bool:
        """
        Update a Threat Intelligence Indicator on Sentinel from an OpenCTI observable.
        :param observable: OpenCTI observable to update Threat Intelligence Indicator from
        :return: True if request is succesful, False otherwise
        """
        indicator_external_id = OpenCTIConnectorHelper.get_attribute_in_extension(
            "id", observable
        )
        indicator_data = self.search_indicator(indicator_external_id)
        if not indicator_data:
            return False

        indicator_id = indicator_data["id"]

        self._send_request(
            "patch",
            f"{self.config.base_url}{self.config.resource_path}/{indicator_id}",
            json=self._build_request_body(observable),
        )
        return True

    def delete_indicator(self, indicator_id: str) -> bool:
        """
        Delete a Threat Intelligence Indicator on Sentinel corresponding to an OpenCTI observable.
        :param indicator_id: OpenCTI observable to delete Threat Intelligence Indicator for
        :return: True if request is succesful, False otherwise
        """
        self._send_request(
            "delete",
            f"{self.config.base_url}{self.config.resource_path}/{indicator_id}",
        )
        return True
