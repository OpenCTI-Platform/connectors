import json
import time

import requests

from .config_variables import UrlscanConfig
from .constants import UrlscanConstants


class UrlscanClient:
    """
    Working with URLScan API
    """

    def __init__(self, helper):
        self.config = UrlscanConfig()
        self.constants = UrlscanConstants
        self.helper = helper
        # Define headers in session and update when needed
        headers = {"API-Key": self.config.api_key, "Content-Type": "application/json"}
        self.session = requests.Session()
        self.session.headers.update(headers)

    def urlscan_submission(self, entity_value: str) -> list | None:
        """
        This method allows you to submit a scan from OpenCTI to URLScan.
        Valid scope: url, hostname, domain-name

        :param entity_value: This parameter contains the value of the entity submitted.
        :return: List | None
        """
        try:
            data = {"url": entity_value, "visibility": self.config.visibility}
            response = self.session.post(
                (self.config.api_base_url + self.constants.SCAN), data=json.dumps(data)
            )
            response.raise_for_status()
            return response.json()

        except requests.exceptions.RequestException as err:
            error_text = json.loads(err.response.text)
            error_msg = "[API-SUBMISSION] Error while fetching data: "
            raise ValueError(
                error_msg,
                {
                    "reason": str(err.response.reason),
                    "status_code": int(err.response.status_code),
                    "message": error_text["message"],
                    "description": (
                        error_text["description"]
                        if "description" in error_text
                        else None
                    ),
                    "entity_value": entity_value,
                },
            )

    def check_urlscan_user_quota(self, visibility: str) -> None:
        """
        This method allows you to check the user quota available for URLScan,
        depending on the visibility in the configuration.

        :param visibility: This parameter contains the visibility in the user configuration (environment variable).
        :return: None
        """
        try:

            response = self.session.get(self.constants.USER_QUOTA)
            response.raise_for_status()

            json_response = response.json()
            rate_limits = json_response["limits"][visibility]
            self.helper.connector_logger.info(
                "[API-RATE-LIMITS] The URLScan rate limits :",
                {"visibility": visibility, "rate_limits": rate_limits},
            )

            if rate_limits["day"]["limit"] == rate_limits["day"]["used"]:
                raise ValueError(
                    "You have reached your limit of API calls per day (URLScan),"
                    " please try again in a day."
                )
            elif rate_limits["hour"]["limit"] == rate_limits["hour"]["used"]:
                raise ValueError(
                    "You have reached your limit of API calls per hour (URLScan),"
                    " please try again in a hour."
                )
            elif rate_limits["minute"]["limit"] == rate_limits["minute"]["used"]:
                raise ValueError(
                    "You have reached your limit of API calls per minute (URLScan), "
                    "please try again in a minute."
                )
            else:
                pass

        except requests.exceptions.HTTPError as http_err:

            error_response = http_err.response
            error_content = json.loads(error_response.content)
            error_msg = "[API-ERROR] Error while fetching user quota: "
            raise ValueError(
                error_msg,
                {
                    "reason": str(error_response.reason),
                    "status_code": int(error_response.status_code),
                    "title": error_content["errors"][0]["title"],
                    "description": error_content["errors"][0]["detail"],
                },
            )

        except requests.exceptions.RequestException as err:
            error_msg = "[API-RATE-LIMITS] Error while fetching user quota: "
            return self.helper.connector_logger.error(error_msg, {"error": {str(err)}})

    def urlscan_result(self, uuid: str) -> dict:
        """
        This method recovers all the data of the entity scanned by URLScan, its data may take a moment to be processed
        by URLScan, if there is a 404 return and a message "Scan is not finished yet" then we make several attempts.

        :param uuid: This parameter contains the uuid of the submitted request.
        :return: dict
        """
        try:
            max_retries = 12
            retry_delay = 10  # in second

            response = self.session.get(
                self.config.api_base_url + self.constants.RESULT + uuid
            )

            if response.status_code != 200:
                json_response = response.json()

                if (
                    response.status_code == 404
                    and json_response["message"] == "Scan is not finished yet"
                ):

                    for i in range(max_retries):
                        # error 404 -> https://urlscan.io/docs/api/ between 10s - 30s
                        time.sleep(retry_delay)
                        new_attempt = self.session.get(
                            self.config.api_base_url + self.constants.RESULT + uuid
                        )
                        if new_attempt.status_code == 200:
                            json_new_attempt = new_attempt.json()
                            if (
                                json_new_attempt["data"]["requests"][0]["response"][
                                    "dataLength"
                                ]
                                == 0
                            ):
                                raise ValueError(
                                    "[API-RESULT] The request has been submitted to URLScan, "
                                    "but the URL does not return any data."
                                )
                            return json_new_attempt

                error_msg = "[API-RESULT] Error while fetching result: "
                raise ValueError(
                    error_msg,
                    {
                        "status_code": json_response["status"],
                        "error": json_response["message"],
                        "uuid": {uuid},
                    },
                )
            else:
                result = response.json()
                if result["data"]["requests"][0]["response"]["dataLength"] == 0:
                    raise ValueError(
                        "[API-RESULT] The request has been submitted to URLScan, but the URL does not return any data."
                    )
                return result

        except requests.exceptions.RequestException as err:
            error_msg = "[API-RESULT] Error while fetching result: "
            return self.helper.connector_logger.error(
                error_msg, {"uuid": uuid, "error": {str(err)}}
            )
