import json
import time

import requests


class ConnectorClient:
    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config
        self.headers = None

        # Define headers in session and update when needed
        oauth_token = self._get_oauth_token()
        headers = {"Authorization": oauth_token}
        self.session = requests.Session()
        self.session.headers.update(headers)

    def _get_oauth_token(self) -> str:
        try:
            url = f"https://login.microsoftonline.com/{self.config.tenant_id}/oauth2/v2.0/token"
            oauth_data = {
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
                "grant_type": "client_credentials",
                "scope": "https://graph.microsoft.com/.default",
            }
            response = requests.post(url, data=oauth_data)
            response_json = json.loads(response.text)

            oauth_token = response_json["access_token"]
            return oauth_token
        except Exception as e:
            raise ValueError("[ERROR] Failed generating oauth token {" + str(e) + "}")

    def pagination_incidents(self, initial_url: str) -> list:
        """
        This method sends GET requests to the starting URL `initial_url` and uses the key ‘@odata.nextLink’ to retrieve
        subsequent incident pages, as long as there is additional data to be retrieved. The results are collected in a
        list which is then returned.

        In the event of a 429 error (rate limit reached), the method waits a certain amount of time before retrying,
        with an exponential waiting mechanism to avoid exceeding the rate limit. A maximum number of retries is defined
        to avoid infinite loops in the case of persistent errors.

        :param initial_url: The starting URL for retrieving incidents.
        :return: A list of all incidents
        """
        all_incidents = []
        next_page_url = initial_url
        max_retries = 5

        while next_page_url:
            retries = 0
            retry_delay = 30
            while retries < max_retries:
                try:
                    response = self.session.get(next_page_url)

                    if response.status_code == 429:
                        retries += 1
                        self.helper.connector_logger.debug(
                            "Rate limit hit, retrying...",
                            {
                                "max_retries": 5,
                                "current_retries": retries,
                                "delay": retry_delay,
                            },
                        )
                        time.sleep(retry_delay)
                        retry_delay *= 2
                        continue
                    response.raise_for_status()

                    data = response.json()
                    all_incidents.extend(data.get("value", []))
                    next_page_url = data.get("@odata.nextLink")
                    break

                except Exception as err:
                    self.helper.connector_logger.error(str(err))
                    break
            if retries == max_retries:
                self.helper.connector_logger.error(
                    "Max retries reached. Stopping pagination."
                )
                break

        return all_incidents

    def get_incidents(self) -> list[dict]:
        """
        Retrieve incidents along with their associated alerts from the Microsoft Sentinel API.

        This method constructs the API URL to fetch incidents created on or after a specified date.
        It handles pagination to ensure that all incidents are retrieved in case of multiple pages of results.

        :return: A list of all incidents
        """
        try:
            url = (
                f"{self.config.api_base_url}{self.config.incident_path}?$expand=alerts&$filter=createdDateTime ge "
                f"{self.config.import_start_date}"
            )
            all_incidents = self.pagination_incidents(url)
            return all_incidents
        except Exception as err:
            self.helper.connector_logger.error(str(err))
