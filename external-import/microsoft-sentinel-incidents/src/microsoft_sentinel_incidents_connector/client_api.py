import json
from datetime import datetime, timezone

import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectionError, HTTPError, RetryError, Timeout
from urllib3.util.retry import Retry


class ConnectorClient:
    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config

        self.log_analytics_url = "https://api.loganalytics.azure.com/v1"
        self.session = requests.Session()

    def set_oauth_token(self):
        try:
            url = f"https://login.microsoftonline.com/{self.config.tenant_id}/oauth2/v2.0/token"
            oauth_data = {
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
                "grant_type": "client_credentials",
                "scope": "https://api.loganalytics.io/.default",
            }
            response = requests.post(url, data=oauth_data)
            response_json = json.loads(response.text)

            oauth_token = response_json["access_token"]

            self.session.headers.update({"Authorization": "Bearer " + oauth_token})
        except Exception as e:
            raise ValueError("[ERROR] Failed generating oauth token {" + str(e) + "}")

    def retries_builder(self) -> None:
        """
        Configures the session's retry strategy for API requests.

        Sets up the session to retry requests upon encountering specific HTTP status codes (429) using
        exponential backoff. The retry mechanism will be applied for both HTTP and HTTPS requests.
        This function uses the `Retry` and `HTTPAdapter` classes from the `requests.adapters` module.

        - Retries up to 5 times with an increasing delay between attempts.
        """
        retry_strategy = Retry(
            total=5, backoff_factor=2, status_forcelist=[429], raise_on_status=True
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)

    def pagination_incidents(self, date_str: str) -> list[dict]:
        """
        Retrieves all incidents from the API with pagination.

        Iteratively fetches incidents from the initial URL, following pagination links until all incidents have been
        collected. If any request results in an error (retry error, HTTP error, timeout, or connection error), it will
        log the issue and halt further pagination.

        :param initial_url: The initial URL for retrieving incidents.
        :return: A list of all incidents as dictionaries containing mixed data types.
        """
        all_incidents = []
        next_page_url = (
            self.log_analytics_url
            + "/workspaces/"
            + self.config.workspace_id
            + "/query"
        )
        body = {
            "query": "SecurityIncident | sort by LastModifiedTime asc | where LastModifiedTime > todatetime('"
            + date_str
            + "')"
        }
        while next_page_url:
            try:
                response = self.session.post(url=next_page_url, json=body)
                response.raise_for_status()
                data = response.json()
                if len(data["tables"]) == 0:
                    break
                columns = data["tables"][0]["columns"]
                rows = data["tables"][0]["rows"]
                for row in rows:
                    incident = {}
                    for idx, row_column in enumerate(row):
                        incident[columns[idx]["name"]] = row_column
                    all_incidents.append(incident)
                next_page_url = data.get("nextLink")
                if next_page_url:
                    continue
                else:
                    break
            except RetryError as err:
                self.helper.connector_logger.error(
                    "A retry error occurred during incident recovery, maximum retries exceeded for url",
                    {"url": next_page_url, "retry_error": str(err)},
                )
                break
            except HTTPError as err:
                self.helper.connector_logger.error(
                    "A http error occurred during incident recovery",
                    {"url": next_page_url, "http_error": str(err)},
                )
                break
            except Timeout as err:
                self.helper.connector_logger.error(
                    "A timeout error has occurred during incident recovery",
                    {"url": next_page_url, "timeout_error": str(err)},
                )
                break
            except ConnectionError as err:
                self.helper.connector_logger.error(
                    "A connection error occurred during incident recovery",
                    {"url": next_page_url, "connection_error": str(err)},
                )
                break
            except Exception as err:
                self.helper.connector_logger.error(
                    "An unexpected error occurred during the recovery of all incidents",
                    {"url": next_page_url, "error": str(err)},
                )
                break
        return all_incidents

    def get_incidents(self, last_incident_timestamp: int) -> list[dict]:
        """
        Retrieves incidents and manages the API request lifecycle.

        Initializes the retry configuration, builds the API query URL, and retrieves all incidents using pagination.
        Logs any unexpected errors encountered during the retrieval process.

        :return: A list of all incidents as dictionaries containing mixed data types.
        """
        try:
            self.retries_builder()
            convert_date_str = (
                datetime.fromtimestamp(last_incident_timestamp, tz=timezone.utc)
                .isoformat()
                .replace("+00:00", "Z")
            )
            all_incidents = self.pagination_incidents(convert_date_str)
            return all_incidents

        except Exception as err:
            self.helper.connector_logger.error(
                "An unknown error occurred during the recovery of all incidents",
                {"error": str(err)},
            )

    def pagination_alerts(self, date_str: str, alert_ids: str) -> list[dict]:
        """
        Retrieves all alerts from the API with pagination.

        Iteratively fetches alerts from the initial URL, following pagination links until all alerts have been
        collected. If any request results in an error (retry error, HTTP error, timeout, or connection error), it will
        log the issue and halt further pagination.

        :param initial_url: The initial URL for retrieving alerts.
        :return: A list of all alerts as dictionaries containing mixed data types.
        """
        all_alerts = []
        next_page_url = (
            self.log_analytics_url
            + "/workspaces/"
            + self.config.workspace_id
            + "/query"
        )
        body = {
            "query": "SecurityAlert | summarize arg_max(TimeGenerated, *) by SystemAlertId | where TimeGenerated > todatetime('"
            + date_str
            + "') and SystemAlertId in("
            + alert_ids.replace("[", "").replace("]", "")
            + ")"
        }
        while next_page_url:
            try:
                response = self.session.post(url=next_page_url, json=body)
                response.raise_for_status()
                data = response.json()
                if len(data["tables"]) == 0:
                    break
                columns = data["tables"][0]["columns"]
                rows = data["tables"][0]["rows"]
                for row in rows:
                    alert = {}
                    for idx, row_column in enumerate(row):
                        alert[columns[idx]["name"]] = row_column
                    all_alerts.append(alert)
                next_page_url = data.get("nextLink")
                if next_page_url:
                    continue
                else:
                    break

            except RetryError as err:
                self.helper.connector_logger.error(
                    "A retry error occurred during alerts recovery, maximum retries exceeded for url",
                    {"url": next_page_url, "retry_error": str(err)},
                )
                break
            except HTTPError as err:
                self.helper.connector_logger.error(
                    "A http error occurred during alerts recovery",
                    {"url": next_page_url, "http_error": str(err)},
                )
                break
            except Timeout as err:
                self.helper.connector_logger.error(
                    "A timeout error has occurred during alerts recovery",
                    {"url": next_page_url, "timeout_error": str(err)},
                )
                break
            except ConnectionError as err:
                self.helper.connector_logger.error(
                    "A connection error occurred during alerts recovery",
                    {"url": next_page_url, "connection_error": str(err)},
                )
                break
            except Exception as err:
                self.helper.connector_logger.error(
                    "An unexpected error occurred during the recovery of all alerts",
                    {"url": next_page_url, "error": str(err)},
                )
                break
        return all_alerts

    def get_alerts(self, last_incident_timestamp: int, alert_ids: str) -> list[dict]:
        """
        Retrieves alerts and manages the API request lifecycle.

        Initializes the retry configuration, builds the API query URL, and retrieves all incidents using pagination.
        Logs any unexpected errors encountered during the retrieval process.

        :return: A list of all alerts as dictionaries containing mixed data types.
        """
        if alert_ids == "[]":
            return []
        try:
            self.retries_builder()
            convert_date_str = (
                datetime.fromtimestamp(last_incident_timestamp, tz=timezone.utc)
                .isoformat()
                .replace("+00:00", "Z")
            )
            all_alerts = self.pagination_alerts(convert_date_str, alert_ids)
            return all_alerts

        except Exception as err:
            self.helper.connector_logger.error(
                "An unknown error occurred during the recovery of all alerts",
                {"error": str(err)},
            )
