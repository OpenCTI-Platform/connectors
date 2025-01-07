import time

import requests
from pycti import get_config_variable

INCIDENTS_API_LOCATION = "web/api/v2.1/private/threat-groups?limit=50&sortBy=createdAt&sortOrder=desc&accountIds="
INCIDENT_NOTES_API_LOCATION_TEMPLATE = "web/api/v2.1/threats/{incident_id}/notes"
INCIDENT_API_LOCATION_TEMPLATE = "web/api/v2.1/private/threats/{incident_id}/analysis"


class S1Client:
    def __init__(self, config, helper):

        self.helper = helper

        self.url = get_config_variable(
            "SENTINELONE_URL", ["sentinelOne", "url"], config
        )
        self.api_key = "APIToken " + get_config_variable(
            "SENTINELONE_API_KEY", ["sentinelOne", "api_key"], config
        )
        self.account_id = get_config_variable(
            "SENTINELONE_ACCOUNT_ID", ["sentinelOne", "account_id"], config
        )
        self.max_calls = int(
            get_config_variable(
                "SENTINELONE_MAX_API_ATTEMPTS", ["sentinelOne", "max_calls"], config
            )
        )

    def get_request(self, url, data={}, wait_time=1, attempts=0):
        def calculate_exponential_delay(last_wait_time):
            """
            Returns a delay between API Requests ('exponential' required by S1)
            very basic for now.
            """
            return last_wait_time * 2

        HEADERS = {"Accept": "application/json", "Authorization": self.api_key}
        response = requests.request("GET", url, headers=HEADERS, data=data, timeout=30)
        if response.status_code == 429:
            if attempts < self.max_calls:
                new_wait_time = calculate_exponential_delay(wait_time)
                self.helper.log_debug(
                    f"Rate limit hit. Retrying in {new_wait_time} seconds..."
                )
                time.sleep(new_wait_time)
                return self.get_request(url, data, new_wait_time, attempts + 1)
            else:
                self.helper.log_error("Error, request to S1 API exceeded max attempts.")
                return None

        elif response.status_code != 200:
            self.helper.log_error(
                f"Error, Request got Response: {response.status_code}"
            )
            self.helper.log_debug(f"URL Used: {url}")
            self.helper.log_debug(f"Headers Used: {HEADERS}")
            self.helper.log_debug(f"S1 responded with: {response.text}")
            return None

        return response.json().get("data", None)

    def fetch_incidents(self):
        url = self.url + INCIDENTS_API_LOCATION + self.account_id
        incidents = self.get_request(url)
        if type(incidents) is str:
            return incidents
        return [inc.get("threatInfo", {}).get("threatId") for inc in incidents]

    def retreive_incident(self, incident_id):
        url = self.url + INCIDENT_API_LOCATION_TEMPLATE.format(incident_id=incident_id)
        return self.get_request(url)

    def retreive_incident_notes(self, incident_id):
        url = self.url + INCIDENT_NOTES_API_LOCATION_TEMPLATE.format(
            incident_id=incident_id
        )
        return self.get_request(url)
