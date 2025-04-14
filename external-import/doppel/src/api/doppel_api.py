import requests
from tenacity import (Retrying, retry, retry_if_exception_type,
                      stop_after_attempt, wait_exponential)


def log_retry(retry_state, helper):
    helper.log_info(
        f"Retrying fetch_alerts (attempt #{retry_state.attempt_number}) "
        f"after exception: {retry_state.outcome.exception()}. "
        f"Sleeping {retry_state.next_action.sleep} seconds..."
    )


def fetch_alerts(helper, api_url, api_key, created_after, max_retries, retry_delay):
    headers = {"x-api-key": api_key, "accept": "application/json"}
    params = {"created_after": created_after}

    helper.log_info(f"Fetching alerts from Doppel API with created_after={created_after}...")

    for attempt in Retrying(
        stop=stop_after_attempt(max_retries),
        wait=wait_exponential(multiplier=1, min=retry_delay, max=60),
        retry=retry_if_exception_type(requests.RequestException),
        reraise=True,
        before_sleep=lambda retry_state: log_retry(retry_state, helper),
    ):
        with attempt:
            response = requests.get(api_url, headers=headers, params=params)

            if response.status_code == 400:
                helper.log_error("The request sent to the Doppel API is invalid. Check query parameters and payload format.")
                return []
            elif response.status_code == 401:
                helper.log_error("Authentication failed! Check your Doppel API key.")
                return []
            elif response.status_code == 403:
                helper.log_error("Access denied! Your Doppel API key does not have the required permissions.")
                return []

            response.raise_for_status()
            return response.json().get("alerts", [])
