import re
import time

import requests

# The suffix to be appended to a base URL for a POST request of IOCs to S1
IOC_ENDPOINT_URL = "/web/api/v2.1/threat-intelligence/iocs/stix"

"""
SentinelOne can only accept Patterns with single elements of the types: File hashes (MD5, SHA1, SHA256),
Domain names, URLs IPv4 addresses. Such regex patterns allow the connector to thus filter for valid Indicators. More details can be found in the connector's documentation. 
"""
SUPPORTED_STIX_PATTERNS = [
    re.compile(r"^\s*\[file:hashes\.(MD5|SHA1|SHA256)\s*=\s*\'[^\']+\'\s*\]\s*$"),
    re.compile(r"^\s*\[domain-name:value\s*=\s*\'[^\']+\'\s*\]\s*$"),
    re.compile(r"^\s*\[url:value\s*=\s*\'[^\']+\'\s*\]\s*$"),
    re.compile(r"^\s*\[ipv4-addr:value\s*=\s*\'[^\']+\'\s*\]\s*$"),
]


class SentinelOneClient:
    def __init__(self, config, helper) -> None:

        self.config = config
        self.helper = helper

        self.session = requests.Session()
        headers = {
            "Authorization": f"APIToken {self.config.api_key}",
            "Content-Type": "application/json",
        }
        self.session.headers.update(headers)

    def create_indicator(self, indicator_msg: dict) -> bool:
        """
        Create an indicator in SentinelOne from a STIX indicator object

        :param indicator: STIX indicator dictionary containing pattern and metadata
        :return: None
        """

        # If the Indicator's pattern will not be accepted by the SentinelOne API
        if not self._is_valid_pattern(indicator_msg["pattern"]):
            self.helper.connector_logger.info(
                "[API] Skipping indicator with unsupported pattern"
            )
            return False

        # For a valid pattern, generate and push an Indicator payload
        payload = self._generate_indicator_payload(indicator_msg)
        return self._push_indicator_payload(payload)

    def _is_valid_pattern(self, pattern: str) -> bool:
        """
        Check if a STIX pattern is in a format that is supported
        by SentinelOne (see README for more information)

        :param pattern: STIX pattern string to validate
        :return: True if pattern is supported, False otherwise
        """
        for valid_pattern in SUPPORTED_STIX_PATTERNS:
            if valid_pattern.match(pattern):
                return True
        return False

    def _generate_indicator_payload(self, indicator: dict) -> dict:
        """
        Generate the API payload for creating an indicator in SentinelOne

        :param indicator: STIX indicator dictionary
        :return: Formatted payload dictionary for SentinelOne API
        """
        payload = {"bundle": {"objects": [indicator]}, "filter": {"tenant": "false"}}

        # Add scope filters based on the configuration combination
        if self.config.account_id is not None:
            payload["filter"]["accountIds"] = [self.config.account_id]
        if self.config.group_id is not None:
            payload["filter"]["groupIds"] = [self.config.group_id]
        if self.config.site_id is not None:
            payload["filter"]["siteIds"] = [self.config.site_id]

        return payload

    def _push_indicator_payload(self, payload: dict) -> bool:
        """
        Send an Indicator payload to SentinelOne API, with relevant
        retry logic to handle retries / back-offs from the SentinelOne
        API.

        :param payload: Formatted payload dictionary for SentinelOne API
        :return: True if successful, False otherwise
        """
        timeout = 10
        request_attempts = 3
        backoff_factor = 5

        url = self.config.api_url + IOC_ENDPOINT_URL

        for attempt in range(request_attempts):
            try:
                response = self.session.post(url, json=payload, timeout=timeout)

                if response.status_code == 200:
                    self.helper.connector_logger.debug(
                        "[API] Indicator payload successfully sent"
                    )
                    # Rate limiting prevention
                    time.sleep(0.2)
                    return True

                elif response.status_code == 429:
                    if attempt < request_attempts - 1:
                        delay = self.backoff_delay(backoff_factor, attempt + 1)
                        self.helper.connector_logger.debug(
                            f"[API] Rate limited, retrying in {delay} seconds"
                        )
                        time.sleep(delay)
                        continue
                    else:
                        self.helper.connector_logger.warning(
                            "[API] Rate limited - exhausted all retry attempts"
                        )

                response.raise_for_status()

            except requests.RequestException as e:
                self.helper.connector_logger.warning(
                    f"[API] Request failed with exception: {e}"
                )
                break

        self.helper.connector_logger.warning(
            f"[API] Failed to create Indicator: Request did not succeed after {request_attempts} retries"
        )
        return False

    @staticmethod
    def backoff_delay(backoff_factor: int, attempts: int) -> float:
        delay = backoff_factor * (2 ** (attempts - 1))
        return delay
