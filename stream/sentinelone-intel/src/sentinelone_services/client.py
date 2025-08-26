import requests
import time
import re
import json
import logging

#The suffix to be appended to a base URL for a POST request of IOCs to S1
IOC_ENDPOINT_URL = "/web/api/v2.1/threat-intelligence/iocs/stix"


#Regex for S1 patterns
SUPPORTED_STIX_PATTERNS = [
    re.compile(r'^\s*\[file:hashes\.(MD5|SHA1|SHA256)\s*=\s*\'[^\']+\'\s*\]\s*$'),
    re.compile(r'^\s*\[domain-name:value\s*=\s*\'[^\']+\'\s*\]\s*$'),
    re.compile(r'^\s*\[url:value\s*=\s*\'[^\']+\'\s*\]\s*$'),
    re.compile(r'^\s*\[ipv4-addr:value\s*=\s*\'[^\']+\'\s*\]\s*$')
]



class SentinelOneClient:
    def __init__(self, config, helper):

        self.config = config
        self.helper = helper

        self.session = requests.Session()
        headers = {
            "Authorization": f"APIToken {self.config.api_key}",
            "Content-Type": "application/json"
        }
        self.session.headers.update(headers)



    def create_indicator(self, indicator: dict) -> None:
        """

        """
        if not self._is_valid_pattern(indicator["pattern"]):    
            return

        payload = self._generate_indicator_payload(indicator)
        self._push_indicator_payload(payload)

    def _is_valid_pattern(self, pattern: str) -> bool:
        """
        """       
        for compiled_pattern in SUPPORTED_STIX_PATTERNS:
            if compiled_pattern.match(pattern):
                self.helper.connector_logger.debug(f"Accepting valid pattern: {pattern}")
                return True
        
        self.helper.connector_logger.info(f"Rejecting unsupported pattern: {pattern}")
        return False


    def _generate_indicator_payload(self, indicator: dict) -> dict:
        """
        """
        payload = {
            "bundle": {
                "objects": [indicator]
            },
            "filter": {
                "tenant": "false"
            }
        }
        
        # Add scope filters if configured
        if self.config.account_id is not None:
            payload["filter"]["accountIds"] = [self.config.account_id]
        if self.config.group_id is not None:
            payload["filter"]["groupIds"] = [self.config.group_id]
        if self.config.site_id is not None:
            payload["filter"]["siteIds"] = [self.config.site_ids]

        return payload



    def _push_indicator_payload(self, payload: dict) -> bool:
        """

        """
        timeout = 5
        request_attempts = 3
        backoff_factor = 5
        url = self.config.api_url + IOC_ENDPOINT_URL

        for attempt in range(request_attempts):
            try:
                response = self.session.post(url, json=payload, timeout=timeout)
                
                if response.status_code == 200:
                    self.helper.connector_logger.info("Successfully sent indicator to SentinelOne")
                    # Rate limiting prevention
                    time.sleep(0.5)
                    return True
                
                elif response.status_code == 429:
                    if attempt < request_attempts - 1: 
                        delay = self.backoff_delay(backoff_factor, attempt + 1)
                        self.helper.connector_logger.warning(f"Rate limited, retrying in {delay} seconds")
                        time.sleep(delay)
                        continue

                response.raise_for_status()

            except requests.RequestException as e:
                self.helper.connector_logger.error(f"Request failed: {e}")
        
        self.helper.connector_logger.error("Failed to send indicator after all retries")
        return False


    @staticmethod
    def backoff_delay(backoff_factor: float, attempts: int) -> float:
        delay = backoff_factor * (2 ** (attempts - 1))
        return delay