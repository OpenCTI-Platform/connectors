import json
import re
import time

import requests
import urllib3
import validators
from pycti import OpenCTIApiClient, OpenCTIConnectorHelper
from stream_connector.utils import obfuscate_api_key, sanitize_payload

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ZscalerConnector:
    def __init__(
        self,
        config_path,
        helper: OpenCTIConnectorHelper,
        opencti_url,
        opencti_token,
        ssl_verify,
        zscaler_username,
        zscaler_password,
        zscaler_api_key,
        zscaler_blacklist_name,
    ):
        self.helper = helper
        self.helper.connector_logger.info("Initializing Zscaler connector...")

        self.opencti_url = opencti_url
        self.opencti_token = opencti_token
        self.ssl_verify = ssl_verify
        self.zscaler_username = zscaler_username
        self.zscaler_password = zscaler_password
        self.api_key = zscaler_api_key
        self.zscaler_blacklist_name = (
            zscaler_blacklist_name  # Parameter for the blacklist
        )

        self.api = OpenCTIApiClient(
            self.opencti_url, self.opencti_token, ssl_verify=self.ssl_verify
        )

        self.zscaler_token = None
        self.zscaler_token_expiry = None
        self.session_cookie = None  # To store the JSESSIONID

        self.rate_limit = 400  # Limit to 400 requests per hour
        self.retry_delay = 65  # Retry delay in seconds

    def authenticate_with_zscaler(self):
        """Authenticate with Zscaler and obtain a session token."""
        self.helper.connector_logger.info("Authenticating with Zscaler...")

        url = "https://zsapi.zscalertwo.net/api/v1/authenticatedSession"
        timestamp = str(int(time.time() * 1000))
        obfuscated_api_key = obfuscate_api_key(self.api_key, timestamp)

        payload = {
            "username": self.zscaler_username,
            "password": self.zscaler_password,
            "apiKey": obfuscated_api_key,
            "timestamp": timestamp,
        }
        headers = {"Content-Type": "application/json"}

        response = self.handle_rate_limit(
            requests.post, url, json=payload, headers=headers
        )

        # Secure logging with automatic masking of sensitive fields
        safe_payload = sanitize_payload(payload)
        self.helper.connector_logger.debug(
            f"Payload sent (sanitized): {json.dumps(safe_payload, indent=4)}"
        )

        if response:
            self.helper.connector_logger.debug(
                f"Raw response from Zscaler: {response.text}"
            )

        if response and response.status_code == 200:
            self.session_cookie = response.cookies.get("JSESSIONID")
            self.helper.connector_logger.info(
                "Authenticated successfully with Zscaler."
            )
        else:
            self.helper.connector_logger.error(
                f"Failed to authenticate with Zscaler: {response.status_code if response else 'No response'} - {response.text if response else 'No text'}"
            )
            self.session_cookie = None

    def handle_rate_limit(self, request_func, *args, **kwargs):
        """Handle rate limits for the Zscaler API by applying a delay if the limit is reached."""

        max_retries = 3
        retry_delay = self.retry_delay

        for attempt in range(max_retries):
            response = request_func(*args, **kwargs)
            if response and response.status_code == 200:
                return response
            if response and response.status_code == 429:
                retry_after = response.headers.get("Retry-After", retry_delay)
                self.helper.connector_logger.warning(
                    f"Rate limit exceeded. Retrying in {retry_after} seconds..."
                )
                time.sleep(int(retry_after))
            else:
                self.helper.connector_logger.error(
                    f"Request failed: {response.status_code if response else 'No response'} - {response.text if response else 'No text'}"
                )
                return None

        self.helper.connector_logger.error("Max retries reached. Request failed.")
        return None

    def get_zscaler_session_cookie(self):
        """Retrieve or renew the Zscaler session by getting the JSESSIONID cookie."""

        if self.session_cookie is None:
            self.helper.connector_logger.warning(
                "Zscaler session expired or missing. Re-authenticating..."
            )
            self.authenticate_with_zscaler()
        return self.session_cookie

    def extract_domain(self, pattern):
        """Extract domain from the STIX pattern if it follows the format [domain-name:value = 'example.com']"""
        match = re.search(r"\[domain-name:value\s*=\s*'([^']+)'\]", pattern)
        return match.group(1) if match else None

    def is_valid_domain(self, pattern):
        """Check if the extracted domain from the pattern is valid."""
        domain = self.extract_domain(pattern)
        if domain and validators.domain(domain):
            return domain
        self.helper.connector_logger.error(f"Invalid domain provided: {pattern}")
        return None

    def get_domain_classification_in_zscaler(self, domain):
        """Retrieve the classification of a domain in Zscaler via the urlLookup API."""
        session_cookie = self.get_zscaler_session_cookie()

        headers = {
            "Content-Type": "application/json",
            "Cookie": f"JSESSIONID={session_cookie}",
        }

        lookup_url = "https://zsapi.zscalertwo.net/api/v1/urlLookup"
        payload = json.dumps([domain])

        response = self.handle_rate_limit(
            requests.post, lookup_url, headers=headers, data=payload
        )

        self.helper.connector_logger.debug(f"=== Checking domain {domain} ===")
        if response and response.status_code == 200:
            lookup_data = response.json()
            if isinstance(lookup_data, list) and len(lookup_data) > 0:
                return lookup_data[0].get("urlClassifications", [])
        self.helper.connector_logger.error(
            f"Failed to lookup domain {domain} in Zscaler."
        )
        return None

    def get_zscaler_blocked_domains(self):
        """Retrieve the list of blocked domains in the specified Zscaler blacklist."""

        session_cookie = self.get_zscaler_session_cookie()
        headers = {
            "Content-Type": "application/json",
            "Cookie": f"JSESSIONID={session_cookie}",
        }

        # Dynamic URL for blacklisting
        url = f"https://zsapi.zscalertwo.net/api/v1/urlCategories/{self.zscaler_blacklist_name}"
        response = self.handle_rate_limit(requests.get, url, headers=headers)

        if response and response.status_code == 200:
            return response.json().get("urls", [])
        self.helper.connector_logger.error(
            f"Failed to retrieve blocked domains: {response.status_code if response else 'No code'} - {response.text if response else 'No response'}"
        )
        return []

    def get_current_configured_name(self):
        session_cookie = self.get_zscaler_session_cookie()
        headers = {
            "Content-Type": "application/json",
            "Cookie": f"JSESSIONID={session_cookie}",
        }
        url = f"https://zsapi.zscalertwo.net/api/v1/urlCategories/{self.zscaler_blacklist_name}"
        response = self.handle_rate_limit(requests.get, url, headers=headers)
        if response and response.status_code == 200:
            return response.json().get("configuredName")
        return None

    def check_and_send_to_zscaler(self, data, event_type):
        """Verify if a domain is already blocked and its classification before sending to Zscaler."""
        domain = self.is_valid_domain(data["pattern"])
        if domain:
            classification = self.get_domain_classification_in_zscaler(domain)
            if classification:
                self.helper.connector_logger.info(
                    f"Classification for {domain}: {classification}"
                )

            blocked_domains = self.get_zscaler_blocked_domains()

            if domain in blocked_domains:
                self.helper.connector_logger.info(
                    f"The domain {domain} is already blocked."
                )
            else:
                self.helper.connector_logger.info(
                    f"Sending domain {domain} to Zscaler..."
                )
                self.send_to_zscaler(domain, event_type)
        else:
            self.helper.connector_logger.error(
                f"Invalid domain pattern: {data['pattern']}"
            )

    def send_to_zscaler(self, domain, event_type):
        """Send creation or deletion events to Zscaler."""
        session_cookie = self.get_zscaler_session_cookie()
        headers = {
            "Content-Type": "application/json",
            "Cookie": f"JSESSIONID={session_cookie}",
        }

        real_configured_name = self.get_current_configured_name()

        if event_type == "create":
            base_url = f"https://zsapi.zscalertwo.net/api/v1/urlCategories/{self.zscaler_blacklist_name}?action=ADD_TO_LIST"
        elif event_type == "delete":
            base_url = f"https://zsapi.zscalertwo.net/api/v1/urlCategories/{self.zscaler_blacklist_name}?action=REMOVE_FROM_LIST"
        else:
            self.helper.connector_logger.error("Unsupported event type.")
            return

        payload = {
            "configuredName": real_configured_name,
            "urls": [domain],
        }

        response = self.handle_rate_limit(
            requests.put, base_url, headers=headers, json=payload
        )

        if response and response.status_code == 200:
            self.helper.connector_logger.info(
                f"Successfully sent {event_type} for {domain}."
            )
            self.activate_zscaler_changes()
        else:
            self.helper.connector_logger.error(
                f"Failed to send {event_type} event: {response.text if response else 'No response'}"
            )

    def activate_zscaler_changes(self):
        """Activate configuration changes in Zscaler."""
        session_cookie = self.get_zscaler_session_cookie()
        headers = {
            "Content-Type": "application/json",
            "Cookie": f"JSESSIONID={session_cookie}",
        }

        activation_url = "https://zsapi.zscalertwo.net/api/v1/status/activate"
        response = self.handle_rate_limit(
            requests.post, activation_url, headers=headers
        )

        if response and response.status_code == 200:
            self.helper.connector_logger.info("Zscaler configuration activated.")
        else:
            self.helper.connector_logger.error(
                f"Failed to activate Zscaler config: {response.text if response else 'No response'}"
            )

    def _process_message(self, msg):
        """Process messages from the OpenCTI stream."""
        data = json.loads(msg.data)["data"]

        # Only process indicators with pattern_type 'sti
        if data.get("type") == "indicator" and data.get("pattern_type") == "stix":
            structured_data = {"pattern": data.get("pattern")}
            if msg.event == "create":
                self.check_and_send_to_zscaler(structured_data, "create")
            elif msg.event == "delete":
                self.check_and_send_to_zscaler(structured_data, "delete")
        else:
            self.helper.connector_logger.info("Ignoring non-STIX indicator.")

    def start(self):
        """Start listening for OpenCTI events."""
        self.helper.connector_logger.info(
            "Starting connector and listening for OpenCTI event..."
        )
        self.helper.listen_stream(self._process_message)
