import json
import re
import time

import requests
import urllib3
import validators
from pycti import OpenCTIApiClient, OpenCTIConnectorHelper
from stream_connector.utils import obfuscate_api_key, sanitize_payload
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

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

        safe_payload = sanitize_payload(payload)
        self.helper.connector_logger.debug(
            f"Payload sent (sanitized): {json.dumps(safe_payload, indent=4)}"
        )

        if response:
            self.helper.connector_logger.debug(
                f"Raw response from Zscaler: {response.text}"
            )

        if response and response.status_code == 200:
            # retrieve the JSESSIONID cookie
            self.session_cookie = response.cookies.get("JSESSIONID")

            # if not found → try an authToken in the JSON (depending on the Zscaler tenant)
            if not self.session_cookie:
                try:
                    data = response.json()
                    self.session_cookie = data.get("authToken")
                except Exception:
                    self.session_cookie = None

            if self.session_cookie:
                self.helper.connector_logger.info(
                    f"Authenticated successfully with Zscaler. Token: {self.session_cookie[:10]}..."
                )
            else:
                self.helper.connector_logger.error(
                    "Authentication succeeded but no session token found in the response."
                )
        else:
            status_code = response.status_code if response else "No response"
            text = response.text if response else "No text"
            self.helper.connector_logger.error(
                f"Failed to authenticate with Zscaler: {status_code} - {text}"
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
                msg = f"Rate limit exceeded. Retrying in {retry_after} seconds..."
                self.helper.connector_logger.warning(msg)
                time.sleep(int(retry_after))
            else:
                msg = f"Request failed with status {response.status_code}: {response.text}"
                self.helper.connector_logger.error(msg)
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

        msg = f"=== Checking domain {domain} ==="
        self.helper.connector_logger.debug(msg)
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
        code = response.status_code if response else "No response"
        text = response.text if response else "No text"

        msg = f"Failed to retrieve blocked domains: {code} - {text}"
        self.helper.connector_logger.error(msg)
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
                msg = f"Classification found for {domain}: {classification}"
                self.helper.connector_logger.info(msg)

            blocked_domains = self.get_zscaler_blocked_domains()

            if domain in blocked_domains:
                msg = f"The domain {domain} is already in the Blacklist."
                self.helper.connector_logger.info(msg)
            else:
                msg = f"Sending domain {domain} to Zscaler..."
                self.helper.connector_logger.info(msg)
                self.send_to_zscaler(domain, event_type)
        else:
            msg = f"Invalid domain pattern: {data['pattern']}"
            self.helper.connector_logger.error(msg)

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
            msg = "Unsupported event type."
            self.helper.connector_logger.error(msg)
            return

        payload = {
            "configuredName": real_configured_name,
            "urls": [domain],
        }

        response = self.handle_rate_limit(
            requests.put, base_url, headers=headers, json=payload
        )

        if response and response.status_code == 200:
            msg = f"Successfully sent {event_type} for {domain}."
            self.helper.connector_logger.info(msg)
            self.activate_zscaler_changes()
        else:
            msg = f"Failed to send {event_type} event: {response.text if response else 'No response'}"
            self.helper.connector_logger.error(msg)

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=5, min=5, max=60),
        retry=retry_if_exception_type(Exception),
        reraise=True,
    )
    def activate_zscaler_changes(self, max_retries=5, delay=30):
        """Activate configuration changes in Zscaler with retry/backoff handled by tenacity."""

        session_cookie = self.get_zscaler_session_cookie()
        headers = {
            "Content-Type": "application/json",
            "Cookie": f"JSESSIONID={session_cookie}",
        }

        status_url = "https://zsapi.zscalertwo.net/api/v1/status"
        activate_url = "https://zsapi.zscalertwo.net/api/v1/status/activate"

        for attempt in range(1, max_retries + 1):
            # Check if already ACTIVE/PENDING/INPROGRESS
            status_resp = requests.get(status_url, headers=headers)
            if status_resp and status_resp.status_code == 200:
                status = status_resp.json().get("status")
                if status in ("ACTIVE", "PENDING", "INPROGRESS"):
                    self.helper.connector_logger.info(
                        f"Zscaler config status = {status}, no activation needed."
                    )
                    return True

            # Try activation
            resp = requests.post(activate_url, headers=headers)
            if resp and resp.status_code == 200:
                self.helper.connector_logger.info("Zscaler configuration activated.")
                return True
            elif resp and resp.status_code == 503:
                try:
                    msg = resp.json().get("message", resp.text)
                except Exception:
                    msg = resp.text
                self.helper.connector_logger.warning(
                    f"Activation attempt {attempt}/{max_retries} failed (503: {msg}). Retrying in {delay}s..."
                )
                time.sleep(delay)
                delay *= 2
                continue
            else:
                self.helper.connector_logger.error(
                    f"Activation failed: {resp.text if resp else 'No response'}"
                )
                raise Exception(
                    f"Activation failed: {resp.text if resp else 'No response'}"
                )

        self.helper.connector_logger.error("Activation failed after all retries.")
        return False

    def _process_message(self, msg):
        """Process messages from the OpenCTI stream."""
        data = json.loads(msg.data)["data"]

        # Only process indicators with pattern_type 'stix'
        if data.get("type") == "indicator" and data.get("pattern_type") == "stix":
            structured_data = {"pattern": data.get("pattern")}
            if msg.event == "create":
                self.check_and_send_to_zscaler(structured_data, "create")
            elif msg.event == "delete":
                self.check_and_send_to_zscaler(structured_data, "delete")

            # Always trigger activation after processing an event
            self.activate_zscaler_changes()

        else:
            msg = "Ignoring non-STIX indicator."
            self.helper.connector_logger.info(msg)

    def start(self):
        """Start listening for OpenCTI events."""

        msg = "Starting connector and listening for OpenCTI event..."
        self.helper.connector_logger.info(msg)
        self.helper.listen_stream(self._process_message)
