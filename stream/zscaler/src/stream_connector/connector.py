import json
import logging
import os
import re
import time

import requests
import urllib3
import validators
import yaml
from pycti import OpenCTIApiClient, OpenCTIConnectorHelper

from stream_connector.utils import obfuscate_api_key

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ZscalerConnector:
    def __init__(self, conf_path):
        logging.info("Initializing connector...")

        # Load the config.yml file
        config_file_path = conf_path
        config = yaml.load(open(config_file_path), Loader=yaml.FullLoader)

        # Initialize OpenCTI Connector
        self.helper = OpenCTIConnectorHelper(config)

        # Load OpenCTI information from the configuration file
        opencti_url = config["opencti"]["url"]
        opencti_token = config["opencti"]["token"]
        ssl_verify = config["opencti"]["ssl_verify"]

        # Initialize the OpenCTI API client
        self.api = OpenCTIApiClient(opencti_url, opencti_token, ssl_verify=ssl_verify)

        # Load Zscaler authentication information
        self.username = os.getenv("ZSCALER_USERNAME")
        self.password = os.getenv("ZSCALER_PASSWORD")
        self.api_key = os.getenv("ZSCALER_API_KEY")

        self.zscaler_token = None
        self.zscaler_token_expiry = None
        self.session_cookie = None  # To store the JSESSIONID

        # Request rate limit handling
        self.rate_limit = 400  # Limit to 400 requests per hour
        self.retry_delay = 65  # Retry delay in seconds

    def authenticate_with_zscaler(self):
        """Authenticate with Zscaler and obtain a session token."""
        logging.info("Authenticating with Zscaler...")

        url = "https://zsapi.zscalertwo.net/api/v1/authenticatedSession"

        # Generate a timestamp in milliseconds
        timestamp = str(int(time.time() * 1000))

        # Obfuscate the API key
        obfuscated_api_key = obfuscate_api_key(self.api_key, timestamp)

        # Prepare the payload with the authentication information
        payload = {
            "username": self.username,
            "password": self.password,
            "apiKey": obfuscated_api_key,
            "timestamp": timestamp,
        }
        headers = {"Content-Type": "application/json"}

        # Send the POST request to get the token
        response = self.handle_rate_limit(
            requests.post, url, json=payload, headers=headers
        )

        logging.debug(f"Payload sent: {json.dumps(payload, indent=4)}")
        logging.debug(f"Raw response from Zscaler: {response.text}")

        if response and response.status_code == 200:
            auth_data = response.json()
            # Store the JSESSIONID cookie from the response
            self.session_cookie = response.cookies.get("JSESSIONID")
            logging.info(
                f"Authenticated successfully with Zscaler. JSESSIONID: {self.session_cookie}"
            )
        else:
            logging.error(
                f"Failed to authenticate with Zscaler: {response.status_code} - {response.text}"
            )
            self.session_cookie = None

    def handle_rate_limit(self, request_func, *args, **kwargs):
        """Handle rate limits for the Zscaler API by applying a delay if the limit is reached."""
        max_retries = 3  # Maximum number of retries
        retry_delay = self.retry_delay  # Retry delay in seconds

        for attempt in range(max_retries):
            response = request_func(*args, **kwargs)

            # If the request is successful, return it
            if response.status_code == 200:
                return response

            # If rate limit status is encountered (HTTP 429), wait and retry
            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After", retry_delay)
                logging.warning(
                    f"Rate limit exceeded. Retrying in {retry_after} seconds..."
                )
                delay = int(retry_after) if retry_after else retry_delay
                time.sleep(delay)
            else:
                # Log failure for other reasons and return None
                logging.error(
                    f"Request failed with status {response.status_code}: {response.text}"
                )
                return None

        # If all attempts fail
        logging.error(f"Max retries reached. Failed to complete the request.")
        return None

    def get_zscaler_session_cookie(self):
        """Retrieve or renew the Zscaler session by getting the JSESSIONID cookie."""
        if self.session_cookie is None:
            logging.warning("Zscaler session expired or missing. Re-authenticating...")
            self.authenticate_with_zscaler()
        return self.session_cookie

    def extract_domain(self, pattern):
        """Extract domain from the STIX pattern if it follows the format [domain-name:value = 'example.com']"""
        match = re.search(r"\[domain-name:value\s*=\s*'([^']+)'\]", pattern)
        if match:
            return match.group(1)
        return None

    def is_valid_domain(self, pattern):
        """Check if the extracted domain from the pattern is valid."""
        domain = self.extract_domain(pattern)
        if domain and validators.domain(domain):
            return domain
        else:
            logging.error(f"Invalid domain provided: {pattern}")
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

        logging.debug(f"=== Checking domain {domain} ===")
        if response and response.status_code == 200:
            lookup_data = response.json()

            if isinstance(lookup_data, list) and len(lookup_data) > 0:
                lookup_entry = lookup_data[0]
                url_classifications = lookup_entry.get("urlClassifications", [])
                return url_classifications
            else:
                logging.warning(
                    f"Unexpected or empty response for domain {domain}: {lookup_data}"
                )
        else:
            logging.error(f"Failed to lookup domain {domain} in Zscaler.")

        return None

    def get_zscaler_blocked_domains(self):
        """Retrieve the list of domains blocked in the BLACK_LIST_DYNDNS category in Zscaler."""
        session_cookie = self.get_zscaler_session_cookie()

        headers = {
            "Content-Type": "application/json",
            "Cookie": f"JSESSIONID={session_cookie}",
        }

        url = "https://zsapi.zscalertwo.net/api/v1/urlCategories/CUSTOM_07"
        response = self.handle_rate_limit(requests.get, url, headers=headers)

        if response and response.status_code == 200:
            data = response.json()
            blocked_domains = data.get("dbCategorizedUrls", [])
            return blocked_domains
        else:
            logging.error(
                f"Failed to retrieve blocked domains: {response.status_code} - {response.text}"
            )
            return []

    def check_and_send_to_zscaler(self, data, event_type):
        """Verify if a domain is already blocked and its classification before sending to Zscaler."""
        domain = self.is_valid_domain(
            data["pattern"]
        )  # Use the pattern for extracting and validating the domain
        if domain:
            classification = self.get_domain_classification_in_zscaler(domain)
            if classification:
                logging.info(f"Classification found for {domain}: {classification}")

            blocked_domains = self.get_zscaler_blocked_domains()

            if domain in blocked_domains:
                logging.info(f"The domain {domain} is already in BLACK_LIST_DYNDNS.")
            else:
                logging.info(
                    f"The domain {domain} is not blocked. Sending to Zscaler..."
                )
                self.send_to_zscaler(domain, event_type)
        else:
            logging.error(
                f"Unable to process indicator due to invalid domain pattern: {data['pattern']}"
            )

    def send_to_zscaler(self, domain, event_type):
        """Send creation or deletion events to Zscaler."""
        session_cookie = self.get_zscaler_session_cookie()

        headers = {
            "Content-Type": "application/json",
            "Cookie": f"JSESSIONID={session_cookie}",
        }

        if event_type == "create":
            base_url = "https://zsapi.zscalertwo.net/api/v1/urlCategories/CUSTOM_07?action=ADD_TO_LIST"
            payload = {
                "configuredName": "BLACK_LIST_DYNDNS",
                "dbCategorizedUrls": [domain],
            }
            response = self.handle_rate_limit(
                requests.put, base_url, headers=headers, json=payload
            )
            logging.debug(f"Response after adding {domain}: {response.text}")

        elif event_type == "delete":
            base_url = "https://zsapi.zscalertwo.net/api/v1/urlCategories/CUSTOM_07?action=REMOVE_FROM_LIST"
            payload = {"configuredName": "BLACK_LIST_DYNDNS", "urls": [domain]}
            response = self.handle_rate_limit(
                requests.put, base_url, headers=headers, json=payload
            )
            logging.debug(f"Response after removing {domain}: {response.text}")

        if response and response.status_code == 200:
            logging.info(f"Successfully sent {event_type} event to Zscaler.")
            self.activate_zscaler_changes()  # Activate changes after addition or removal
        else:
            logging.error(
                f"Failed to send {event_type} event to Zscaler: {response.text}"
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

        logging.debug(f"Response after activating changes: {response.text}")

        if response and response.status_code == 200:
            logging.info("Configuration changes activated successfully.")
        else:
            logging.error(f"Failed to activate configuration changes: {response.text}")

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
        else:
            logging.info(
                "Ignoring indicator: unsupported pattern type or indicator type."
            )

    def start(self):
        """Start listening for OpenCTI events."""
        logging.info("Starting connector and listening for OpenCTI events...")
        self.helper.listen_stream(self._process_message)


if __name__ == "__main__":
    ZscalerInstance = ZscalerConnector("config.yml")
    ZscalerInstance.start()
