import json
import re
import time

import validators
from pycti import OpenCTIConnectorHelper
from stream_connector.client import ZscalerClient


class ZscalerConnector:
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        client: ZscalerClient,
        zscaler_blacklist_name: str,
    ):
        self.helper = helper
        self.helper.connector_logger.info("Initializing Zscaler connector...")

        self.client = client
        self.zscaler_blacklist_name = (
            zscaler_blacklist_name  # Parameter for the blacklist
        )

    def extract_domain(self, pattern):
        """Extract domain from the STIX pattern if it follows the format [domain-name:value = 'example.com']"""
        match = re.search(r"\[domain-name:value\s*=\s*'([^']+)'\]", pattern)
        return match.group(1) if match else None

    def is_valid_domain(self, pattern):
        """Check if the extracted domain from the pattern is valid."""
        domain = self.extract_domain(pattern)
        if domain and validators.domain(domain):
            return domain
        self.helper.connector_logger.warning(
            "Invalid domain provided", {"pattern": pattern}
        )
        return None

    def get_domain_classification_in_zscaler(self, domain):
        """Retrieve the classification of a domain in Zscaler via the urlLookup API."""
        self.helper.connector_logger.debug(
            "Checking domain classification", {"domain": domain}
        )
        response = self.client.request("POST", "/urlLookup", json=[domain])

        if response is not None and response.ok:
            lookup_data = response.json()
            if isinstance(lookup_data, list) and len(lookup_data) > 0:
                return lookup_data[0].get("urlClassifications", [])
        self.helper.connector_logger.warning(
            "Failed to lookup domain in Zscaler",
            {
                "domain": domain,
                "status_code": response.status_code if response is not None else None,
            },
        )
        return None

    def get_blacklist_category(self):
        """Retrieve the URL category used as blacklist, including its URLs."""
        response = self.client.request(
            "GET", f"/urlCategories/{self.zscaler_blacklist_name}"
        )
        if response is not None and response.ok:
            return response.json()

        self.helper.connector_logger.error(
            "Failed to retrieve the Zscaler blacklist category",
            {
                "category_id": self.zscaler_blacklist_name,
                "status_code": response.status_code if response is not None else None,
                "response": response.text if response is not None else None,
            },
        )
        return None

    def check_and_send_to_zscaler(self, data, event_type):
        """Verify if a domain is already blocked and its classification before sending to Zscaler."""
        domain = self.is_valid_domain(data["pattern"])
        if not domain:
            return

        classification = self.get_domain_classification_in_zscaler(domain)
        if classification:
            self.helper.connector_logger.info(
                "Classification found",
                {"domain": domain, "classification": classification},
            )

        category = self.get_blacklist_category()
        if category is None:
            return

        if domain in category.get("urls", []):
            self.helper.connector_logger.info(
                "The domain is already in the blacklist", {"domain": domain}
            )
        else:
            self.helper.connector_logger.info(
                "Sending domain to Zscaler", {"domain": domain}
            )
            self.send_to_zscaler(domain, event_type, category.get("configuredName"))

    def send_to_zscaler(self, domain, event_type, configured_name):
        """Send creation or deletion events to Zscaler."""
        if event_type == "create":
            action = "ADD_TO_LIST"
        elif event_type == "delete":
            action = "REMOVE_FROM_LIST"
        else:
            self.helper.connector_logger.warning(
                "Unsupported event type", {"event_type": event_type}
            )
            return

        response = self.client.request(
            "PUT",
            f"/urlCategories/{self.zscaler_blacklist_name}",
            params={"action": action},
            json={"configuredName": configured_name, "urls": [domain]},
        )

        if response is not None and response.ok:
            self.helper.connector_logger.info(
                "Successfully sent event to Zscaler",
                {"domain": domain, "event_type": event_type},
            )
            self.activate_zscaler_changes()
        else:
            self.helper.connector_logger.error(
                "Failed to send event to Zscaler",
                {
                    "domain": domain,
                    "event_type": event_type,
                    "status_code": (
                        response.status_code if response is not None else None
                    ),
                    "response": response.text if response is not None else None,
                },
            )

    def activate_zscaler_changes(self, max_retries=5, delay=30):
        """Activate configuration changes in Zscaler, retrying while another activation is in progress."""
        for attempt in range(1, max_retries + 1):
            # Check if already ACTIVE/PENDING/INPROGRESS
            status_resp = self.client.request("GET", "/status")
            if status_resp is not None and status_resp.ok:
                status = status_resp.json().get("status")
                if status in ("ACTIVE", "PENDING", "INPROGRESS"):
                    self.helper.connector_logger.info(
                        "No Zscaler activation needed", {"status": status}
                    )
                    return True

            # Try activation
            resp = self.client.request("POST", "/status/activate")
            if resp is not None and resp.ok:
                self.helper.connector_logger.info("Zscaler configuration activated.")
                return True
            if resp is not None and resp.status_code == 503:
                self.helper.connector_logger.warning(
                    "Zscaler activation unavailable, retrying",
                    {
                        "attempt": attempt,
                        "max_retries": max_retries,
                        "delay": delay,
                        "response": resp.text,
                    },
                )
                time.sleep(delay)
                delay *= 2
                continue

            self.helper.connector_logger.error(
                "Zscaler activation failed",
                {
                    "status_code": resp.status_code if resp is not None else None,
                    "response": resp.text if resp is not None else None,
                },
            )
            return False

        self.helper.connector_logger.error(
            "Zscaler activation failed after all retries",
            {"max_retries": max_retries},
        )
        return False

    def _process_message(self, msg):
        """Process messages from the OpenCTI stream."""
        data = json.loads(msg.data)["data"]

        # Only process indicators with pattern_type 'stix'
        if data.get("type") == "indicator" and data.get("pattern_type") == "stix":
            structured_data = {"pattern": data.get("pattern")}
            if msg.event in ("create", "delete"):
                self.check_and_send_to_zscaler(structured_data, msg.event)
        else:
            self.helper.connector_logger.info("Ignoring non-STIX indicator.")

    def start(self):
        """Start listening for OpenCTI events."""

        msg = "Starting connector and listening for OpenCTI event..."
        self.helper.connector_logger.info(msg)
        self.helper.listen_stream(self._process_message)
