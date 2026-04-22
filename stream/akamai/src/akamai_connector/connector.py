import ipaddress
import json
import re

import requests
from akamai.edgegrid import EdgeGridAuth


def is_ip(value: str) -> bool:
    """
    Validate whether a string is a valid IPv4 or IPv6 address.
    """
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


class AkamaiConnector:
    """
    OpenCTI STREAM connector that synchronizes IPv4 indicators
    with an Akamai Client List.
    """

    def __init__(self, config, helper):
        self.helper = helper
        self.config = config

        # Convert HttpUrl (pydantic) to string before string operations
        self.base_url = str(self.config.akamai.base_url).rstrip("/")

        # Client list ID (single list)
        self.client_list_id = self.config.akamai.client_list_id.strip()

        # Create HTTP session
        self.session = requests.Session()

        # Apply EdgeGrid authentication using secrets from config
        self.session.auth = EdgeGridAuth(
            client_token=self.config.akamai.client_token.get_secret_value(),
            client_secret=self.config.akamai.client_secret.get_secret_value(),
            access_token=self.config.akamai.access_token.get_secret_value(),
        )

        # Enable SSL verification (production-ready)
        self.session.verify = True

        # Default headers
        self.session.headers.update(
            {
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )

        self.helper.connector_logger.info(
            f"Akamai connector initialized (base_url={self.base_url})"
        )

    def run(self):
        """
        Start listening to OpenCTI live stream.
        """
        self.helper.connector_logger.info("Listening for OpenCTI stream events...")
        self.helper.listen_stream(self._process_message)

    def _extract_ip_from_pattern(self, pattern: str):
        """
        Extract IP address from STIX pattern.
        Example: [ipv4-addr:value = '1.2.3.4']
        """
        match = re.search(r"value\s*=\s*'([^']+)'", pattern)
        if not match:
            return None

        ip = match.group(1)

        if not is_ip(ip):
            return None

        return ip

    def _process_message(self, msg):
        """
        Handle OpenCTI stream message.
        """
        try:
            payload = msg.data
            if isinstance(payload, str):
                payload = json.loads(payload)

            data = payload.get("data")

            # Only process STIX indicators
            if (
                not data
                or data.get("type") != "indicator"
                or data.get("pattern_type") != "stix"
            ):
                return

            pattern = data.get("pattern")
            if not pattern:
                return

            ip = self._extract_ip_from_pattern(pattern)
            if not ip:
                return

            if msg.event == "create":
                self.helper.connector_logger.info(f"[CREATE] Adding IP: {ip}")
                self._add_ip(ip)

            elif msg.event == "delete":
                self.helper.connector_logger.info(f"[DELETE] Removing IP: {ip}")
                self._remove_ip(ip)

        except Exception as e:
            self.helper.connector_logger.error(f"Error processing message: {str(e)}")

    def _add_ip(self, ip):
        """
        Add IP to Akamai Client List.
        """
        url = f"{self.base_url}/client-list/v1/lists/{self.client_list_id}/items"

        payload = {"append": [{"value": ip}]}

        response = self.session.post(url, json=payload)
        response.raise_for_status()

        self.helper.connector_logger.info("Add success")

    def _remove_ip(self, ip):
        """
        Remove IP from Akamai Client List.
        Ignore 400 if IP does not exist (idempotent behavior).
        """
        url = f"{self.base_url}/client-list/v1/lists/{self.client_list_id}/items"

        payload = {"delete": [{"value": ip}]}

        response = self.session.post(url, json=payload)

        if response.status_code == 400:
            self.helper.connector_logger.info(
                f"IP {ip} not present in Akamai list. Ignoring."
            )
            return

        response.raise_for_status()

        self.helper.connector_logger.info("Remove success")
