import json
import re
import requests
import ipaddress
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

    def __init__(
        self,
        helper,
        base_url: str,
        client_token: str,
        client_secret: str,
        access_token: str,
        client_list_id: str,
    ):
        """
        Initialize Akamai API session with EdgeGrid authentication.
        """

        self.helper = helper
        self.base_url = base_url.rstrip("/")
        self.client_list_id = client_list_id.strip()

        # Create persistent HTTP session
        self.session = requests.Session()

        # Apply EdgeGrid authentication
        self.session.auth = EdgeGridAuth(
            client_token=client_token,
            client_secret=client_secret,
            access_token=access_token,
        )

        # Enable/Disable SSL verification
        self.session.verify = True

        # Default headers for API calls
        self.session.headers.update(
            {
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )

        self.helper.connector_logger.info(
            f"Akamai connector initialized (SSL enabled)"
        )

    def start(self):
        """
        Start listening to OpenCTI live stream.
        """
        self.helper.connector_logger.info(
            "Listening for OpenCTI stream events..."
        )
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
            payload = json.loads(msg.data)
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
                self.helper.connector_logger.info(
                    f"Adding IP: {ip}"
                )
                self._add_ip(ip)

            elif msg.event == "delete":
                self.helper.connector_logger.info(
                    f"Removing IP: {ip}"
                )
                self._remove_ip(ip)

        except Exception as e:
            self.helper.connector_logger.error(
                f"Error processing message: {str(e)}"
            )

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