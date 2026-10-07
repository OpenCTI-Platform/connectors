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


def is_asn(value: str) -> bool:
    """
    Validate whether a value is a valid 32-bit ASN.
    """
    try:
        asn = int(value)

        return 0 <= asn <= 4294967295

    except (TypeError, ValueError):
        return False


class AkamaiConnector:
    """
    OpenCTI STREAM connector that synchronizes
    IP and ASN indicators with dedicated
    Akamai Client Lists.
    """

    def __init__(
        self,
        config,
        helper,
    ):
        self.helper = helper
        self.config = config

        # Convert Pydantic HttpUrl to string.
        self.base_url = str(self.config.akamai.base_url).rstrip("/")

        # Akamai Client List for IP.
        self.client_list_id = self.config.akamai.client_list_id.strip()

        # Akamai Client List for ASN.
        self.asn_client_list_id = self.config.akamai.asn_client_list_id.strip()

        # Create HTTP session.
        self.session = requests.Session()

        # Configure Akamai EdgeGrid authentication.
        self.session.auth = EdgeGridAuth(
            client_token=(self.config.akamai.client_token.get_secret_value()),
            client_secret=(self.config.akamai.client_secret.get_secret_value()),
            access_token=(self.config.akamai.access_token.get_secret_value()),
        )

        # Enable SSL certificate verification.
        self.session.verify = True

        # Default HTTP headers.
        self.session.headers.update(
            {
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )

        self.helper.connector_logger.info(
            f"Akamai connector initialized " f"(base_url={self.base_url})"
        )

    def run(self):
        """
        Start listening to OpenCTI live stream.
        """

        self.helper.connector_logger.info("Listening for OpenCTI stream events...")

        self.helper.listen_stream(self._process_message)

    def _extract_ip_from_pattern(
        self,
        pattern: str,
    ):
        """
        Extract IP address from STIX pattern.

        Example:
        [ipv4-addr:value = '1.2.3.4']
        """

        match = re.search(
            r"value\s*=\s*'([^']+)'",
            pattern,
        )

        if not match:
            return None

        ip = match.group(1)

        if not is_ip(ip):
            return None

        return ip

    def _extract_asn_from_pattern(
        self,
        pattern: str,
    ):
        """
        Extract ASN from STIX pattern.

        Supported examples:

        [autonomous-system:number = 64512]

        [autonomous-system:number = '64512']

        [autonomous-system:number = 'AS200651']

        The optional AS prefix is removed before
        sending the ASN to Akamai.
        """

        match = re.search(
            r"autonomous-system:number\s*=\s*'?(?:AS)?([0-9]+)'?",
            pattern,
            re.IGNORECASE,
        )

        if not match:
            return None

        # Only retrieve the numeric ASN.
        #
        # Example:
        # AS200651 -> 200651
        asn = match.group(1)

        if not is_asn(asn):
            return None

        return asn

    def _process_message(
        self,
        msg,
    ):
        """
        Handle OpenCTI stream message.
        """

        try:
            payload = msg.data

            if isinstance(
                payload,
                str,
            ):
                payload = json.loads(payload)

            data = payload.get("data")

            # Only process STIX indicators.
            if (
                not data
                or data.get("type") != "indicator"
                or data.get("pattern_type") != "stix"
            ):
                return

            pattern = data.get("pattern")

            if not pattern:
                return

            # Try IP extraction.
            ip = self._extract_ip_from_pattern(pattern)

            # Try ASN extraction.
            asn = self._extract_asn_from_pattern(pattern)

            # -------------------------
            # IP
            # -------------------------

            if ip:

                if msg.event == "create":

                    self.helper.connector_logger.info(f"[CREATE] Adding IP: {ip}")

                    self._add_ip(ip)

                elif msg.event == "delete":

                    self.helper.connector_logger.info(f"[DELETE] Removing IP: {ip}")

                    self._remove_ip(ip)

            # -------------------------
            # ASN
            # -------------------------

            elif asn:

                if msg.event == "create":

                    self.helper.connector_logger.info(f"[CREATE] Adding ASN: {asn}")

                    self._add_asn(asn)

                elif msg.event == "delete":

                    self.helper.connector_logger.info(f"[DELETE] Removing ASN: {asn}")

                    self._remove_asn(asn)

        except Exception as e:

            self.helper.connector_logger.error(f"Error processing message: {str(e)}")

    def _add_ip(
        self,
        ip,
    ):
        """
        Add IP to Akamai IP Client List.
        """

        url = (
            f"{self.base_url}"
            f"/client-list/v1/lists/"
            f"{self.client_list_id}"
            f"/items"
        )

        payload = {"append": [{"value": ip}]}

        response = self.session.post(
            url,
            json=payload,
        )

        response.raise_for_status()

        self.helper.connector_logger.info("Add IP success")

    def _remove_ip(
        self,
        ip,
    ):
        """
        Remove IP from Akamai IP Client List.

        Ignore HTTP 400 if the IP does not exist.
        """

        url = (
            f"{self.base_url}"
            f"/client-list/v1/lists/"
            f"{self.client_list_id}"
            f"/items"
        )

        payload = {"delete": [{"value": ip}]}

        response = self.session.post(
            url,
            json=payload,
        )

        if response.status_code == 400:

            self.helper.connector_logger.info(
                f"IP {ip} not present " "in Akamai list. Ignoring."
            )

            return

        response.raise_for_status()

        self.helper.connector_logger.info("Remove IP success")

    def _add_asn(
        self,
        asn,
    ):
        """
        Add ASN to Akamai ASN Client List.
        """

        url = (
            f"{self.base_url}"
            f"/client-list/v1/lists/"
            f"{self.asn_client_list_id}"
            f"/items"
        )

        payload = {"append": [{"value": asn}]}

        response = self.session.post(
            url,
            json=payload,
        )

        response.raise_for_status()

        self.helper.connector_logger.info("Add ASN success")

    def _remove_asn(
        self,
        asn,
    ):
        """
        Remove ASN from Akamai ASN Client List.

        Ignore HTTP 400 if the ASN does not exist.
        """

        url = (
            f"{self.base_url}"
            f"/client-list/v1/lists/"
            f"{self.asn_client_list_id}"
            f"/items"
        )

        payload = {"delete": [{"value": asn}]}

        response = self.session.post(
            url,
            json=payload,
        )

        if response.status_code == 400:

            self.helper.connector_logger.info(
                f"ASN {asn} not present " "in Akamai list. Ignoring."
            )

            return

        response.raise_for_status()

        self.helper.connector_logger.info("Remove ASN success")
