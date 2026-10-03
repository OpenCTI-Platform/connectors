import json
import re
import time
from typing import TYPE_CHECKING, Any

import requests
import urllib3
import validators
from pycti import OpenCTIConnectorHelper
from stream_connector.utils import obfuscate_api_key, sanitize_payload
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

if TYPE_CHECKING:
    from connectors_sdk import DeploymentAssurance

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MAX_ERROR_DETAIL_LENGTH = 500
"""Maximum length of the Zscaler response body kept in an error message."""


class ZscalerApiError(Exception):
    """Error raised when Zscaler rejects a request or cannot be reached."""


class ZscalerConnector:
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        ssl_verify,
        zscaler_username,
        zscaler_password,
        zscaler_api_key,
        zscaler_blacklist_name,
    ):
        self.helper = helper
        self.helper.connector_logger.info("Initializing Zscaler connector...")

        self.ssl_verify = ssl_verify
        self.zscaler_username = zscaler_username
        self.zscaler_password = zscaler_password
        self.api_key = zscaler_api_key
        self.zscaler_blacklist_name = (
            zscaler_blacklist_name  # Parameter for the blacklist
        )

        self.zscaler_base_url = "https://zsapi.zscalertwo.net/api/v1"
        self.session = requests.Session()

        self.rate_limit = 400  # Limit to 400 requests per hour
        self.retry_delay = 65  # Retry delay in seconds
        # Deployment write-back (dissemination assurance), set by `main.py`
        self.assurance: "DeploymentAssurance | None" = None

    def authenticate_with_zscaler(self):
        """Authenticate with Zscaler and obtain a session token."""
        self.helper.connector_logger.info("Authenticating with Zscaler...")

        url = f"{self.zscaler_base_url}/authenticatedSession"
        timestamp = str(int(time.time() * 1000))
        obfuscated_api_key = obfuscate_api_key(self.api_key, timestamp)

        payload = {
            "username": self.zscaler_username,
            "password": self.zscaler_password,
            "apiKey": obfuscated_api_key,
            "timestamp": timestamp,
        }
        headers = {"Content-Type": "application/json"}

        try:
            response = self.request_zscaler(
                self.session.post,
                url,
                json=payload,
                headers=headers,
                reauthenticate=False,
            )
        except ZscalerApiError:
            response = None

        safe_payload = sanitize_payload(payload)
        self.helper.connector_logger.debug(
            f"Payload sent (sanitized): {json.dumps(safe_payload, indent=4)}"
        )

        if response and response.status_code == 200:
            self.helper.connector_logger.debug(
                f"Raw response from Zscaler: {response.text}"
            )
            # retrieve the JSESSIONID cookie
            if self.session.cookies.get("JSESSIONID"):
                self.helper.connector_logger.info(
                    "Authenticated successfully with Zscaler."
                )
            else:
                self.helper.connector_logger.error(
                    "Authentication succeeded but no JSESSIONID cookie found in the response."
                )
        else:
            status_code = response.status_code if response else "No response"
            text = response.text if response else "No text"
            self.helper.connector_logger.error(
                f"Failed to authenticate with Zscaler: {status_code} - {text}"
            )

    def handle_rate_limit(self, request_func, *args, **kwargs):
        """Handle rate limits for the Zscaler API by applying a delay if the limit is reached.

        :return: The response, or None when the request failed (the error is logged).
        """
        try:
            return self.request_zscaler(request_func, *args, **kwargs)
        except ZscalerApiError:
            return None

    def request_zscaler(
        self, request_func, *args, reauthenticate: bool = True, **kwargs
    ) -> requests.Response:
        """Send a request to Zscaler: throttled requests (429) are retried after `Retry-After`,
        an expired session (401) is re-authenticated once per attempt.

        :param reauthenticate: False for the authentication request itself, whose 401 means
            rejected credentials.
        :return: The successful (HTTP 200) response.
        :raises ZscalerApiError: When the request failed, with the HTTP status and the Zscaler
            response, or the transport error.
        """
        max_retries = 3
        retry_delay = self.retry_delay

        for _attempt in range(max_retries):
            try:
                response = request_func(*args, **kwargs)
            except requests.RequestException as err:
                self.helper.connector_logger.error(f"Request failed: {err}")
                raise ZscalerApiError(f"Zscaler request failed: {err}") from err
            if response is None:
                self.helper.connector_logger.error("Request failed: no response.")
                raise ZscalerApiError("No response from Zscaler")

            if response.status_code == 200:
                return response

            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After", retry_delay)
                try:
                    delay = int(retry_after)
                except (TypeError, ValueError):
                    # `Retry-After` may also be an HTTP date.
                    delay = retry_delay
                msg = f"Rate limit exceeded. Retrying in {delay} seconds..."
                self.helper.connector_logger.warning(msg)
                time.sleep(delay)
                continue

            if response.status_code == 401 and not reauthenticate:
                self.helper.connector_logger.error(
                    "Authentication rejected by Zscaler (401)."
                )
                raise ZscalerApiError("Authentication rejected by Zscaler (HTTP 401)")

            if response.status_code == 401:
                msg = "Request failed with status 401 : SESSION_NOT_VALID. Re-authentication has started..."
                self.helper.connector_logger.warning(msg)
                self.authenticate_with_zscaler()
                if not self.session.cookies.get("JSESSIONID"):
                    self.helper.connector_logger.error(
                        "Re-authentication failed, aborting retry."
                    )
                    raise ZscalerApiError("Re-authentication with Zscaler failed")
                continue

            msg = f"Request failed with status {response.status_code}: {response.text}"
            self.helper.connector_logger.error(msg)
            detail = (response.text or "").strip()[:MAX_ERROR_DETAIL_LENGTH]
            raise ZscalerApiError(
                f"Request failed with status {response.status_code}: {detail}"
            )

        self.helper.connector_logger.error("Max retries reached. Request failed.")
        raise ZscalerApiError("Max retries reached, the Zscaler request failed")

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

        lookup_url = f"{self.zscaler_base_url}/urlLookup"
        payload = json.dumps([domain])

        response = self.handle_rate_limit(self.session.post, lookup_url, data=payload)

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

        # Dynamic URL for blacklisting
        url = f"{self.zscaler_base_url}/urlCategories/{self.zscaler_blacklist_name}"
        response = self.handle_rate_limit(self.session.get, url)

        if response and response.status_code == 200:
            return response.json().get("urls", [])
        code = response.status_code if response else "No response"
        text = response.text if response else "No text"

        msg = f"Failed to retrieve blocked domains: {code} - {text}"
        self.helper.connector_logger.error(msg)
        return []

    def list_blocked_domains(self) -> list[str]:
        """Read the domains of the blacklist URL category back (deployment reconciliation).

        :raises ZscalerApiError: When the category cannot be read or its payload is unexpected:
            a partial listing is never returned.
        """
        url = f"{self.zscaler_base_url}/urlCategories/{self.zscaler_blacklist_name}"
        response = self.request_zscaler(self.session.get, url)
        try:
            category = response.json()
        except ValueError as err:
            raise ZscalerApiError(
                "Unexpected URL category response: the body is not JSON"
            ) from err
        if not isinstance(category, dict) or not (
            "id" in category or "configuredName" in category
        ):
            raise ZscalerApiError(
                "Unexpected URL category response: not a URL category"
            )
        urls = category.get("urls", [])
        if not isinstance(urls, list):
            raise ZscalerApiError(
                "Unexpected URL category response: 'urls' is not a list"
            )
        return [url for url in urls if isinstance(url, str)]

    def get_current_configured_name(self):
        url = f"{self.zscaler_base_url}/urlCategories/{self.zscaler_blacklist_name}"
        response = self.handle_rate_limit(self.session.get, url)
        if response and response.status_code == 200:
            return response.json().get("configuredName")
        return None

    def check_and_send_to_zscaler(self, data, event_type):
        """Verify the classification of a domain, then add it to (create) or remove it from
        (delete) the blacklist.

        :return: The domain when the blacklist holds it (create) or no longer holds it
            (delete), None for an invalid domain pattern or an unsupported event type.
        :raises ZscalerApiError: When Zscaler refuses the change or the blacklist cannot be read.
        """
        domain = self.is_valid_domain(data["pattern"])
        if not domain:
            msg = f"Invalid domain pattern: {data['pattern']}"
            self.helper.connector_logger.error(msg)
            return None

        classification = self.get_domain_classification_in_zscaler(domain)
        if classification:
            msg = f"Classification found for {domain}: {classification}"
            self.helper.connector_logger.info(msg)

        if event_type == "create":
            self.deploy_domain(domain)
        elif event_type == "delete":
            self.withdraw_domain(domain)
        else:
            self.helper.connector_logger.error("Unsupported event type.")
            return None
        return domain

    def deploy_domain(self, domain: str) -> None:
        """Add a domain to the blacklist, unless it is already listed.

        :raises ZscalerApiError: When Zscaler refuses the change.
        """
        if domain in self.get_zscaler_blocked_domains():
            msg = f"The domain {domain} is already in the Blacklist."
            self.helper.connector_logger.info(msg)
            return
        msg = f"Sending domain {domain} to Zscaler..."
        self.helper.connector_logger.info(msg)
        self.send_to_zscaler(domain, "create")

    def withdraw_domain(self, domain: str) -> None:
        """Remove a domain from the blacklist, when it is listed.

        :raises ZscalerApiError: When the blacklist cannot be read or Zscaler refuses the change.
        """
        if domain not in self.list_blocked_domains():
            msg = f"The domain {domain} is not in the Blacklist."
            self.helper.connector_logger.info(msg)
            return
        self.send_to_zscaler(domain, "delete")

    def send_to_zscaler(self, domain, event_type):
        """Send creation or deletion events to Zscaler, then activate the configuration.

        :raises ZscalerApiError: When Zscaler refuses the change.
        """
        real_configured_name = self.get_current_configured_name()

        if event_type == "create":
            base_url = f"{self.zscaler_base_url}/urlCategories/{self.zscaler_blacklist_name}?action=ADD_TO_LIST"
        elif event_type == "delete":
            base_url = f"{self.zscaler_base_url}/urlCategories/{self.zscaler_blacklist_name}?action=REMOVE_FROM_LIST"
        else:
            msg = "Unsupported event type."
            self.helper.connector_logger.error(msg)
            return

        payload = {
            "configuredName": real_configured_name,
            "urls": [domain],
        }

        self.request_zscaler(self.session.put, base_url, json=payload)
        msg = f"Successfully sent {event_type} for {domain}."
        self.helper.connector_logger.info(msg)
        try:
            activated = self.activate_zscaler_changes()
        except Exception as err:
            raise ZscalerApiError(
                f"Zscaler configuration activation failed: {err}"
            ) from err
        if not activated:
            raise ZscalerApiError(
                "Zscaler configuration activation failed after all retries"
            )

    def push_indicator(self, indicator: dict[str, Any]) -> None:
        """Add the domain of an OpenCTI indicator to the blacklist (reconciliation re-push).

        :param indicator: The indicator, in the stream event shape.
        :raises ValueError: When the pattern is not a valid domain-name pattern.
        :raises ZscalerApiError: When Zscaler refuses the change.
        """
        domain = self.is_valid_domain(indicator.get("pattern") or "")
        if not domain:
            raise ValueError("The pattern of the indicator is not a valid domain name")
        self.deploy_domain(domain)

    def _apply_and_report(self, data: dict[str, Any], event_type: str) -> None:
        """Apply a create or delete event and report the outcome to OpenCTI.

        A create is reported `deployed` (or `failed` with the Zscaler error), a delete
        `removed` once the domain is out of the blacklist; nothing is reported for an
        invalid domain pattern.
        """
        try:
            domain = self.check_and_send_to_zscaler(
                {"pattern": data.get("pattern")}, event_type
            )
        except ZscalerApiError as err:
            self.helper.connector_logger.error(
                f"Failed to send {event_type} event: {err}"
            )
            if event_type == "create" and self.assurance is not None:
                self.assurance.report_push_failed(data, err)
            return
        if domain is None or self.assurance is None:
            return
        if event_type == "create":
            self.assurance.report_pushed(data)
        else:
            self.assurance.report_removed(data)

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=5, min=5, max=60),
        retry=retry_if_exception_type(Exception),
        reraise=True,
    )
    def activate_zscaler_changes(self, max_retries=5, delay=30):
        """Activate configuration changes in Zscaler with retry/backoff handled by tenacity."""

        status_url = f"{self.zscaler_base_url}/status"
        activate_url = f"{self.zscaler_base_url}/status/activate"

        for attempt in range(1, max_retries + 1):
            # Check if already ACTIVE/PENDING/INPROGRESS
            status_resp = self.session.get(status_url)
            if status_resp and status_resp.status_code == 200:
                status = status_resp.json().get("status")
                if status in ("ACTIVE", "PENDING", "INPROGRESS"):
                    self.helper.connector_logger.info(
                        f"Zscaler config status = {status}, no activation needed."
                    )
                    return True

            # Try activation
            resp = self.session.post(activate_url)
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
            # Each change of the blacklist is activated by `send_to_zscaler`.
            if msg.event in ("create", "delete"):
                self._apply_and_report(data, msg.event)
        else:
            msg = "Ignoring non-STIX indicator."
            self.helper.connector_logger.info(msg)

    def start(self):
        """Start listening for OpenCTI events."""

        msg = "Starting connector and listening for OpenCTI event..."
        self.helper.connector_logger.info(msg)
        if self.assurance is not None:
            self.assurance.start()
        self.helper.listen_stream(self._process_message)
