import json
import re
import time
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import requests
import urllib3
import validators
from connectors_sdk.connectors.stream.deployment import (
    deployment_failure_reason,
    parse_datetime,
)
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

PLATFORM_NAME = "Zscaler"
"""Name of the security platform in the deployment failure reasons."""

LIST_ACTION = "blacklist update"
"""What Zscaler is asked to do when a domain is added to or removed from the blacklist."""

ACTIVATION_ACTION = "configuration activation"
"""What Zscaler is asked to do after each change of the blacklist."""

READ_ACTION = "blacklist read"
"""What Zscaler is asked to do when the blacklist is read back."""


class ZscalerApiError(Exception):
    """Error raised when Zscaler rejects a request or cannot be reached.

    Attributes:
        status_code: The HTTP status of the Zscaler response, None when Zscaler
            could not be reached.
        action: What Zscaler was asked to do.
    """

    def __init__(
        self, message: str, status_code: int | None = None, action: str = LIST_ACTION
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.action = action


class ZscalerActivationPendingError(ZscalerApiError):
    """Error raised when a configuration activation is still not active after the checks."""


def failure_reason(error: BaseException) -> str:
    """Return the reason OpenCTI shows for a domain Zscaler did not take.

    :param error: The error raised while adding the domain to the blacklist.
    :return: One short sentence naming Zscaler and the cause; the Zscaler response is
        left to the logs.
    """
    if isinstance(error, ZscalerActivationPendingError):
        return f"{PLATFORM_NAME} did not complete the {ACTIVATION_ACTION} in time"
    if isinstance(error, ZscalerApiError):
        return deployment_failure_reason(PLATFORM_NAME, error.action, error.status_code)
    return str(error) or type(error).__name__


class SharedDomainLookupError(Exception):
    """Error raised when OpenCTI cannot tell whether another indicator blocks a domain."""


ACTIVATION_POLL_SECONDS = 5
"""Seconds between two checks of a Zscaler configuration activation in progress."""


def _category_of(response: requests.Response) -> dict[str, Any]:
    """Return the URL category of a successful Zscaler response.

    :raises ZscalerApiError: With the response status when the body is not a URL
        category, so that the shared "unexpected response" reason applies.
    """
    try:
        category = response.json()
    except ValueError as err:
        raise ZscalerApiError(
            "Unexpected URL category response: the body is not JSON",
            status_code=response.status_code,
            action=READ_ACTION,
        ) from err
    if not isinstance(category, dict) or not (
        "id" in category or "configuredName" in category
    ):
        raise ZscalerApiError(
            "Unexpected URL category response: not a URL category",
            status_code=response.status_code,
            action=READ_ACTION,
        )
    return category


def _category_urls(response: requests.Response) -> list[str]:
    """Return the URLs of the URL category of a successful Zscaler response.

    :raises ZscalerApiError: With the response status when the body is not a URL
        category or its `urls` is not a list of URL entries: a partial listing is
        never returned.
    """
    urls = _category_of(response).get("urls", [])
    if not isinstance(urls, list) or not all(
        isinstance(url, str) and url for url in urls
    ):
        raise ZscalerApiError(
            "Unexpected URL category response: 'urls' is not a list of URL entries",
            status_code=response.status_code,
            action=READ_ACTION,
        )
    return urls


def _activation_status(response) -> str | None:
    """Return the activation status (`ACTIVE`, `PENDING`, `INPROGRESS`) of a ZIA response."""
    try:
        payload = response.json()
    except ValueError:
        return None
    return payload.get("status") if isinstance(payload, dict) else None


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
        # A rejected login must not leave the expired session cookie, which would pass
        # for a new session.
        self.session.cookies.set("JSESSIONID", None)

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
        self,
        request_func,
        *args,
        reauthenticate: bool = True,
        action: str = LIST_ACTION,
        **kwargs,
    ) -> requests.Response:
        """Send a request to Zscaler: throttled requests (429) are retried after `Retry-After`,
        an expired session (401) is re-authenticated once per attempt.

        :param reauthenticate: False for the authentication request itself, whose 401 means
            rejected credentials.
        :param action: What Zscaler is asked to do, named by the errors raised.
        :return: The successful (HTTP 200) response.
        :raises ZscalerApiError: When the request failed, with the HTTP status and the Zscaler
            response, or the transport error. Once the retries are spent, the status is the
            one of the last response (429 only when Zscaler kept throttling).
        """
        max_retries = 3
        retry_delay = self.retry_delay

        for _attempt in range(max_retries):
            try:
                response = request_func(*args, **kwargs)
            except requests.RequestException as err:
                self.helper.connector_logger.error(f"Request failed: {err}")
                raise ZscalerApiError(
                    f"Zscaler request failed: {err}", action=action
                ) from err
            if response is None:
                self.helper.connector_logger.error("Request failed: no response.")
                raise ZscalerApiError("No response from Zscaler", action=action)

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
                raise ZscalerApiError(
                    "Authentication rejected by Zscaler (HTTP 401)",
                    status_code=401,
                    action=action,
                )

            if response.status_code == 401:
                msg = "Request failed with status 401 : SESSION_NOT_VALID. Re-authentication has started..."
                self.helper.connector_logger.warning(msg)
                self.authenticate_with_zscaler()
                if not self.session.cookies.get("JSESSIONID"):
                    self.helper.connector_logger.error(
                        "Re-authentication failed, aborting retry."
                    )
                    raise ZscalerApiError(
                        "Re-authentication with Zscaler failed",
                        status_code=401,
                        action=action,
                    )
                continue

            msg = f"Request failed with status {response.status_code}: {response.text}"
            self.helper.connector_logger.error(msg)
            detail = (response.text or "").strip()[:MAX_ERROR_DETAIL_LENGTH]
            raise ZscalerApiError(
                f"Request failed with status {response.status_code}: {detail}",
                status_code=response.status_code,
                action=action,
            )

        self.helper.connector_logger.error("Max retries reached. Request failed.")
        raise ZscalerApiError(
            "Max retries reached, the Zscaler request failed",
            status_code=response.status_code,
            action=action,
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
        self.helper.connector_logger.error(f"Invalid domain provided: {pattern}")
        return None

    def get_domain_classification_in_zscaler(self, domain):
        """Retrieve the classification of a domain in Zscaler via the urlLookup API.

        The classification is only logged: a failed lookup, or a reply that is not a
        list of lookup results, is logged and returns None.
        """

        lookup_url = f"{self.zscaler_base_url}/urlLookup"
        payload = json.dumps([domain])

        response = self.handle_rate_limit(self.session.post, lookup_url, data=payload)

        msg = f"=== Checking domain {domain} ==="
        self.helper.connector_logger.debug(msg)
        if response and response.status_code == 200:
            try:
                lookup_data = response.json()
            except ValueError:
                lookup_data = None
            if (
                isinstance(lookup_data, list)
                and len(lookup_data) > 0
                and isinstance(lookup_data[0], dict)
            ):
                return lookup_data[0].get("urlClassifications", [])
        self.helper.connector_logger.error(
            f"Failed to lookup domain {domain} in Zscaler."
        )
        return None

    def list_blocked_domains(self) -> list[str]:
        """Read the domains of the blacklist URL category back (deployment reconciliation).

        :raises ZscalerApiError: When the category cannot be read or its payload is unexpected:
            a partial listing is never returned.
        """
        url = f"{self.zscaler_base_url}/urlCategories/{self.zscaler_blacklist_name}"
        return _category_urls(
            self.request_zscaler(self.session.get, url, action=READ_ACTION)
        )

    def get_current_configured_name(self):
        """Return the configured name of the blacklist URL category.

        The change of the blacklist names it, so a failed read stops the change.

        :raises ZscalerApiError: When the category cannot be read or the response is
            not a URL category.
        """
        url = f"{self.zscaler_base_url}/urlCategories/{self.zscaler_blacklist_name}"
        response = self.request_zscaler(self.session.get, url, action=READ_ACTION)
        return _category_of(response).get("configuredName")

    def check_and_send_to_zscaler(self, data, event_type, indicator_ids=()):
        """Verify the classification of a domain, then add it to (create) or remove it from
        (delete) the blacklist.

        :param indicator_ids: The OpenCTI ids of the indicator (delete), never counted
            as another indicator blocking the domain.
        :return: The domain when the blacklist holds it (create) or no longer holds it
            for this indicator (delete), None for an invalid domain pattern or an
            unsupported event type.
        :raises ZscalerApiError: When Zscaler refuses the change or the blacklist cannot be read.
        :raises SharedDomainLookupError: When the other indicators of the domain cannot be read.
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
            self.withdraw_domain(domain, indicator_ids)
        else:
            self.helper.connector_logger.error("Unsupported event type.")
            return None
        return domain

    def deploy_domain(self, domain: str) -> None:
        """Add a domain to the blacklist; an already listed one gets its change activated.

        An analyst retry or a repeated create of a listed domain whose earlier
        activation timed out activates it again, so it is only reported once enforced.

        :raises ZscalerApiError: When the blacklist cannot be read, or Zscaler refuses the
            change or the activation.
        """
        if domain in self.list_blocked_domains():
            msg = f"The domain {domain} is already in the Blacklist."
            self.helper.connector_logger.info(msg)
            self.ensure_configuration_active()
            return
        msg = f"Sending domain {domain} to Zscaler..."
        self.helper.connector_logger.info(msg)
        self.send_to_zscaler(domain, "create")

    def withdraw_domain(self, domain: str, indicator_ids: Iterable[str]) -> None:
        """Remove the domain of an indicator from the blacklist, when it is listed.

        :param indicator_ids: The OpenCTI ids of the indicator.
        :raises ZscalerApiError: When the blacklist cannot be read or Zscaler refuses the change.
        :raises SharedDomainLookupError: When the other indicators of the domain cannot be read.
        """
        if domain not in self.list_blocked_domains():
            msg = f"The domain {domain} is not in the Blacklist."
            self.helper.connector_logger.info(msg)
            return
        self.remove_domain(domain, indicator_ids)

    def remove_domain(self, domain: str, indicator_ids: Iterable[str]) -> None:
        """Remove a listed domain from the blacklist, unless another indicator blocks it.

        The blacklist only holds values: a domain shared by several OpenCTI indicators
        stays listed while one of them is valid (neither revoked nor expired).

        :param indicator_ids: The OpenCTI ids of the indicator removed.
        :raises ZscalerApiError: When Zscaler refuses the change.
        :raises SharedDomainLookupError: When the other indicators of the domain cannot be read.
        """
        if self.is_blocked_by_another_indicator(domain, indicator_ids):
            msg = f"The domain {domain} stays in the Blacklist: another OpenCTI indicator blocks it."
            self.helper.connector_logger.info(msg)
            return
        self.send_to_zscaler(domain, "delete")

    def is_blocked_by_another_indicator(
        self, domain: str, indicator_ids: Iterable[str]
    ) -> bool:
        """Tell whether a valid OpenCTI indicator, other than the given one, has the
        `[domain-name:value = '<domain>']` pattern.

        Revoked indicators and indicators whose `valid_until` is past do not block the
        domain: their own removal is due as well.

        :param indicator_ids: The OpenCTI ids (internal or STIX) of the indicator removed.
        :raises SharedDomainLookupError: When OpenCTI cannot be queried.
        """
        now = datetime.now(UTC)
        # Domain names are case-insensitive: Example.COM blocks example.com too.
        canonical = domain.lower()
        excluded = {str(indicator_id).lower() for indicator_id in indicator_ids}
        try:
            indicators = self.helper.api.indicator.list(
                filters={
                    "mode": "and",
                    "filters": [
                        {
                            "key": "pattern",
                            "values": [f"'{domain}'"],
                            "operator": "contains",
                        },
                        {"key": "revoked", "values": ["false"]},
                    ],
                    "filterGroups": [],
                },
                getAll=True,
            )
        except Exception as err:
            raise SharedDomainLookupError(
                f"Cannot read the OpenCTI indicators of {domain}: {err}"
            ) from err
        return any(
            str(indicator.get("id")).lower() not in excluded
            and str(indicator.get("standard_id")).lower() not in excluded
            and (self.extract_domain(indicator.get("pattern") or "") or "").lower()
            == canonical
            and (
                (valid_until := parse_datetime(indicator.get("valid_until"))) is None
                or valid_until > now
            )
            for indicator in indicators or []
        )

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
        self.ensure_configuration_active()

    def ensure_configuration_active(self) -> None:
        """Activate the pending configuration changes, if any, and wait until they are active.

        Called after every change of the blacklist, before every read-back (a domain
        staged but not active is not enforced, so it is never confirmed) and when a
        domain to deploy is already listed (its change may still be pending).

        :raises ZscalerActivationPendingError: When the configuration is still not active.
        :raises ZscalerApiError: When Zscaler refuses the status read or the activation.
        """
        try:
            activated = self.activate_zscaler_changes()
        except ZscalerApiError:
            raise
        except Exception as err:
            raise ZscalerApiError(
                f"Zscaler configuration activation failed: {err}",
                action=ACTIVATION_ACTION,
            ) from err
        if not activated:
            raise ZscalerActivationPendingError(
                "Zscaler configuration activation failed after all retries",
                action=ACTIVATION_ACTION,
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
        `removed` once the domain is out of the blacklist or only kept for another
        indicator; nothing is reported for an invalid domain pattern.
        """
        indicator_ids = [
            indicator_id
            for indicator_id in (
                data.get("id"),
                self.helper.get_attribute_in_extension("id", data),
            )
            if indicator_id
        ]
        try:
            domain = self.check_and_send_to_zscaler(
                {"pattern": data.get("pattern")}, event_type, indicator_ids
            )
        except (ZscalerApiError, SharedDomainLookupError) as err:
            self.helper.connector_logger.error(
                f"Failed to send {event_type} event: {err}"
            )
            if event_type == "create" and self.assurance is not None:
                self.assurance.report_push_failed(data, failure_reason(err))
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
        """Activate the pending configuration changes in Zscaler and wait until they are active.

        `ACTIVE` means every change is active; `PENDING` changes are activated with
        `POST /status/activate`; an `INPROGRESS` activation is checked again until it
        completes. Both requests go through `request_zscaler` (expired session,
        throttling); a busy Zscaler (503) is asked again after a growing delay, and
        refused activations are retried with backoff by tenacity.

        :return: True once the configuration is `ACTIVE`, False when it is still not
            after `max_retries` checks.
        :raises ZscalerApiError: When Zscaler refuses the status read or the activation.
        """

        status_url = f"{self.zscaler_base_url}/status"
        activate_url = f"{self.zscaler_base_url}/status/activate"

        for attempt in range(1, max_retries + 1):
            try:
                status = _activation_status(
                    self.request_zscaler(
                        self.session.get, status_url, action=ACTIVATION_ACTION
                    )
                )
                if status == "ACTIVE":
                    self.helper.connector_logger.info(
                        "Zscaler configuration is active."
                    )
                    return True
                if status == "INPROGRESS":
                    self.helper.connector_logger.info(
                        f"Zscaler activation in progress ({attempt}/{max_retries}), "
                        f"checking again in {ACTIVATION_POLL_SECONDS}s..."
                    )
                    time.sleep(ACTIVATION_POLL_SECONDS)
                    continue

                # PENDING changes (or an unreadable status): activate them.
                resp = self.request_zscaler(
                    self.session.post, activate_url, action=ACTIVATION_ACTION
                )
            except ZscalerApiError as err:
                if err.status_code != 503:
                    raise
                self.helper.connector_logger.warning(
                    f"Activation attempt {attempt}/{max_retries} failed ({err}). "
                    f"Retrying in {delay}s..."
                )
                time.sleep(delay)
                delay *= 2
                continue
            if _activation_status(resp) == "ACTIVE":
                self.helper.connector_logger.info("Zscaler configuration activated.")
                return True
            self.helper.connector_logger.info(
                "Zscaler activation started, checking its status..."
            )
            time.sleep(ACTIVATION_POLL_SECONDS)

        self.helper.connector_logger.error(
            "Zscaler configuration still not active after all checks."
        )
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
