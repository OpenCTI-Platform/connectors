"""HTTP client for the ArcSight ESM Service Layer REST API (cases)."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Optional

import requests
from pycti import OpenCTIConnectorHelper

if TYPE_CHECKING:
    from connector.settings import ConnectorSettings

LOGIN_PATH = "/www/core-service/rest/LoginService/login"
FIND_IDS_PATH = "/www/manager-service/rest/CaseService/findAllIds"
GET_CASE_PATH = "/www/manager-service/rest/CaseService/getResourceById"
GET_EVENTS_PATH = "/www/manager-service/rest/SecurityEventService/getSecurityEvents"


class ArcSightClient:
    """Thin client around the ArcSight ESM CaseService API."""

    REQUEST_ATTEMPTS = 3
    BACKOFF_FACTOR = 5
    TIMEOUT = 60

    def __init__(
        self, config: ConnectorSettings, helper: OpenCTIConnectorHelper
    ) -> None:
        """
        Initialize the ArcSight client.

        :param config: The connector settings.
        :param helper: The OpenCTI connector helper (used for logging).
        """
        self.helper = helper
        self.config = config.arcsight_incidents

        self._base_url = str(self.config.api_base_url).rstrip("/")
        self._token: Optional[str] = None

        self.session = requests.Session()
        self.session.verify = self.config.ssl_verify
        self.session.headers.update({"Accept": "application/json"})

    def get_cases(self) -> list:
        """Fetch ESM cases, capped at the configured maximum."""
        ids: Optional[list] = None
        token: Optional[str] = None
        for attempt in range(2):  # allow one re-authentication
            token = self._get_token(force=attempt > 0)
            if token is None:
                return []
            ids = self._find_ids(token)
            if ids is not None:
                break
            self._token = None
        if ids is None or token is None:
            return []

        cases = []
        for case_id in ids[: self.config.max_cases]:
            case = self._get_case(token, case_id)
            if case is not None:
                cases.append(case)
        return cases

    def get_case_events(self, case: dict) -> list:
        """
        Fetch the ArcSight security events referenced by a case.

        Relies on the auth token cached by :meth:`get_cases` (re-authenticating
        if needed). Returns an empty list when the case references no events.
        """
        event_ids = self._extract_event_ids(case)
        if not event_ids:
            return []
        token = self._get_token()
        if token is None:
            return []
        body = {"sev.getSecurityEvents": {"sev.authToken": token, "sev.ids": event_ids}}
        response = self._request(
            "post", GET_EVENTS_PATH, params={"alt": "json"}, json=body
        )
        if response is None:
            return []
        try:
            return self._extract_events(response.json())
        except ValueError:
            return []

    @staticmethod
    def _extract_event_ids(case: dict) -> list:
        for key in ("eventIDs", "eventIds", "events", "baseEventIds"):
            value = case.get(key)
            if isinstance(value, list):
                return [item for item in value if item not in (None, "")]
            if value not in (None, ""):
                return [value]
        return []

    @staticmethod
    def _extract_events(payload) -> list:
        if isinstance(payload, dict):
            nested = payload.get("sev.getSecurityEventsResponse", {})
            if isinstance(nested, dict):
                value = nested.get("sev.return")
                if isinstance(value, list):
                    return value
                if value is not None:
                    return [value]
        if isinstance(payload, list):
            return payload
        return []

    def _get_token(self, force: bool = False) -> Optional[str]:
        if self._token is not None and not force:
            return self._token
        params = {
            "login": self.config.username,
            "password": self.config.password.get_secret_value(),
            "alt": "json",
        }
        response = self._request("get", LOGIN_PATH, params=params)
        if response is None:
            return None
        try:
            self._token = response.json()["log.loginResponse"]["log.return"]
        except (ValueError, KeyError):
            self.helper.connector_logger.error(
                "[API] Unexpected ArcSight login response"
            )
            return None
        return self._token

    @staticmethod
    def _extract_ids(payload) -> list:
        if isinstance(payload, dict):
            nested = payload.get("cas.findAllIdsResponse", {})
            if isinstance(nested, dict):
                value = nested.get("cas.return")
                if isinstance(value, list):
                    return value
                if value is not None:
                    return [value]
        if isinstance(payload, list):
            return payload
        return []

    @staticmethod
    def _extract_case(payload):
        if isinstance(payload, dict):
            nested = payload.get("cas.getResourceByIdResponse", {})
            if isinstance(nested, dict) and isinstance(nested.get("cas.return"), dict):
                return nested["cas.return"]
            if "name" in payload or "resourceid" in payload:
                return payload
        return None

    def _find_ids(self, token: str) -> Optional[list]:
        response = self._request(
            "get", FIND_IDS_PATH, params={"authToken": token, "alt": "json"}
        )
        if response is None:
            return None
        try:
            return self._extract_ids(response.json())
        except ValueError:
            return []

    def _get_case(self, token: str, case_id) -> Optional[dict]:
        response = self._request(
            "get",
            GET_CASE_PATH,
            params={"authToken": token, "resourceId": case_id, "alt": "json"},
        )
        if response is None:
            return None
        try:
            return self._extract_case(response.json())
        except ValueError:
            return None

    def _request(self, method: str, path: str, **kwargs) -> Optional[requests.Response]:
        """
        Perform an HTTP request with retry/backoff.

        Connection/timeout errors, rate limiting (429) and server-side errors
        (5xx) are retried; other 4xx responses (e.g. 401/403/404) fail fast
        without retrying. Failing fast on 401 also lets the caller re-issue the
        auth token immediately instead of after three backoff sleeps.

        Errors are logged with the path and the exception type/status code only -
        never ``str(err)`` - because the login request carries the ArcSight
        password as a query parameter and a ``requests`` exception string usually
        embeds the full request URL, which would leak the credentials (and auth
        token) into the logs.
        """
        url = f"{self._base_url}{path}"
        for attempt in range(self.REQUEST_ATTEMPTS):
            last_attempt = attempt == self.REQUEST_ATTEMPTS - 1
            try:
                response = self.session.request(
                    method, url, timeout=self.TIMEOUT, **kwargs
                )
            except requests.RequestException as err:
                self.helper.connector_logger.warning(
                    "[API] ArcSight request failed",
                    meta={"path": path, "error_type": type(err).__name__},
                )
                if last_attempt:
                    return None
                time.sleep(self.BACKOFF_FACTOR * (2**attempt))
                continue

            if response.status_code == 429 or response.status_code >= 500:
                status_code = response.status_code
                # Release the connection back to the Session pool: the body is
                # never consumed on this retry/error path.
                response.close()
                if last_attempt:
                    self.helper.connector_logger.warning(
                        "[API] ArcSight request failed",
                        meta={"path": path, "status_code": status_code},
                    )
                    return None
                time.sleep(self.BACKOFF_FACTOR * (2**attempt))
                continue

            try:
                response.raise_for_status()
            except requests.HTTPError as err:
                self.helper.connector_logger.warning(
                    "[API] ArcSight request failed",
                    meta={
                        "path": path,
                        "status_code": response.status_code,
                        "error_type": type(err).__name__,
                    },
                )
                response.close()
                return None
            return response
        return None
