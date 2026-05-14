"""
Microsoft Defender for Endpoint Indicator Sync API

Documentation: https://learn.microsoft.com/en-us/defender-endpoint/api/ti-indicator
"""

from datetime import datetime, timedelta, timezone
from time import perf_counter
from typing import Any, Final, Mapping

import requests
from pycti import OpenCTIConnectorHelper
from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectionError as requestsConnectionError
from requests.exceptions import (
    HTTPError,
    RetryError,
    Timeout,
)
from urllib3.util.retry import Retry

from .rbac_scope import (
    RbacConfigError,
    fetch_rbac_name_id_map,
    resolve_rbac_scope_or_abort,
)
from .types import RBACScope
from .utils import (
    CREATABLE_INDICATOR_TYPES,
    IOC_TYPES,
    get_action,
    get_description,
    get_educate_url,
    get_expiration_datetime,
    get_expire_days,
    get_recommended_actions,
    get_severity,
    indicator_title,
    indicator_value,
)

DEFAULT_TIMEOUT: Final = (10, 180)  # connect, read


class DefenderApiHandlerError(Exception):
    def __init__(self, message: str, metadata: Mapping[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.metadata: Mapping[str, Any] = metadata or {}

    @property
    def msg(self):
        return self.message

    def __str__(self) -> str:
        status = (self.metadata or {}).get("details", {}).get("status")
        return f"{self.message} (status={status})" if status else self.message


class DefenderApiHandler:
    def __init__(self, helper: OpenCTIConnectorHelper, config: Any):
        """
        Init Defender Intel API handler.
        :param helper: PyCTI helper instance
        :param config: Connector config variables
        """
        self.helper = helper
        self.config = config

        # RBAC scope for the current run (pair of arrays or None).
        # Set from connector.run() when scoping is enabled.
        self._rbac_scope: RBACScope | None = None

        # Define headers in session and update when needed
        self.session = requests.Session()
        self.retries_builder()
        self._expiration_token_date = None
        # Set content type
        self.session.headers.update(
            {
                "User-Agent": "OpenCTI-DefenderIntelSync/1.0",
                "Accept": "application/json",
            }
        )

        # Clean URLs
        self.login_url = (
            self.config.login_url or "https://login.microsoftonline.com/"
        ).rstrip("/")
        self.base_url = (self.config.base_url or "").rstrip("/")
        self.resource_path = "/" + (self.config.resource_path or "").lstrip("/")

    # Exposed so the orchestrator (connector.run) can set per-run scope once.
    def set_rbac_scope(self, rbac_scope: RBACScope | None) -> None:
        """
        Set the RBAC scope for this sync run.
        When not None, both rbacGroupNames and rbacGroupIds will be emitted on every write.
        When None, tenant-wide is implied and no RBAC fields are sent.
        """
        self._rbac_scope = rbac_scope

    def _get_authorization_header(self):
        """
        Get an OAuth access token and set it as Authorization header in headers.
        """
        response_json = {}
        try:
            url = f"{self.login_url}/{self.config.tenant_id}/oauth2/v2.0/token"
            body = {
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
                "grant_type": "client_credentials",
                "scope": self.base_url + "/.default",
            }
            response = self.session.post(url, data=body, timeout=DEFAULT_TIMEOUT)
            try:
                response_json = response.json()
            except ValueError:
                response_json = {}
            response.raise_for_status()

            oauth_token = response_json["access_token"]
            oauth_expired = float(response_json["expires_in"])  # time in seconds
            self.session.headers.update({"Authorization": "Bearer " + oauth_token})
            now = datetime.now(timezone.utc)
            self._expiration_token_date = now + timedelta(
                seconds=int(oauth_expired * 0.9)
            )
        except (requests.exceptions.RequestException, KeyError) as e:
            error_description = response_json.get("error_description", "Unknown error")
            error_message = f"Failed generating oauth token: {error_description}"
            meta: dict[str, Any] = {"response": response_json}
            if isinstance(e, requests.exceptions.HTTPError) and e.response is not None:
                try:
                    meta["details"] = {
                        "status": e.response.status_code,
                        "body": e.response.text[:500],
                    }
                except (AttributeError, TypeError, UnicodeDecodeError) as parse_error:
                    # Best-effort enrichment of error metadata; if we cannot read
                    # the response details we still want to raise the original error.
                    self.helper.connector_logger.debug(
                        "Failed to parse error response details: %s", parse_error
                    )
            self.helper.connector_logger.error(error_message, meta)
            raise DefenderApiHandlerError(error_message, meta) from e

    def retries_builder(self) -> None:
        """
        Configures the session's retry strategy for API requests.

        Sets up the session to retry requests upon encountering specific HTTP status codes (429, 502, 503, 504) using
        exponential backoff. The retry mechanism will be applied for both HTTP and HTTPS requests.
        """
        retry_strategy = Retry(
            total=8,
            backoff_factor=3,
            status_forcelist=(429, 502, 503, 504),
            allowed_methods={
                "HEAD",
                "GET",
                "OPTIONS",
                "POST",
                "PUT",
                "DELETE",
                "PATCH",
            },
            respect_retry_after_header=True,
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def _send_request(self, method: str, url: str, **kwargs) -> Any:
        """
        Send a request to Defender API.
        :param method: Request HTTP method
        :param url: Request URL
        :param kwargs: Any arguments valid for session.requests() method
        :return: Parsed JSON (dict/list) when JSON, requests.Response when stream=True, else text when non-JSON, else None.
        """

        # Handle dry-run mode for modifying requests
        if self.config.passive_only and method.upper() in {
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        }:
            self.helper.connector_logger.info(
                "[DRY-RUN] Skipping modifying request",
                {
                    "method": method.upper(),
                    "url": url,
                    "payload_present": "json" in kwargs or "data" in kwargs,
                },
            )
            # Return a safe, caller-friendly synthetic result.
            # Keep shape minimal but predictable so upstream logic doesn't break.
            return {
                "dry_run": True,
                "status": "skipped (dry-run)",
                "method": method.upper(),
                "url": url,
                "value": [],
            }

        try:
            now = datetime.now(timezone.utc)
            if self._expiration_token_date is None or now > self._expiration_token_date:
                self._get_authorization_header()

            if "timeout" not in kwargs:
                kwargs["timeout"] = DEFAULT_TIMEOUT

            start = perf_counter()
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()

            self.helper.connector_logger.debug(
                "[API] HTTP Request to endpoint",
                {
                    "url_path": f"{method.upper()} {url}",
                    "elapsed_s": round(perf_counter() - start, 3),
                },
            )

            # If streaming, let caller consume the body
            if kwargs.get("stream"):
                return response

            # No body
            if not response.content:
                return None

            # Try JSON only when content-type says JSON
            ctype = response.headers.get("Content-Type", "")
            if "application/json" in ctype.lower():
                try:
                    return response.json()
                except ValueError:
                    return response.text

            # Fallback: return text for non-JSON bodies
            return response.text

        except (RetryError, HTTPError, Timeout, requestsConnectionError) as err:
            meta: dict[str, Any] = {"url_path": f"{method.upper()} {url}"}
            if isinstance(err, HTTPError) and err.response is not None:
                try:
                    snippet = err.response.text[:500]
                except (AttributeError, TypeError, UnicodeDecodeError):
                    snippet = "<unavailable>"
                meta["details"] = {
                    "status": err.response.status_code,
                    "body": snippet,
                }
            raise DefenderApiHandlerError(
                "[API] An error occurred during request",
                meta,
            ) from err

    def _build_request_body(self, observable: dict[str, Any]) -> dict[str, Any] | None:
        """
        Build Defender POST/PATCH request's body from an observable.
        """
        # Make a copy to avoid mutating input
        o = dict(observable)

        # Normalize hash observables into (type, value)
        hashes = o.get("hashes")
        if isinstance(hashes, dict):
            if o.get("type") == "x509-certificate":
                # Prefer SHA1 thumbprints for certificate indicatorType
                for algo in ("sha1", "sha256", "md5"):
                    v = hashes.get(algo)
                    if isinstance(v, str) and v:
                        o["value"] = v
                        break
            else:
                for algo in ("sha256", "sha1", "md5"):
                    v = hashes.get(algo)
                    if isinstance(v, str) and v:
                        o["type"] = algo
                        o["value"] = v
                        break

        # Basic presence/type checks
        t = o.get("type")
        v = o.get("value")
        if not isinstance(t, str) or not isinstance(v, str) or not v:
            self.helper.connector_logger.debug(
                "[PAYLOAD] Skipping observable with missing/invalid type/value",
                {"type": t, "value_sample": str(v)[:64]},
            )
            return None

        # Map to Defender type; enforce known mapping
        indicator_type = IOC_TYPES.get(t)
        if indicator_type is None:
            self.helper.connector_logger.debug(
                "[PAYLOAD] Skipping unsupported observable type", {"type": t}
            )
            return None

        # Enforce writability
        if indicator_type not in CREATABLE_INDICATOR_TYPES:
            self.helper.connector_logger.debug(
                "[PAYLOAD] Skipping non-creatable observable type", {"type": t}
            )
            return None

        # Clean/normalize indicator value
        cleaned_value = indicator_value(v)
        if cleaned_value is None:
            self.helper.connector_logger.debug(
                "[PAYLOAD] Skipping invalid value", {"value": v, "type": t}
            )
            return None

        # Build body
        body: dict[str, Any] = {
            "indicatorType": indicator_type,
            "indicatorValue": cleaned_value,
            "application": "OpenCTI Microsoft Defender Intel Synchronizer",
            "action": get_action(o, self.config.action),
            "title": indicator_title(cleaned_value),
            "description": get_description(o),
            "externalId": o.get("id"),
            "lastUpdateTime": o.get("modified") or o.get("created"),
            "expirationTime": get_expiration_datetime(
                o, get_expire_days(o, int(self.config.expire_time))
            ),
            "severity": get_severity(o),
            "generateAlert": True,
        }

        # Optional config
        rec = get_recommended_actions(o, self.config.recommended_actions)
        if rec not in (None, ""):
            body["recommendedActions"] = rec
        edu = get_educate_url(o, self.config.educate_url)
        if edu not in (None, ""):
            body["educateUrl"] = edu

        # RBAC scoping (emit both arrays when active)
        # RBAC scoping: prefer per-observable policy over global scope
        if isinstance(o.get("rbacGroupIds"), list) and o["rbacGroupIds"]:
            body["rbacGroupNames"] = o.get("rbacGroupNames", [])
            body["rbacGroupIds"] = o["rbacGroupIds"]
        elif self._rbac_scope:
            names, ids = self._rbac_scope
            body["rbacGroupNames"] = names
            body["rbacGroupIds"] = ids

        return body

    def preflight(self) -> bool:
        """
        Fast, best-effort checks to fail early on missing permissions or auth.
        Returns True if preflight looks OK, False otherwise (the run should abort).
        """
        self.helper.connector_logger.info(
            "[Preflight] Starting Defender API preflight checks"
        )

        # Force token refresh first
        try:
            now = datetime.now(timezone.utc)
            if self._expiration_token_date is None or now > self._expiration_token_date:
                self._get_authorization_header()
        except DefenderApiHandlerError as e:
            self.helper.connector_logger.error(
                "[Preflight] Token acquisition failed",
                {"error": e.msg, "meta": e.metadata},
            )
            return False
        except (
            requests.exceptions.RequestException,
            KeyError,
        ) as e:
            self.helper.connector_logger.error(
                "[Preflight] Token acquisition failed",
                {"error": str(e)},
            )
            return False

        # Build canonical URLs once
        list_url = f"{self.base_url}{self.resource_path}"
        import_url = f"{self.base_url}{self.resource_path}/import"

        # --- 1) Test READ access (GET /indicators?$top=1)
        try:
            _ = self._send_request("get", list_url, params={"$top": 1})
            self.helper.connector_logger.info("[Preflight] Indicators read: OK")
        except DefenderApiHandlerError as e:
            status = (e.metadata.get("details") or {}).get("status")
            if status == 401:
                hint = "Unauthorized: verify tenant/client/secret and scope URL"
            elif status == 403:
                hint = "Forbidden: missing Ti.Read.All or Ti.ReadWrite.All permission"
            elif status == 404:
                hint = "Not found: check base_url/resource_path (e.g., /api/indicators)"
            else:
                hint = "Unexpected error during indicators read"
            self.helper.connector_logger.error(
                "[Preflight] Indicators read failed",
                {"status": status, "hint": hint, "meta": e.metadata},
            )
            return False

        # --- 2) Test WRITE access (POST /import with empty Indicators array)
        try:
            # Defender returns 200/202 or 400 for invalid body - both prove we have write permission
            resp = self._send_request("post", import_url, json={"Indicators": []})
            if isinstance(resp, dict) and resp.get("dry_run"):
                self.helper.connector_logger.info(
                    "[Preflight] Indicators write check skipped (passive_only=true)"
                )
            else:
                # 200/202 or 400 for invalid body - both prove we have write permission
                self.helper.connector_logger.info(
                    "[Preflight] Indicators write (empty batch): OK"
                )
        except DefenderApiHandlerError as e:
            status = (e.metadata.get("details") or {}).get("status")
            body = (e.metadata.get("details") or {}).get("body", "")
            if status == 400:
                # 400 means we reached the API and passed authz, body just invalid
                self.helper.connector_logger.info(
                    "[Preflight] Indicators write: OK (400 expected on empty batch)"
                )
            elif status == 403:
                self.helper.connector_logger.error(
                    "[Preflight] Indicators write failed (Forbidden)",
                    {
                        "status": status,
                        "hint": "Missing Ti.ReadWrite.All permission",
                        "meta": e.metadata,
                    },
                )
                return False
            elif status == 401:
                self.helper.connector_logger.error(
                    "[Preflight] Indicators write failed (Unauthorized)",
                    {
                        "status": status,
                        "hint": "Token invalid/expired or wrong resource scope",
                        "meta": e.metadata,
                    },
                )
                return False
            else:
                self.helper.connector_logger.error(
                    "[Preflight] Indicators write failed",
                    {"status": status, "body_sample": body[:200], "meta": e.metadata},
                )
                return False

        # --- 3) Optional RBAC group visibility check
        rbac_group_names = self.config.used_rbac_groups()
        if rbac_group_names:
            name_to_id: dict[str, int] = {}
            try:
                name_to_id, _ = fetch_rbac_name_id_map(
                    self.session.get, self.base_url, self.session.headers
                )
                self.helper.connector_logger.info(
                    "[Preflight] RBAC group read from API: OK"
                )
                _ = resolve_rbac_scope_or_abort(rbac_group_names, name_to_id)
                self.helper.connector_logger.info(
                    "[Preflight] RBAC group names validated"
                )
            except RbacConfigError as e:
                unrecognized = None
                if len(e.args) > 1 and isinstance(e.args[1], dict):
                    unrecognized = e.args[1].get("missing_groups")
                self.helper.connector_logger.error(
                    "[Preflight] RBAC name validation failed; aborting startup",
                    {
                        "error": str(e),
                        "unrecognized_groups": unrecognized,
                        "available_groups": sorted(name_to_id.keys()),
                    },
                )
                return False
            except DefenderApiHandlerError as e:
                status = (e.metadata.get("details") or {}).get("status")
                hint = (
                    "Missing permission to read machine groups (Score.Read.All)"
                    if status in (401, 403)
                    else "Unexpected failure on RBAC group check"
                )
                self.helper.connector_logger.error(
                    "[Preflight] RBAC group read failed",
                    {"status": status, "hint": hint, "meta": e.metadata},
                )
                return False

        self.helper.connector_logger.info(
            "[Preflight] Defender API preflight checks passed successfully"
        )
        return True

    def get_indicators(self) -> list[dict[str, Any]]:
        """
        Get Threat Intelligence Indicators from Defender.
        :return: List of Threat Intelligence Indicators if request is successful, empty list otherwise
        """
        data = self._send_request("get", f"{self.base_url}{self.resource_path}")
        if (
            not isinstance(data, dict)
            or "value" not in data
            or not isinstance(data["value"], list)
        ):
            self.helper.connector_logger.error(
                "[API] Unexpected response when listing indicators",
                {"response_type": type(data).__name__},
            )
            return []
        result = data["value"]
        while "@odata.nextLink" in data and data["@odata.nextLink"] is not None:
            data = self._send_request("get", data["@odata.nextLink"])
            if (
                not isinstance(data, dict)
                or "value" not in data
                or not isinstance(data["value"], list)
            ):
                break
            result.extend(data["value"])
        return result

    def post_indicators(self, observables: list[dict]) -> dict[str, Any] | None:
        """
        Create a Threat Intelligence Indicator on Defender from an OpenCTI observable.
        :param observables: OpenCTI observables to create Threat Intelligence Indicator for
        :return: Threat Intelligence Indicator if request is successful, None otherwise
        """
        request_body = {"Indicators": []}
        for observable in observables:
            request_body_observable = self._build_request_body(observable)
            if request_body_observable is not None:
                request_body["Indicators"].append(request_body_observable)

        # If there are no creatable indicators, return a synthetic "all good" response
        if not request_body.get("Indicators"):
            return {"value": [], "failed_count": 0, "total_count": 0}

        data = self._send_request(
            "post",
            f"{self.base_url}{self.resource_path}/import",
            json=request_body,
        )

        # Count and log failed indicators
        failed_count = 0
        failed_reasons = []
        if (
            isinstance(data, dict)
            and "value" in data
            and isinstance(data["value"], list)
        ):
            for item in data["value"]:
                if item.get("isFailed"):
                    failed_count += 1
                    reason = item.get("failureReason", "Unknown reason")
                    failed_reasons.append(str(reason))
        if failed_count > 0:
            self.helper.connector_logger.warning(
                "[API] Some indicators failed to import.",
                {
                    "failed_count": failed_count,
                    "failed_reasons": failed_reasons[:10],
                    "truncated": failed_count > 10,
                },
            )

        # add the failed count to the data
        if not isinstance(data, dict):
            return {
                "value": [],
                "failed_count": failed_count,
                "total_count": len(request_body["Indicators"]),
            }
        data["failed_count"] = failed_count
        data["total_count"] = len(request_body["Indicators"])

        return data

    def delete_indicators(self, indicator_ids: list[str]) -> bool:
        """
        Delete a Threat Intelligence Indicator on Defender corresponding to an OpenCTI observable.
        :param indicator_ids: Indicators IDs
        :return: True if request is successful, False otherwise
        """
        request_body = {"IndicatorIds": indicator_ids}
        self._send_request(
            "post",
            f"{self.base_url}{self.resource_path}/BatchDelete",
            json=request_body,
        )
        return True

    def delete_indicator(self, indicator_id: str) -> bool:
        """
        Delete a Threat Intelligence Indicator on Defender corresponding to an OpenCTI observable.
        :param indicator_id: OpenCTI observable to delete Threat Intelligence Indicator for
        :return: True if request is successful, False otherwise
        """
        self._send_request(
            "delete",
            f"{self.base_url}{self.resource_path}/{indicator_id}",
        )
        return True
