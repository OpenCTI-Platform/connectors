"""IPQS client module."""

import time
from typing import Any, Dict, Optional

from pycti import OpenCTIConnectorHelper
from requests import session
from requests.exceptions import (
    ConnectTimeout,
    HTTPError,
    InvalidURL,
    JSONDecodeError,
    ProxyError,
    RequestException,
)

from .constants import (
    EMAIL_ENRICH_FIELDS,
    FILE_ENRICH_FIELDS,
    IP_ENRICH_FIELDS,
    LEAK_PASSWORD,
    LEAK_USERNAME_OR_EMAIL,
    PHONE_ENRICH_FIELDS,
    URL_ENRICH_FIELDS,
    to_bool,
)

# Default per-request timeout (seconds) applied to the synchronous
# fraud-and-risk-scoring + leaked-credential calls so a stuck IPQS
# network does not block the worker indefinitely. The malware-file
# scanner branch uses its own ``_REQUEST_TIMEOUT_SECONDS`` /
# ``_POSTBACK_REQUEST_TIMEOUT_SECONDS`` budgets defined on the class.
_HTTP_TIMEOUT_SECONDS = 30


class IPQSClient:
    """IPQS client.

    Speaks to three IPQS API families with a single API key:

    * the fraud-and-risk-scoring endpoints (``/ip``, ``/url``,
      ``/email``, ``/phone``) used by ``IPQSConnector._process_ip`` /
      ``_process_url`` / ``_process_email`` / ``_process_phone``;
    * the Darkweb-Leak endpoints (``/leaked/email``,
      ``/leaked/username``, ``/leaked/password``) used by
      ``IPQSConnector._process_leak`` for ``User-Account`` observables
      (PR #6399);
    * the malware-file-scanner endpoints (``/malware/scan``,
      ``/malware/lookup``, ``/postback``) used by
      ``IPQSConnector._process_artifact`` for ``Artifact``
      observables — the integration originally proposed as a
      standalone connector in PR #5970 now lives here so a single
      connector serves every IPQS use case (issue #6199). The flow
      is cache-first (lookup) then submit (scan) then poll
      (postback) until a final result is returned, the upstream
      surfaces an error, or the polling budget is exhausted.
    """

    _MALWARE_SCAN_ENDPOINT = "/malware/scan"
    _MALWARE_LOOKUP_ENDPOINT = "/malware/lookup"
    _MALWARE_POSTBACK_ENDPOINT = "/postback"

    # Polling defaults for asynchronous malware scans.
    _MAX_POLLING_ATTEMPTS = 9
    _POLLING_INTERVAL_SECONDS = 10
    _REQUEST_TIMEOUT_SECONDS = 60
    # Postback is a small status-check JSON response. The per-request
    # timeout is kept low (10 s) so a stuck postback call cannot eat
    # the whole polling budget on its own. The attempt-level upper
    # bound is therefore
    # ``_MAX_POLLING_ATTEMPTS * (_POLLING_INTERVAL_SECONDS +
    # _POSTBACK_REQUEST_TIMEOUT_SECONDS) == 9 * (10 + 10) == 180 s``,
    # but ``_POLLING_BUDGET_SECONDS`` below caps the loop absolutely
    # at the documented 120 s so the worker is never blocked longer
    # than that on a single Artifact enrichment.
    _POSTBACK_REQUEST_TIMEOUT_SECONDS = 10
    # Hard ceiling on the postback polling loop — even if every
    # iteration burns its full per-request timeout we still bail out
    # at this point so a single slow scan cannot tie up the enrichment
    # worker indefinitely.
    _POLLING_BUDGET_SECONDS = 120

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        base_url: str,
        api_key: str,
    ) -> None:
        """Initialise IPQS client.

        The API key is sent through the ``IPQS-KEY`` HTTP header for
        every endpoint — including the ``/leaked/...`` and
        ``/malware/...`` families — so the secret is never written to
        the URL (and therefore never ends up in HTTP access logs).

        ``base_url`` is normalised through ``.rstrip("/")`` so the
        per-endpoint URL builders never produce a double slash; the
        ``isinstance`` guard mirrors the defensive shape applied
        repo-wide by ``[all] Fix url to avoid double slash`` (#6394)
        and protects against a future config typing change that might
        pass a non-``str`` value here.
        """
        self.helper = helper
        self.url = base_url.rstrip("/") if isinstance(base_url, str) else base_url
        self.session = session()
        self.session.headers.update({"IPQS-KEY": api_key})

        # Field maps consumed by the enrichment workers.
        self.ip_enrich_fields = IP_ENRICH_FIELDS
        self.url_enrich_fields = URL_ENRICH_FIELDS
        self.email_enrich_fields = EMAIL_ENRICH_FIELDS
        self.phone_enrich_fields = PHONE_ENRICH_FIELDS
        self.file_enrich_fields = FILE_ENRICH_FIELDS

    # ------------------------------------------------------------------
    # GET (legacy IP / URL / Email / Phone enrichment)
    # ------------------------------------------------------------------
    def _query(
        self, url: str, params: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """Issue a GET request and return the parsed JSON body.

        Returns ``None`` for every condition that prevents a usable
        response (network error, non-2xx HTTP status, non-JSON body,
        IPQS ``success == False`` payload). Callers must treat the
        return value as optional rather than calling ``.get(...)`` on it
        directly.
        """
        try:
            response = self.session.get(
                url, params=params, timeout=_HTTP_TIMEOUT_SECONDS
            )
            response.raise_for_status()
            data = response.json()
        except HTTPError as error:
            # HTTP status outside of 2xx — keep the connector alive and
            # surface the status for the operator. ``HTTPError`` is a
            # subclass of ``RequestException`` so the ordering matters:
            # this branch must come before the broader transport branch
            # below to keep the dedicated log message.
            self.helper.log_error(f"IPQS HTTP error for {url}: {error}")
            return None
        except (JSONDecodeError, ValueError) as error:
            # Non-JSON / truncated body — keep the connector alive.
            # ``requests.exceptions.JSONDecodeError`` inherits from
            # both ``ValueError`` and (via ``InvalidJSONError``)
            # ``RequestException``, so this branch *must* come before
            # the catch-all ``except RequestException`` below; otherwise
            # an IPQS response with an HTML / text error body would be
            # logged as a connectivity failure instead of an actionable
            # "non-JSON response" log line.
            self.helper.log_error(
                f"IPQS returned a non-JSON response for {url}: {error}"
            )
            return None
        except RequestException as error:
            # Catch the full ``requests`` exception hierarchy so a slow
            # response (``ReadTimeout`` / ``Timeout``), a proxy error,
            # an invalid URL, an SSL error, a chunked-encoding error
            # or any other transport failure simply returns ``None``
            # rather than crashing the connector. ``ConnectTimeout``,
            # ``ProxyError`` and ``InvalidURL`` are all subclasses of
            # ``RequestException`` so they remain handled.
            self.helper.log_error(
                f"Error connecting to IPQS ({type(error).__name__}): {error}"
            )
            return None

        if not to_bool(data.get("success")):
            self.helper.log_error(f"Error: {data.get('message')}")
            return None
        return data

    def get_ipqs_info(
        self, enrich_type: str, enrich_value: str
    ) -> Optional[Dict[str, Any]]:
        """Return the IPQS enrichment for the given observable value.

        Always returns either the parsed JSON dict on success or
        ``None`` on any failure (network, HTTP status, JSON decode,
        ``success == False``); the underlying error has already been
        logged by :meth:`_query`.
        """
        url = f"{self.url}/{enrich_type}"
        params = {enrich_type: enrich_value}
        return self._query(url, params)

    # ------------------------------------------------------------------
    # POST (leaked credentials / passwords)
    # ------------------------------------------------------------------
    @staticmethod
    def looks_like_email(value: str) -> bool:
        """Return ``True`` when ``value`` looks like an email address.

        Uses a permissive shape check (single ``@``, non-empty local and
        domain parts, at least one ``.`` in the domain) rather than a
        strict ASCII-TLD regex so that IDN/punycode domains (e.g.
        ``user@example.xn--p1ai``) and multi-label TLDs (e.g.
        ``user@example.co.uk``) are routed to ``/leaked/email`` instead
        of being misrouted to ``/leaked/username`` — the latter would
        silently miss leak matches for any address whose TLD is not a
        plain ASCII-letters-only string.
        """
        cleaned = (value or "").strip()
        if cleaned.count("@") != 1:
            return False
        local, _, domain = cleaned.partition("@")
        if not local or not domain:
            return False
        # Reject whitespace anywhere in the local or domain parts; a
        # full RFC-5322 parser would be overkill for the routing
        # decision but a stray space is a clear "not an email" signal.
        if any(c.isspace() for c in cleaned):
            return False
        # Require a dot in the domain part so bare hostnames
        # (``user@localhost``) still take the ``/leaked/username``
        # path. The domain part itself cannot start or end with a dot.
        return "." in domain and not domain.startswith(".") and not domain.endswith(".")

    def get_leaked_info(self, leak_endpoint: str, value: str):
        """Return the IPQS Darkweb-Leak enrichment for ``value``.

        ``leak_endpoint`` is one of
        :data:`~.constants.LEAK_USERNAME_OR_EMAIL` (when the
        User-Account observable carries an ``account_login``) or
        :data:`~.constants.LEAK_PASSWORD` (when it carries a
        ``credential``). The IPQS leak API expects different JSON keys
        depending on the kind of data being looked up:

        * ``email`` for an email-shaped account login;
        * ``username`` for any other login;
        * ``password`` for a credential.

        The API key is sent through the ``IPQS-KEY`` header inherited
        from the shared session — *never* as a path component, which
        would risk leaking the secret into HTTP access logs.
        """
        if leak_endpoint == LEAK_USERNAME_OR_EMAIL:
            query_kind = "email" if self.looks_like_email(value) else "username"
        elif leak_endpoint == LEAK_PASSWORD:
            query_kind = "password"
        else:
            raise ValueError(f"Unsupported leak endpoint: {leak_endpoint!r}")

        url = f"{self.url}/leaked/{query_kind}"
        try:
            response = self.session.post(
                url,
                json={query_kind: value},
                timeout=_HTTP_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            data = response.json()
        except HTTPError as exc:
            # HTTP status outside of 2xx — keep the connector alive.
            # ``HTTPError`` is a subclass of ``RequestException`` so the
            # ordering matters: this branch must come before the broader
            # transport branch below to keep the dedicated log message.
            self.helper.log_error(f"IPQS leaked API HTTP error for {url}: {exc}")
            return None
        except (JSONDecodeError, ValueError) as exc:
            # Non-JSON / truncated body — keep the connector alive.
            # ``requests.exceptions.JSONDecodeError`` inherits from
            # both ``ValueError`` and (via ``InvalidJSONError``)
            # ``RequestException``, so this branch *must* come before
            # the catch-all ``except RequestException`` below; otherwise
            # a leaked-API response with an HTML / text error body
            # would be logged as a connectivity failure instead of an
            # actionable "non-JSON response" log line.
            self.helper.log_error(
                f"IPQS leaked API returned a non-JSON response for {url}: {exc}"
            )
            return None
        except RequestException as exc:
            # Catch the full ``requests`` exception hierarchy here too
            # (``ReadTimeout`` / ``Timeout`` / ``ProxyError`` /
            # ``InvalidURL`` / ``SSLError`` / ``ChunkedEncodingError``
            # / ...) so a slow leaked-API response cannot crash the
            # enrichment worker.
            self.helper.log_error(
                f"Error connecting to IPQS leaked API ({type(exc).__name__}): {exc}"
            )
            return None

        # IPQS encodes ``success`` either as a native JSON boolean or as
        # the strings ``"True"`` / ``"False"`` depending on the endpoint
        # (the legacy GET endpoints handled by ``_query`` use the string
        # form). ``to_bool`` normalises both shapes so a ``success ==
        # "False"`` payload from the leaked API is treated as a failure
        # — a naive ``data.get("success", False)`` would treat the
        # non-empty string ``"False"`` as truthy and let a failed lookup
        # produce indicators / labels.
        if not to_bool(data.get("success")):
            self.helper.log_error(f"IPQS leaked API error: {data.get('message')}")
            return None
        return data

    # ------------------------------------------------------------------
    # Malware file scanner endpoints
    #
    # Adapted from the standalone connector proposed in PR
    # https://github.com/OpenCTI-Platform/connectors/pull/5970 — instead of
    # shipping a separate ``ipqs-analyzer`` connector, the malware-file-scanner
    # flow lives next to the existing fraud-and-risk-scoring + leaked-credential
    # flows so a single IPQS API key can drive every supported observable type.
    # ------------------------------------------------------------------
    def _query_malware(
        self,
        endpoint: str,
        params: Optional[dict] = None,
        file: Optional[dict] = None,
        timeout: Optional[int] = None,
    ) -> Optional[dict]:
        """Send a request to the IPQS malware-file-scanner API.

        Returns the decoded JSON payload, or ``None`` when the request fails
        because of a network / SSL / HTTP error, an unavailable upstream
        service, or an invalid JSON payload. Callers MUST handle ``None``
        explicitly.

        ``timeout`` overrides the default per-request timeout — used by
        the postback polling loop to enforce a tighter budget than the
        60 s default that fits an actual scan submission.
        """
        request_timeout = (
            timeout if timeout is not None else self._REQUEST_TIMEOUT_SECONDS
        )
        url = f"{self.url}{endpoint}"
        is_post = bool(file) or bool(params and params.get("url"))
        try:
            # ``debug`` rather than ``info`` because the postback polling
            # loop hits this code path up to ``_MAX_POLLING_ATTEMPTS`` times
            # per Artifact enrichment — emitting one INFO line per call
            # would flood normal ``info``-level deployments with N noisy
            # lines per single enrichment. ``get_malware_scan_info``
            # already logs the lookup / scan / postback lifecycle at INFO
            # so operators still see the high-level state changes.
            self.helper.log_debug(f"IPQS malware request: {endpoint}")
            if is_post:
                # Auth header lives on ``self.session.headers`` — passing
                # it again per-request would be redundant.
                response = self.session.post(
                    url,
                    files=file,
                    json=params,
                    timeout=request_timeout,
                )
            else:
                response = self.session.get(
                    url,
                    params=params,
                    timeout=request_timeout,
                )

            if response.status_code == 503:
                self.helper.log_error(
                    f"IPQS service unavailable (HTTP 503) on {endpoint}."
                )
                return None
            if response.status_code >= 500:
                self.helper.log_error(
                    f"IPQS server error (HTTP {response.status_code}) on {endpoint}."
                )
                return None
            if response.status_code == 401:
                self.helper.log_error(
                    "IPQS authentication failed (HTTP 401); check IPQS_PRIVATE_KEY."
                )
                return None
            response.raise_for_status()

            try:
                return response.json()
            except (JSONDecodeError, ValueError) as error:
                self.helper.log_error(
                    f"IPQS returned a non-JSON response on {endpoint}: {error}"
                )
                return None
        except (ConnectTimeout, ProxyError, InvalidURL) as error:
            self.helper.log_error(
                f"Connection error while contacting IPQS ({endpoint}): {error}"
            )
            return None
        except HTTPError as error:
            self.helper.log_error(f"HTTP error from IPQS ({endpoint}): {error}")
            return None
        except RequestException as error:
            self.helper.log_error(
                f"Unexpected error while contacting IPQS ({endpoint}): {error}"
            )
            return None

    def get_malware_scan_info(
        self,
        file: Optional[dict] = None,
        params: Optional[dict] = None,
    ) -> Optional[dict]:
        """Return the IPQS malware-scan data for an Artifact or URL.

        The lookup endpoint is tried first to leverage the 24h cache; on a
        cache miss the scan endpoint is called and the postback endpoint
        is polled until a final result is returned, an error occurs, or
        the polling budget is exhausted.
        """
        if not file and not params:
            self.helper.log_error(
                "get_malware_scan_info called without 'file' or 'params'; "
                "nothing to query."
            )
            return None

        # Try the cache first. Lifecycle events for the malware-scan flow
        # are emitted at INFO so operators see one log line per Artifact
        # enrichment (lookup → scan → polling start → completion), while
        # the per-request lines from ``_query_malware`` are kept at DEBUG
        # to avoid a flood during postback polling.
        self.helper.log_info("IPQS malware scan: looking up cached verdict.")
        response = self._query_malware(
            self._MALWARE_LOOKUP_ENDPOINT, file=file, params=params
        )
        if response is None:
            self.helper.log_error("No response received from IPQS lookup request.")
            return None
        if response.get("status") == "cached":
            self.helper.log_info("IPQS malware scan: cache hit; no scan submitted.")
            return response

        # Cache miss: submit a scan request.
        self.helper.log_info(
            "IPQS malware scan: cache miss, submitting file to /malware/scan."
        )
        response = self._query_malware(
            self._MALWARE_SCAN_ENDPOINT, file=file, params=params
        )
        if response is None:
            self.helper.log_error("No response received from IPQS scan request.")
            return None

        if not response.get("success", False):
            # Scan rejected (invalid input, no credits, ...) — surface as-is.
            return response

        request_id = response.get("request_id")
        if not request_id:
            # Without a ``request_id`` we cannot poll for the final
            # verdict. Returning the partial scan response as-is would
            # let ``_process_artifact`` treat the acknowledgement as a
            # final result (and potentially mark a still-running scan
            # as ``Clean``). Convert it into an explicit failure so the
            # caller raises a failure note instead of building an
            # indicator from incomplete data.
            self.helper.log_error(
                "Scan response missing 'request_id'; cannot poll for results."
            )
            original_message = response.get("message", "")
            failure_message = (
                "IPQS scan response did not include a request_id; "
                "results cannot be polled."
            )
            if original_message:
                failure_message = f"{failure_message} (upstream: {original_message})"
            response["success"] = False
            response["message"] = failure_message
            return response

        # Poll the postback endpoint for an asynchronous result. The
        # overall deadline caps the worst case to
        # ``_POLLING_BUDGET_SECONDS`` (default 120s) even if every
        # iteration burns its full per-request timeout — a single slow
        # scan can no longer tie up the enrichment worker indefinitely.
        self.helper.log_info(
            "IPQS malware scan: polling /postback for "
            f"request_id={request_id} (budget={self._POLLING_BUDGET_SECONDS}s)."
        )
        postback_params = {"request_id": request_id}
        deadline = time.monotonic() + self._POLLING_BUDGET_SECONDS
        for _ in range(self._MAX_POLLING_ATTEMPTS):
            if response.get("status") != "pending":
                break
            if time.monotonic() >= deadline:
                self.helper.log_warning(
                    "IPQS postback polling budget exhausted "
                    f"({self._POLLING_BUDGET_SECONDS}s); "
                    "returning the last known response."
                )
                break
            time.sleep(self._POLLING_INTERVAL_SECONDS)
            postback_response = self._query_malware(
                self._MALWARE_POSTBACK_ENDPOINT,
                params=postback_params,
                timeout=self._POSTBACK_REQUEST_TIMEOUT_SECONDS,
            )
            if postback_response is None:
                self.helper.log_error(
                    "No response received from IPQS during postback polling; "
                    "returning the last known response."
                )
                break
            response = postback_response
            if not response.get("success", False):
                self.helper.log_error(
                    f"IPQS postback returned failure: {response.get('message')}"
                )
                break

        return response
