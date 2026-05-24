import time
from datetime import datetime, timezone
from typing import Optional, Protocol

import requests

from .config_variables import ConfigConnector
from .custom_exceptions import SentinelOnePermissionError

REQUEST_TIMEOUT = (10, 30)

# All endpoints start with a leading ``/`` because
# ``ConfigConnector`` strips the trailing ``/`` from ``s1_url``
# (see ``config_variables.py``); composing the request URL with
# ``s1_url + INCIDENTS_API_LOCATION`` therefore yields
# ``https://<tenant>.sentinelone.net/web/api/v2.1/threats?...``
# rather than the broken ``...netweb/api/...`` form a missing
# leading slash would produce.
INCIDENTS_API_LOCATION = (
    "/web/api/v2.1/threats?limit=50&sortBy=createdAt&sortOrder=desc&accountIds="
)
INCIDENT_NOTES_API_LOCATION_TEMPLATE = "/web/api/v2.1/threats/{incident_id}/notes?limit=1000&sortBy=createdAt&sortOrder=desc"


class _MetaLogger(Protocol):
    """Minimal structural type for the connector logger.

    ``SentinelOneClient`` is constructed with
    ``OpenCTIConnectorHelper.connector_logger`` (a pycti ``AppLogger``)
    whose level methods accept an optional ``meta`` keyword for
    structured context. The stdlib ``logging.Logger`` API does **not**
    accept ``meta``, so annotating the parameter as ``logging.Logger``
    (the previous shape) was misleading and would silently break a
    type-checker if a stdlib logger was ever passed in. ``AppLogger``
    is created dynamically inside the pycti ``logger(...)`` factory
    and is not importable, so we capture the contract structurally
    here.
    """

    def debug(self, message: str, meta: Optional[dict] = None) -> None: ...

    def info(self, message: str, meta: Optional[dict] = None) -> None: ...

    def warning(self, message: str, meta: Optional[dict] = None) -> None: ...

    def error(self, message: str, meta: Optional[dict] = None) -> None: ...


def _parse_utc(dt_str: Optional[str]) -> Optional[datetime]:
    """Parse an ISO 8601 datetime string and ensure it is UTC-aware.

    Returns ``None`` when the input is missing/empty so the caller can
    explicitly decide what to do with an incident that carries no
    ``createdAt`` — the previous shape returned the Unix epoch
    (``1970-01-01T00:00:00Z``), which in :meth:`fetch_incidents` would
    immediately be ``< start_date`` and stop pagination on the first
    timestamp-less record, silently skipping every newer incident
    behind it.

    Handles both the ``Z`` suffix and timezone-naive inputs (assumed
    UTC). Compatible with Python 3.9+.
    """
    if not dt_str:
        return None
    dt_str = dt_str.replace("Z", "+00:00")
    dt = datetime.fromisoformat(dt_str)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt


class SentinelOneClient:

    def __init__(self, logger: _MetaLogger, config: ConfigConnector):
        self.logger = logger
        self.config = config
        self.logger.info("SentinelOne Client Initialised Successfully.")

    def fetch_incidents(self, start_date: datetime) -> list:
        """
        Fetches all incidents from SentinelOne created after start_date.
        Results are sorted descending by createdAt, so we stop as soon
        as we hit an incident older than start_date.
        """
        # Normalise ``start_date`` to UTC-aware so the
        # ``incident_created_at < start_date`` comparison below never
        # raises ``TypeError`` when the caller hands in a naive
        # datetime (e.g. a downstream regression that re-introduces
        # naive parsing in ``connector.py``). Naive values are assumed
        # to already be UTC — the connector only produces UTC
        # timestamps anyway.
        if start_date.tzinfo is None:
            start_date = start_date.replace(tzinfo=timezone.utc)
        else:
            start_date = start_date.astimezone(timezone.utc)

        url = self.config.s1_url + INCIDENTS_API_LOCATION + self.config.s1_account_id
        incidents = []
        skip = 0
        stop_fetching = False

        while not stop_fetching:
            page_url = url + (f"&skip={skip}" if skip > 0 else "")
            response = self._send_api_req(page_url, "GET")

            # ``_send_api_req`` documents ``None`` as the only failure
            # sentinel — a successful 204 / empty-body 2xx now returns
            # an empty ``dict`` (which is falsy in Python). Comparing
            # against ``None`` explicitly so a legitimate empty success
            # response does not get misclassified as a failure that
            # aborts pagination on the rest of the SentinelOne /threats
            # window.
            if response is None:
                self.logger.error("API request failed, stopping fetch.")
                break

            page_data = response.get("data", [])
            total_items = response.get("pagination", {}).get("totalItems", 0)

            if not page_data:
                break

            for incident in page_data:
                threat_info = incident.get("threatInfo", {})
                incident_created_at = _parse_utc(threat_info.get("createdAt", ""))
                # SentinelOne's v2.1 ``/threats`` items expose the
                # canonical identifier under ``threatInfo.threatId``;
                # the top-level ``id`` is populated as a convenience
                # mirror in current responses but is not guaranteed
                # by the API documentation. Prefer the nested field
                # and fall back to the top-level alias so log lines,
                # downstream URL composition and STIX external
                # references stay correct even if a future
                # SentinelOne release drops the top-level mirror.
                incident_id = threat_info.get("threatId") or incident.get("id")

                # Skip incidents with a missing/empty ``createdAt``
                # rather than stopping the pagination: ``_parse_utc``
                # now returns ``None`` for those, and treating them as
                # 1970-01-01 (the previous shape) would always be
                # ``< start_date`` and silently truncate the result
                # set on the first timestamp-less record. Log and
                # continue so the operator can investigate the upstream
                # data quality issue without losing every newer
                # incident behind it.
                if incident_created_at is None:
                    self.logger.warning(
                        "Incident has no createdAt timestamp; skipping",
                        meta={"incident_id": incident_id},
                    )
                    continue

                # Use ``<=`` (not ``<``) so the cursor semantics are
                # "created strictly after ``start_date``", matching the
                # docstring above and the README. ``last_run`` is
                # written as ``datetime.now(...).strftime("...Z")`` at
                # the end of every cycle (second-precision wall clock),
                # so any incident whose ``createdAt`` second-aligns
                # with the previous cycle's cursor would otherwise be
                # appended on this cycle AND on the previous one,
                # producing a duplicate-import. On the very first
                # cycle the cursor is the configured
                # ``IMPORT_START_DATE``: incidents created at exactly
                # that second are excluded too, matching the
                # documented "strictly after" semantic.
                if incident_created_at <= start_date:
                    self.logger.info(
                        f"Incident created at {incident_created_at} is at or before "
                        f"start_date {start_date}, stopping fetch."
                    )
                    stop_fetching = True
                    break

                incidents.append(incident)

            skip += len(page_data)

            # Stop if we've fetched everything. ``total_items`` is
            # only a meaningful upper bound when SentinelOne returned
            # a positive ``pagination.totalItems`` — when the field
            # is missing or zero (some v2.1 responses omit it), the
            # previous shape would unconditionally break here after
            # the first page because ``skip`` (e.g. 50) was already
            # ``>= 0``, silently truncating the result set to a
            # single page even when more pages existed. The
            # empty-page check at the top of the next iteration is
            # the natural pagination terminator on those payloads,
            # so guard the bound on ``total_items > 0`` and let the
            # loop fall through to it.
            if total_items > 0 and skip >= total_items:
                break

        self.logger.info(f"Fetched {len(incidents)} incidents since {start_date}.")
        return incidents

    def fetch_incident_notes(self, incident_id: str) -> list:
        """
        Fetches all notes from a single incident from SentinelOne via API.

        Returns an empty list when ``_send_api_req`` could not retrieve
        a usable response (transport failure, 429 retry exhaustion or a
        non-200 status) so the caller's bundle assembly still completes
        for the rest of the incident's STIX objects instead of crashing
        with ``AttributeError: 'NoneType' object has no attribute 'get'``.
        """

        url = self.config.s1_url + INCIDENT_NOTES_API_LOCATION_TEMPLATE.format(
            incident_id=incident_id
        )
        response = self._send_api_req(url, "GET")
        # See the ``fetch_incidents`` rationale for the explicit
        # ``is None`` check: a successful 204 / empty-body 2xx returns
        # ``{}`` and ``not {}`` is ``True``, which would otherwise be
        # treated as a transport failure and degrade silently to an
        # empty notes list even when the API legitimately said
        # "no notes for this incident".
        if response is None:
            return []
        return response.get("data", [])

    def _send_api_req(
        self,
        url: str,
        request_type: str,
        payload: Optional[dict] = None,
        wait_time: int = 1,
        attempts: int = 0,
    ) -> Optional[dict]:
        """
        Dynamic API request sender handling all
        important cases and retries.

        Returns the response decoded as a ``dict`` on any 2xx response
        (with an empty ``dict`` for a 204 / empty body, so callers can
        still safely call ``.get(...)``) and ``None`` on a transport-
        level failure (network / DNS / timeout / connection reset, 429
        retry exhaustion or a non-2xx status). Authentication failures
        (401) raise :class:`SentinelOnePermissionError`. The ``None``
        sentinel matches the ``Optional[dict]`` return annotation, so
        callers like :meth:`fetch_incident_notes` can safely fall back
        to an empty result without an ``AttributeError`` on
        ``.get(...)``.
        """

        def calculate_exponential_delay(last_wait_time):
            return last_wait_time * 2

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": self.config.s1_api_key,
        }

        # ``requests.request`` raises ``RequestException`` (the base for
        # DNS errors, timeouts, connection resets, SSL errors, …) on
        # any transport-level failure. Without this guard the
        # exception would bubble out of ``fetch_incidents`` /
        # ``fetch_incident_notes`` and abort the whole scheduler
        # cycle for a transient network blip. The docstring above
        # promises a ``None`` return on transport failure, so the
        # try/except keeps the runtime behaviour aligned with the
        # contract (callers degrade gracefully — `fetch_incidents`
        # stops pagination cleanly and `fetch_incident_notes` falls
        # back to an empty notes list for the current incident).
        try:
            response = requests.request(
                method=request_type,
                url=url,
                headers=headers,
                data=payload or {},
                timeout=REQUEST_TIMEOUT,
            )
        except requests.exceptions.RequestException as exc:
            self.logger.error(
                "Transport-level failure talking to SentinelOne; "
                "returning None so the caller can degrade gracefully.",
                meta={"url": url, "method": request_type, "error": str(exc)},
            )
            return None

        # Authentication Errors should be raised and halt execution, nothing can continue if they are present.
        if response.status_code == 401:
            raise SentinelOnePermissionError(
                "Permissions Error, SentinelOne returned a 401, please check your API key and account ID."
            )

        # Rate Limiting requires an exponential backoff as a workaround.
        elif response.status_code == 429:
            if attempts < self.config.max_api_attempts:
                new_wait_time = calculate_exponential_delay(wait_time)
                self.logger.info(
                    f"Too many requests to S1, waiting: {new_wait_time} seconds"
                )
                time.sleep(new_wait_time)
                return self._send_api_req(
                    url, request_type, payload, new_wait_time, attempts + 1
                )
            else:
                self.logger.error(
                    f"Error, unable to send Payload to SentinelOne after: {self.config.max_api_attempts} attempts."
                )
            return None

        # Treat every 2xx as success and align the runtime with the
        # ``Returns the response decoded as a ``dict`` on any 2xx
        # response`` contract advertised in the docstring above. The
        # previous shape only accepted 200, so a future SentinelOne
        # endpoint that returns 201 (created) or 202 (accepted) — both
        # documented as legal success codes by the SentinelOne v2.1
        # API — would silently fall through to the ``None`` branch
        # despite the response being a successful one. ``204 No
        # Content`` (or any other empty-body success) is collapsed to
        # an empty ``dict`` here so callers' ``.get("data", [])`` etc.
        # still works without an extra branch — ``response.json()``
        # would otherwise raise ``JSONDecodeError`` on an empty body.
        elif 200 <= response.status_code < 300:
            if response.status_code == 204 or not response.content:
                return {}
            try:
                return response.json()
            except ValueError as exc:
                # Non-JSON body on a 2xx response — surface it as a
                # transport-level failure rather than crashing the
                # caller. The SentinelOne v2.1 API documents JSON
                # responses for every endpoint the connector hits, so
                # this branch only fires on a misconfigured
                # tenant / proxy.
                self.logger.error(
                    "Non-JSON 2xx response from SentinelOne; returning None.",
                    meta={
                        "url": url,
                        "method": request_type,
                        "status_code": response.status_code,
                        "error": str(exc),
                    },
                )
                return None

        # Non-2xx (and non-401/429) errors should be logged with context of their origin
        self.logger.info(f"Error, Request got Response: {response.status_code}")
        self.logger.debug(f"URL Used: {url}")
        self.logger.debug(f"S1 responded with: {response.text}")
        return None
