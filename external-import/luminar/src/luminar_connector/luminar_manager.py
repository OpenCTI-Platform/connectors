"""
luminar_manager.py

Cognyte Luminar TAXII client: a single ``LuminarManager`` class that owns the
whole retrieval (EXTRACT) stage of the connector pipeline

    Luminar API calls -> pagination -> batching -> sliding window
        -> reference resolution -> batched results

Intended usage::

    manager = LuminarManager(
        cognyte_client_id=...,
        cognyte_client_secret=...,
        cognyte_account_id=...,
        cognyte_base_url=...,
        added_after="2024-01-01T00:00:00.000000Z",  # default fetch-from
        logger=helper.connector_logger,
    )
    for feed_name in EXPECTED_COLLECTION_ALIASES:
        for batch in manager.get_objects(feed_name, added_after=checkpoint):
            ingest(batch["results"]["data"])
            save_checkpoint(feed_name, batch["results"]["last_success"])

``get_objects()`` is a generator: it produces one resolved batch at a time
rather than accumulating an entire collection in memory. Each yield is

    {
        "results": {
            "data": [...],          # raw STIX records for this batch, plus the
                                    # objects they reference (hydrated)
            "last_success": "...",  # checkpoint for this batch
        },
        "error": None or "<error text>",
    }

``results["data"]`` is a fresh list per yield owned by the caller; persist
``results["last_success"]`` as the feed's resume checkpoint after ingesting.

This module only fetches and returns raw Luminar records. It performs no STIX
conversion, filtering or ingestion; those are separate pipeline stages.
"""

from __future__ import annotations

import logging
import re
import time
from collections import OrderedDict
from datetime import datetime, timedelta
from typing import (
    Any,
    Callable,
    Dict,
    Iterator,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
)

import requests

# -------------------------
# Config / Constants
# -------------------------

TIMEOUT = 60.0

LUMINAR_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

USER_AGENT = "OpenCTI-Luminar-Connector"

# API RETRY CONFIG
RETRY_ATTEMPTS = 3
RETRY_DELAY = 60  # seconds (1 minute)
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}

# Network-error retry for `next`-cursored page fetches.
# These are intentionally small: a `next` cursor has a ~2-minute TTL, so we
# must recover from a transient transport blip (ConnectionError, Timeout,
# SSLError, etc.) WITHOUT burning enough time to let the cursor go stale.
# This retry covers ONLY raised network exceptions; HTTP status handling
# (410 -> StaleCursorError, 429/5xx -> execute_with_retry) is left to the
# caller and is deliberately untouched.
CURSOR_NETWORK_RETRY_ATTEMPTS = 2
CURSOR_NETWORK_RETRY_DELAY = 2  # seconds

# Stall guard for stale-cursor recovery. It guards only the narrow
# no-progress stall: the fresh request keeps succeeding but the cursored
# follow-up keeps going stale AND the last-seen X-TAXII-Date-Added never
# advances, so each rebuild re-fetches the same slice forever. We abort only
# when last_added_seen fails to advance across this many CONSECUTIVE stale
# rebuilds; any forward progress resets the counter, so a healthy
# slow-but-degraded run (one batch per cycle) is never penalized.
MAX_STALE_REBUILDS_WITHOUT_PROGRESS = 5

# TAXII collection aliases processed by the connector, in processing order.
# Other collections served by Luminar (e.g. "vulnerabilities") are not ingested.
EXPECTED_COLLECTION_ALIASES = ["iocs", "leakedrecords", "cyberfeeds"]

# Pagination / batching
DEFAULT_LIMIT = 9999
PAGES_PER_BATCH = 10

# Persistent cache for life of the manager (required), bounded to avoid
# unbounded memory growth on long-running / large-backfill runs.
HYDRATED_OBJECTS_MAX_SIZE = 50000

# STIX 2.x identifier shape: "<object-type>--<UUID>". Covers standard types
# (indicator--, identity--, ...) and custom x-* object types. A *_ref(s)
# property holding anything else is not a fetchable TAXII object id, so
# extract_relationship_refs drops it instead of poisoning a match[id] chunk
# (a single malformed id could make the server reject the whole request).
STIX_ID_PATTERN = re.compile(
    r"^[a-z][a-z0-9-]*--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


# -------------------------
# Logging
# -------------------------


class _StdLogger:
    """Fallback logger exposing the OpenCTI ``connector_logger`` call shape
    (``message, meta=None``) on top of the standard ``logging`` module, so the
    manager can be used outside a connector (e.g. in tests)."""

    def __init__(self) -> None:
        self._logger = logging.getLogger(__name__)

    def _log(self, level: int, message: str, meta: Optional[Dict] = None) -> None:
        self._logger.log(level, f"{message} {meta}" if meta else message)

    def debug(self, message: str, meta: Optional[Dict] = None) -> None:
        self._log(logging.DEBUG, message, meta)

    def info(self, message: str, meta: Optional[Dict] = None) -> None:
        self._log(logging.INFO, message, meta)

    def warning(self, message: str, meta: Optional[Dict] = None) -> None:
        self._log(logging.WARNING, message, meta)

    def error(self, message: str, meta: Optional[Dict] = None) -> None:
        self._log(logging.ERROR, message, meta)


# -------------------------
# Exceptions
# -------------------------


class LuminarAPIError(Exception):
    """Carries an already-formatted Luminar failure up to the caller.

    The message is exactly what lands in the response ``error`` key, i.e. one of

        "HTTP <status>: <API error message>"
        "Network error: <exception message>"
        "Invalid response from Luminar: <exception message>"

    It exists so a failure that survives every retry keeps its status code and
    API message instead of being flattened into a generic HTTPError or, worse,
    silently converted into an empty end-of-stream.
    """


class StaleCursorError(Exception):
    """Raised when a TAXII 'next' cursor has expired.

    Luminar signals this with HTTP 410 Gone:

        {"title": "Expired pagination token",
         "description": "The pagination token has expired. Please restart the
                         query from the beginning.",
         "http_status": "410"}

    The caller should drop the cursor and rebuild the request with
    `added_after` taken from the last successful X-TAXII-Date-Added-Last, so
    pagination restarts from that point instead of from the beginning."""


# -------------------------
# API client + pipeline
# -------------------------


class LuminarManager:
    """Manages interactions with the Cognyte Luminar TAXII API.

    Uses a single `requests.Session` for connection pooling and shared headers.
    The bearer token is stored on `self.session.headers["Authorization"]` after
    a successful auth call, so individual request callers don't need to plumb
    headers through.

    The class also owns the retrieval pipeline built on top of those calls:
    pagination (``fetch_page``), batching (``iter_page_batches``), reference
    resolution (``resolve_and_augment_batch``) and the sliding window
    (``iter_collection_batches``), plus the bounded
    hydrated-object LRU cache they share.
    """

    def __init__(
        self,
        cognyte_client_id: str,
        cognyte_client_secret: str,
        cognyte_account_id: str,
        cognyte_base_url: str,
        added_after: Optional[str] = None,
        limit: int = DEFAULT_LIMIT,
        pages_per_batch: int = PAGES_PER_BATCH,
        match_id_batch_size: int = 100,
        logger: Optional[Any] = None,
    ) -> None:
        # OpenCTI connector_logger (or compatible); never log credentials.
        self.logger = logger or _StdLogger()

        # Strict input validation: bail out early instead of failing mid-pipeline.
        missing = [
            name
            for name, val in [
                ("client_id", cognyte_client_id),
                ("client_secret", cognyte_client_secret),
                ("account_id", cognyte_account_id),
                ("base_url", cognyte_base_url),
            ]
            if not isinstance(val, str) or not val.strip()
        ]
        if missing:
            raise ValueError(
                f"LuminarManager missing required parameters: {', '.join(missing)}"
            )

        # Tuning params must be positive ints (bool excluded: it is an int
        # subclass and would silently pass isinstance(True, int)).
        for name, val in [
            ("limit", limit),
            ("pages_per_batch", pages_per_batch),
            ("match_id_batch_size", match_id_batch_size),
        ]:
            if not isinstance(val, int) or isinstance(val, bool) or val <= 0:
                raise ValueError(f"{name} must be a positive integer, got {val!r}")

        # Default fetch-from anchor; get_objects() may override it per feed.
        if added_after is not None:
            if not isinstance(added_after, str) or not added_after.strip():
                raise ValueError(
                    "added_after must be a non-empty ISO Z timestamp string"
                )
            added_after = added_after.strip()
            try:
                datetime.strptime(added_after, LUMINAR_DATE_FORMAT)
            except ValueError:
                raise ValueError(
                    "added_after must match LUMINAR_DATE_FORMAT "
                    f"({LUMINAR_DATE_FORMAT}), got {added_after!r}"
                )

        # Normalize base_url (drop trailing slashes).
        self.base_url = cognyte_base_url.strip().rstrip("/")
        self.account_id = cognyte_account_id.strip()
        self.client_id = cognyte_client_id.strip()
        self.client_secret = cognyte_client_secret.strip()

        # Pipeline configuration (instance-level defaults).
        self.added_after = added_after
        self.limit = limit
        self.pages_per_batch = pages_per_batch
        self.match_id_batch_size = match_id_batch_size

        self.payload = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "client_credentials",
            "scope": "externalAPI/stix.readonly",
        }

        # Persistent session: connection pooling + central header management.
        # These headers apply to every Luminar API call by default.
        # access_token() overrides Content-Type per-call (x-www-form-urlencoded)
        # because that endpoint expects form-encoded payloads, not JSON.
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": USER_AGENT,
                "Accept": "application/taxii+json;version=2.1, application/json",
                "Content-Type": "application/json",
            }
        )

        self.taxi_collection: Dict[str, str] = {}

        # Last formatted Luminar failure ("HTTP <status>: <message>" or
        # "Network error: <message>"), recorded by _format_api_error(). Methods
        # whose return type cannot express a failure (access_token,
        # get_taxi_collections, get_objects_by_match_id) leave it here so the
        # status and API message are never lost.
        self.last_api_error: Optional[str] = None

        # Bounded least-recently-used cache for hydrated STIX objects, keyed by
        # id. Purpose: avoid re-fetching cross-batch references within the
        # sliding window. References are overwhelmingly local, so the
        # most-recently touched entries carry the live re-reference value.
        # Evicting a still-needed entry is correctness-preserving: it just
        # triggers an idempotent match[id] re-fetch.
        #
        # Access rules, maintained inline by resolve_and_augment_batch:
        #   - ``oid in cache``     membership test; does NOT change recency
        #   - ``cache[oid]``       read after move_to_end; marks most-recently-used
        #   - ``cache[oid] = obj`` insert/update; evicts the least-recently-used
        #                          entry once the cache exceeds the cap
        self.hydrated_objects: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        self.hydrated_objects_max_size = HYDRATED_OBJECTS_MAX_SIZE
        # True when the last resolve_and_augment_batch() call could not
        # complete its match[id] lookups (see "hydration_complete" in results).
        self.last_hydration_failed = False

    # ----- auth -----

    def access_token(self) -> Optional[str]:
        """Obtain an access token using client credentials. Returns the token
        string on success, or None on any failure (reason kept in
        ``self.last_api_error``)."""
        req_url = f"{self.base_url}/externalApi/v2/realm/{self.account_id}/token"
        try:
            self.logger.debug("[LUMINAR] Requesting access token")
            response = self.execute_with_retry(
                lambda: self.session.post(
                    req_url,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    data=self.payload,
                    timeout=TIMEOUT,
                )
            )
            if not response.ok:
                self.logger.error(
                    "[LUMINAR] Error obtaining access token",
                    {"error": self._format_api_error(response)},
                )
                return None
            data = response.json() if response.content else {}
            if not isinstance(data, dict):
                self.last_api_error = (
                    "Invalid response from Luminar: unexpected token payload type "
                    f"{type(data).__name__}"
                )
                self.logger.error(self.last_api_error)
                return None
            token = data.get("access_token")
            if isinstance(token, str) and token:
                return token
            self.last_api_error = (
                "Invalid response from Luminar: token response contained no "
                "access_token"
            )
            self.logger.error(self.last_api_error)
            return None
        except requests.RequestException as err:
            self.last_api_error = f"Network error: {err}"
            self.logger.error(
                "[LUMINAR] Error obtaining access token",
                {"error": self.last_api_error},
            )
            return None
        except (ValueError, KeyError) as err:
            self.last_api_error = f"Invalid response from Luminar: {err}"
            self.logger.error(
                "[LUMINAR] Error obtaining access token",
                {"error": self.last_api_error},
            )
            return None

    def _refresh_token(self) -> bool:
        """Refresh the bearer token and update the session headers in-place.
        Returns True on success."""
        self.logger.info("[LUMINAR] Refreshing access token")
        token = self.access_token()
        if not token:
            return False
        self.session.headers["Authorization"] = f"Bearer {token}"
        return True

    def set_bearer_token(self, token: str) -> None:
        """Install a bearer token on the session."""
        if not isinstance(token, str) or not token:
            raise ValueError("token must be a non-empty string")
        self.session.headers["Authorization"] = f"Bearer {token}"

    # ----- collections -----

    def get_taxi_collections(self) -> Dict[str, str]:
        """Fetch TAXII collection IDs and return a mapping of alias -> collection_id."""
        taxii_collection_ids: Dict[str, str] = {}
        req_url = f"{self.base_url}/externalApi/taxii/collections/"
        try:
            self.logger.debug("[LUMINAR] Fetching TAXII collections")
            response = self.execute_with_retry(
                lambda: self.session.get(req_url, timeout=TIMEOUT)
            )

            # One-shot 401 -> token refresh -> retry
            if response.status_code == 401 and self._refresh_token():
                response = self.execute_with_retry(
                    lambda: self.session.get(req_url, timeout=TIMEOUT)
                )

            if not response.ok:
                self.logger.error(
                    "[LUMINAR] Error fetching collections",
                    {"error": self._format_api_error(response)},
                )
                return taxii_collection_ids

            payload = response.json() if response.content else {}
            if not isinstance(payload, dict):
                self.last_api_error = (
                    "Invalid response from Luminar: unexpected collections payload "
                    f"type {type(payload).__name__}"
                )
                self.logger.error(self.last_api_error)
                return taxii_collection_ids

            collections_data = payload.get("collections", []) or []
            if not isinstance(collections_data, list):
                self.last_api_error = (
                    "Invalid response from Luminar: unexpected 'collections' type "
                    f"{type(collections_data).__name__}"
                )
                self.logger.error(self.last_api_error)
                return taxii_collection_ids

            for collection in collections_data:
                if not isinstance(collection, dict):
                    continue
                alias = collection.get("alias")
                collection_id = collection.get("id")
                if isinstance(alias, str) and isinstance(collection_id, str):
                    taxii_collection_ids[alias] = collection_id
            self.logger.info(
                "[LUMINAR] TAXII collections discovered",
                {"aliases": sorted(taxii_collection_ids)},
            )
        except requests.RequestException as err:
            self.last_api_error = f"Network error: {err}"
            self.logger.error(
                "[LUMINAR] Error fetching collections", {"error": self.last_api_error}
            )
        except (ValueError, KeyError) as err:
            self.last_api_error = f"Invalid response from Luminar: {err}"
            self.logger.error(
                "[LUMINAR] Error fetching collections", {"error": self.last_api_error}
            )
        return taxii_collection_ids

    # ----- objects -----

    def get_objects_by_match_id(
        self,
        collection_id: str,
        object_ids: Sequence[str],
        batch_size: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Fetch objects from a TAXII collection in chunks by match[id]."""
        all_objects: List[Dict[str, Any]] = []
        if not collection_id or not object_ids:
            return all_objects
        if batch_size is None:
            batch_size = self.match_id_batch_size

        url = f"{self.base_url}/externalApi/taxii/collections/{collection_id}/objects/"
        ids_list = list(object_ids)
        self.logger.debug(
            "[LUMINAR] Hydrating referenced objects by match[id]",
            {
                "collection_id": collection_id,
                "ids": len(ids_list),
                "chunk_size": batch_size,
            },
        )

        for i in range(0, len(ids_list), batch_size):
            chunk = ids_list[i : i + batch_size]
            chunk_number = (i // batch_size) + 1
            params = {"match[id]": ",".join(chunk), "limit": len(chunk)}

            try:
                response = self.execute_with_retry(
                    lambda p=params: self.session.get(url, params=p, timeout=TIMEOUT)
                )

                if response.status_code == 401 and self._refresh_token():
                    response = self.execute_with_retry(
                        lambda p=params: self.session.get(
                            url, params=p, timeout=TIMEOUT
                        )
                    )

                if not response.ok:
                    # Not fatal here: other chunks still run. The failure is
                    # surfaced per batch via last_hydration_failed.
                    self.last_hydration_failed = True
                    self.logger.warning(
                        "[LUMINAR] match[id] chunk failed",
                        {
                            "chunk": chunk_number,
                            "error": self._format_api_error(response),
                        },
                    )
                    continue

                data = response.json() if response.content else {}
                if not isinstance(data, dict):
                    self.last_hydration_failed = True
                    self.logger.warning(
                        "[LUMINAR] Unexpected match[id] payload type",
                        {"chunk": chunk_number, "type": type(data).__name__},
                    )
                    continue
                objs = data.get("objects", []) or []
                if isinstance(objs, list):
                    all_objects.extend(o for o in objs if isinstance(o, dict))
            except (requests.RequestException, ValueError, KeyError) as err:
                # Continue with other chunks rather than failing the whole pipeline.
                self.last_hydration_failed = True
                self.logger.warning(
                    "[LUMINAR] match[id] chunk failed",
                    {"chunk": chunk_number, "error": str(err)},
                )
                continue

        return all_objects

    def fetch_page(
        self,
        collection_id: str,
        params: Dict[str, Any],
    ) -> Tuple[List[Dict[str, Any]], Optional[str], Optional[str], Optional[str]]:
        """
        Fetch a single page from the TAXII objects endpoint.

        Returns: (objects, next_token, last_added, first_added)

        Special handling when the request is using a `next` cursor: an expired
        cursor comes back as HTTP 410 Gone ("Expired pagination token"), which
        is terminal for that cursor, so we do NOT retry it. Instead we raise
        StaleCursorError so the caller can rebuild a fresh request using
        `added_after` from the last successful header value.

        A 500 on a cursored request is an ordinary server error, not an expired
        cursor, and is retried like any other retryable status.
        """
        if not collection_id:
            raise ValueError("collection_id is required")
        if not isinstance(params, dict):
            raise ValueError("params must be a dict")

        url = f"{self.base_url}/externalApi/taxii/collections/{collection_id}/objects/"
        using_next = "next" in params and params.get("next")

        try:
            if using_next:
                # No retry on 410 when using a next cursor: the pagination token
                # has expired and will never come back. We DO retry
                # transport-level errors via _get_with_network_retry, with
                # short delays so a recovered request can't blow the cursor TTL.
                response = self._get_with_network_retry(url, params)
                if response.status_code == 410:
                    raise StaleCursorError(self._format_api_error(response))
                if response.status_code == 401:
                    if self._refresh_token():
                        response = self._get_with_network_retry(url, params)
                        if response.status_code == 410:
                            raise StaleCursorError(
                                self._format_api_error(response)
                                + " (after token refresh)"
                            )
                # Retry on retryable codes (429, 500, 502, 503, 504). 410 is not
                # retryable and has already been raised above.
                if response.status_code in RETRYABLE_STATUS_CODES:
                    response = self.execute_with_retry(
                        lambda: self.session.get(url, params=params, timeout=TIMEOUT)
                    )
            else:
                response = self.execute_with_retry(
                    lambda: self.session.get(url, params=params, timeout=TIMEOUT)
                )
                if response.status_code == 401 and self._refresh_token():
                    response = self.execute_with_retry(
                        lambda: self.session.get(url, params=params, timeout=TIMEOUT)
                    )

            if not response.ok:
                # Retries are already exhausted here, so this is the page's
                # final outcome. Keep the status and the API's own message.
                error_text = self._format_api_error(response)
                self.logger.error(
                    "[LUMINAR] Page fetch failed",
                    {
                        "params": self._sanitize_params_for_log(params),
                        "error": error_text,
                    },
                )
                raise LuminarAPIError(error_text)

            payload = response.json() if response.content else {}
            if not isinstance(payload, dict):
                # `objects` and `next` are unreadable, so treating this as an
                # empty page would silently end pagination. Fail loudly instead.
                error_text = (
                    "Invalid response from Luminar: unexpected page payload type "
                    f"{type(payload).__name__}"
                )
                self.last_api_error = error_text
                self.logger.error(error_text)
                raise LuminarAPIError(error_text)

            objs = payload.get("objects", []) or []
            if not isinstance(objs, list):
                self.logger.warning(
                    "[LUMINAR] Unexpected 'objects' type; treating page as empty",
                    {"type": type(objs).__name__},
                )
                objs = []
            objs = [o for o in objs if isinstance(o, dict)]

            next_token = payload.get("next")
            if next_token is not None and not isinstance(next_token, str):
                next_token = str(next_token)

            last_added = response.headers.get("X-TAXII-Date-Added-Last")
            first_added = response.headers.get("X-TAXII-Date-Added-First")
            return objs, next_token, last_added, first_added

        except (StaleCursorError, LuminarAPIError):
            raise
        except requests.RequestException as err:
            # No usable response was received, so there is no HTTP status to
            # report. Never invent one.
            error_text = f"Network error: {err}"
            self.last_api_error = error_text
            self.logger.error(
                "[LUMINAR] Page fetch failed",
                {
                    "params": self._sanitize_params_for_log(params),
                    "error": error_text,
                },
            )
            raise LuminarAPIError(error_text) from err
        except (ValueError, KeyError) as err:
            error_text = f"Invalid response from Luminar: {err}"
            self.last_api_error = error_text
            self.logger.error(
                "[LUMINAR] Page fetch failed",
                {
                    "params": self._sanitize_params_for_log(params),
                    "error": error_text,
                },
            )
            raise LuminarAPIError(error_text) from err

    # ----- retry -----

    def _get_with_network_retry(
        self,
        url: str,
        params: Dict[str, Any],
        retries: int = CURSOR_NETWORK_RETRY_ATTEMPTS,
        delay: int = CURSOR_NETWORK_RETRY_DELAY,
    ) -> requests.Response:
        """
        GET that retries ONLY on transport-layer exceptions
        (requests.RequestException: ConnectionError, Timeout, SSLError,
        ChunkedEncodingError, ...), with short delays.

        This exists for the `next`-cursored page fetch path, where we must not
        route through execute_with_retry: a 410 there means an expired
        pagination token, and execute_with_retry's 60s delay would risk
        expiring an otherwise-valid cursor.

        Status codes are NOT inspected: the returned response is handed back
        as-is for the caller to interpret. Only raised exceptions are retried;
        on final failure the last exception is re-raised.
        """
        last_err: Optional[requests.RequestException] = None
        for attempt in range(1, retries + 1):
            try:
                return self.session.get(url, params=params, timeout=TIMEOUT)
            except requests.RequestException as err:
                last_err = err
                self.logger.warning(
                    "[LUMINAR] Cursored GET raised a network error",
                    {
                        "error_type": err.__class__.__name__,
                        "attempt": attempt,
                        "max_attempts": retries,
                    },
                )
                if attempt < retries:
                    time.sleep(delay)
                    continue
                raise
        # Unreachable when retries >= 1. Explicit guard (not assert, so it
        # survives `python -O`) covers a degenerate retries < 1 call.
        if last_err is not None:
            raise last_err
        raise RuntimeError(
            f"_get_with_network_retry exited without a response (retries={retries})"
        )

    def execute_with_retry(
        self,
        request_call: Callable[[], requests.Response],
        retries: int = RETRY_ATTEMPTS,
        delay: int = RETRY_DELAY,
    ) -> requests.Response:
        """
        Execute a request callable with retry on retryable HTTP statuses and
        on network/transport exceptions.

        - Retries when response.status_code in RETRYABLE_STATUS_CODES.
        - Retries on requests.RequestException (network, timeout, etc.).
        - Sleeps `delay` seconds between attempts.
        - On final failure: returns the last response if any, else re-raises
          the last network exception.

        Always returns a requests.Response or raises; never returns None.

        Note: 410 on a `next`-cursored objects call is handled separately in
        fetch_page (no retry there) because the pagination token is gone.
        """
        last_response: Optional[requests.Response] = None

        for attempt in range(1, retries + 1):
            try:
                response = request_call()
                last_response = response

                if response.status_code in RETRYABLE_STATUS_CODES:
                    if attempt < retries:
                        self.logger.warning(
                            "[LUMINAR] Retryable HTTP status; retrying",
                            {
                                "status": response.status_code,
                                "reason": response.reason,
                                "attempt": attempt,
                                "retry_in_seconds": delay,
                            },
                        )
                        time.sleep(delay)
                        continue
                    self.logger.error(
                        "[LUMINAR] Retryable HTTP status persisted after all attempts",
                        {
                            "status": response.status_code,
                            "reason": response.reason,
                            "attempts": retries,
                        },
                    )
                return response

            except requests.RequestException as err:
                self.logger.warning(
                    "[LUMINAR] Request raised a network error",
                    {
                        "error_type": err.__class__.__name__,
                        "attempt": attempt,
                        "max_attempts": retries,
                    },
                )
                if attempt < retries:
                    time.sleep(delay)
                    continue
                if last_response is not None:
                    return last_response
                raise

        # Unreachable when retries >= 1. Explicit guard (not assert, so it
        # survives `python -O`) covers a degenerate retries < 1 call.
        if last_response is not None:
            return last_response
        raise RuntimeError(
            f"execute_with_retry exited without a response (retries={retries})"
        )

    # ----- helpers -----

    def _sanitize_params_for_log(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Return a copy of request params safe/compact for logging.

        The TAXII `next` cursor is an opaque ~250+ char token that bloats log
        lines and carries no diagnostic value in full. Truncate it to a tail
        preview; leave `limit` / `added_after` intact.
        """
        if not isinstance(params, dict):
            return params
        safe = dict(params)
        nxt = safe.get("next")
        if isinstance(nxt, str) and len(nxt) > 42:
            safe["next"] = f"…{nxt[-42:]}"
        return safe

    def _format_api_error(self, response: requests.Response) -> str:
        """Build "HTTP <status>: <API error message>" from a failed response.

        The response body is inspected first for an API-provided error message;
        if it does not carry one, we fall back to the HTTP reason phrase rather
        than dumping the raw body. The formatted text is also recorded in
        self.last_api_error.
        """
        status = getattr(response, "status_code", None)
        message = ""

        try:
            body = response.json() if response.content else None
        except ValueError:
            body = None

        if isinstance(body, dict):
            for key in (
                "description",
                "title",
            ):
                value = body.get(key)
                if isinstance(value, str) and value.strip():
                    message = value.strip()
                    break

        if not message:
            reason = getattr(response, "reason", None)
            if isinstance(reason, str) and reason.strip():
                message = reason.strip()
            else:
                message = "Unknown error"

        formatted = f"HTTP {status}: {message}"
        self.last_api_error = formatted
        return formatted

    def _subtract_one_second(self, ts: str) -> str:
        """
        Subtract 1 second from an ISO Z timestamp and return in the same format.
        Used to apply a small overlap buffer when rebuilding a stale cursor,
        so we won't miss records due to sub-second boundaries.
        On any parsing failure, returns the original timestamp unchanged.
        """
        if not ts or not isinstance(ts, str):
            return ts
        try:
            dt = datetime.strptime(ts, LUMINAR_DATE_FORMAT) - timedelta(seconds=1)
            return dt.strftime(LUMINAR_DATE_FORMAT)
        except (ValueError, TypeError) as err:
            self.logger.warning(
                "[LUMINAR] Could not subtract 1s from timestamp",
                {"timestamp": ts, "error": str(err)},
            )
            return ts

    def create_lookup_dict(
        self,
        list_of_dicts: List[Dict[str, Any]],
    ) -> Dict[str, Dict[str, Any]]:
        """Create a lookup dictionary from a list of dictionaries, keyed by 'id'."""
        return {d["id"]: d for d in list_of_dicts if "id" in d}

    def extract_relationship_refs(
        self,
        records: List[Dict[str, Any]],
    ) -> Set[str]:
        """Extract unique object references from all STIX reference properties.

        STIX expresses object references through top-level properties ending
        in ``_ref`` (a single id string) or ``_refs`` (a list of id strings):
        ``source_ref``/``target_ref`` on relationships, ``object_refs`` on
        reports/groupings/notes/opinions, ``created_by_ref``,
        ``object_marking_refs``, ``sighting_of_ref``, ``sample_refs``, etc.
        Scanning by suffix covers every standard and custom ref property.
        ``external_references`` is not a ref property (it holds embedded dicts,
        not ids) and does not match either suffix, so it is correctly excluded.
        """
        refs: Set[str] = set()
        dropped: Set[str] = set()
        for r in records:
            if not isinstance(r, dict):
                continue
            for key, value in r.items():
                candidates: List[str] = []
                if key.endswith("_ref") and isinstance(value, str):
                    candidates = [value]
                elif key.endswith("_refs") and isinstance(value, list):
                    candidates = [x for x in value if isinstance(x, str)]
                for ref in candidates:
                    if ref and STIX_ID_PATTERN.match(ref):
                        refs.add(ref)
                    elif ref:
                        dropped.add(ref)

        if dropped:
            self.logger.debug(
                "[LUMINAR] Skipped non-STIX-id ref values (not fetchable via match[id])",
                {"count": len(dropped), "sample": sorted(dropped)[:10]},
            )
        return refs

    # ----- batching -----

    def iter_page_batches(
        self,
        collection_id: str,
        start_added_after: str,
        pages_per_batch: Optional[int] = None,
        limit: Optional[int] = None,
    ) -> Iterator[Tuple[List[Dict[str, Any]], str]]:
        """
        Yields (batch_records, last_added_seen) every `pages_per_batch` pages
        fetched from the TAXII objects endpoint. Any partial trailing batch
        (fewer than `pages_per_batch` pages because the stream ended) is also
        yielded once before the iterator stops.

        Pagination:
          - First call: GET ...objects/?limit=<limit>&added_after=<start_added_after>
          - Subsequent calls: include the `next` cursor returned by the previous page.
          - On every successful page, we record X-TAXII-Date-Added-Last (or fall
            back to X-TAXII-Date-Added-First) as the "checkpoint of last seen".

        Stale `next` cursor recovery:
          - When the `next` cursor expires the server returns HTTP 410 Gone
            ("Expired pagination token"). `fetch_page` raises StaleCursorError.
          - On StaleCursorError we DROP the cursor and rebuild a fresh request
            using `added_after = last_seen_X-TAXII-Date-Added-Last`. We do NOT
            increment the page counter for the failed call — only successful pages
            count toward the batch.
        """
        if not isinstance(start_added_after, str) or not start_added_after:
            raise ValueError("start_added_after must be a non-empty ISO Z timestamp")

        if pages_per_batch is None:
            pages_per_batch = self.pages_per_batch
        if limit is None:
            limit = self.limit

        added_after = start_added_after
        next_token: Optional[str] = None
        last_added_seen: Optional[str] = None

        batch: List[Dict[str, Any]] = []
        pages_in_batch = 0

        # No-progress stall tracking (see MAX_STALE_REBUILDS_WITHOUT_PROGRESS).
        stale_rebuilds_without_progress = 0
        last_added_at_prev_rebuild: Optional[str] = None

        while True:
            params: Dict[str, Any] = {"limit": limit, "added_after": added_after}
            if next_token:
                params["next"] = next_token

            self.logger.debug(
                "[LUMINAR] Fetching page",
                {
                    "page": pages_in_batch + 1,
                    "pages_per_batch": pages_per_batch,
                    "collection_id": collection_id,
                    "next": f"…{next_token[-42:]}" if next_token else None,
                    "added_after": added_after,
                },
            )

            try:
                objs, new_next, last_added, first_added = self.fetch_page(
                    collection_id, params
                )
            except StaleCursorError as err:
                # The next cursor expired (HTTP 410) mid-pagination. Rebuild a
                # fresh `added_after` from the last successful
                # X-TAXII-Date-Added-Last we observed, minus a 1-second safety
                # buffer to avoid any sub-second gap at the boundary. Any
                # duplicates this introduces are deduplicated downstream by id.
                if last_added_seen:
                    rebuild_anchor = self._subtract_one_second(last_added_seen)
                else:
                    # No successful page yet in this iter call; reuse the
                    # caller-provided anchor unchanged.
                    rebuild_anchor = added_after
                self.logger.warning(
                    "[LUMINAR] Stale next cursor; rebuilding request",
                    {
                        "error": str(err),
                        "added_after": rebuild_anchor,
                        "last_added": last_added_seen,
                    },
                )
                added_after = rebuild_anchor
                next_token = None

                # No-progress stall detection: abort only after
                # MAX_STALE_REBUILDS_WITHOUT_PROGRESS consecutive rebuilds in
                # which last_added_seen did not advance.
                if (
                    last_added_seen is not None
                    and last_added_seen != last_added_at_prev_rebuild
                ):
                    stale_rebuilds_without_progress = 0
                else:
                    stale_rebuilds_without_progress += 1
                last_added_at_prev_rebuild = last_added_seen

                if (
                    stale_rebuilds_without_progress
                    >= MAX_STALE_REBUILDS_WITHOUT_PROGRESS
                ):
                    # Emit any partial batch accumulated so far, then report
                    # the abort so the caller sees why iteration stopped.
                    if batch:
                        yield batch, (last_added_seen or added_after)
                    stall_error = (
                        "Stale-cursor recovery made no progress across "
                        f"{stale_rebuilds_without_progress} consecutive rebuilds "
                        f"(last_added={last_added_seen}); "
                        f"last API error: {self.last_api_error}"
                    )
                    self.last_api_error = stall_error
                    self.logger.error(f"[LUMINAR] {stall_error}")
                    raise LuminarAPIError(stall_error)

                # Do not increment pages_in_batch; loop again.
                continue
            except LuminarAPIError as err:
                # Hand back every page successfully fetched before the failure,
                # together with the last X-TAXII-Date-Added header the server
                # actually returned, then re-raise so the error reaches the
                # caller instead of looking like a clean end of stream.
                self.logger.error(
                    "[LUMINAR] Unrecoverable fetch error; stopping iteration",
                    {
                        "error": str(err),
                        "records_kept": len(batch),
                        "checkpoint": last_added_seen or added_after,
                    },
                )
                if batch:
                    yield batch, (last_added_seen or added_after)
                raise

            # Track last-seen header for checkpointing and stale-cursor recovery.
            la_seen = last_added or first_added
            if isinstance(la_seen, str) and la_seen:
                last_added_seen = la_seen

            if objs:
                batch.extend(objs)

            pages_in_batch += 1
            next_token = new_next

            # Yield a full batch whenever we've accumulated pages_per_batch pages.
            if pages_in_batch >= pages_per_batch:
                if batch:
                    yield batch, (last_added_seen or added_after)
                batch = []
                pages_in_batch = 0

            # End of stream: emit trailing partial batch (if any) and stop.
            if not next_token:
                if batch:
                    yield batch, (last_added_seen or added_after)
                self.logger.debug(
                    "[LUMINAR] Stream exhausted", {"collection_id": collection_id}
                )
                break

    # ----- hydration: resolve missing IDs via prev/next, cache, match[id] -----

    def resolve_and_augment_batch(
        self,
        collection_id: str,
        target_batch: List[Dict[str, Any]],
        prev_batch: Optional[List[Dict[str, Any]]],
        next_batch: Optional[List[Dict[str, Any]]],
    ) -> List[Dict[str, Any]]:
        """
        Returns an augmented record list for `target_batch` only:
        - Includes:
            * all objects from target_batch
            * any referenced objects found in prev/next by ID
            * any referenced objects found in the hydrated-object cache
            * any newly hydrated objects fetched via match[id]
            * one further level: objects referenced by the attached objects
        - Sets ``self.last_hydration_failed`` when a match[id] request failed.
        - Does NOT include unreferenced prev/next objects, to avoid pulling in
          other batches' records unintentionally.

        Correctness note (eviction safety):
            Every referenced object needed for THIS batch is first resolved into a
            local dict (`resolved`) that is never subject to eviction. Only after
            the batch is fully resolved do we write those objects into the bounded
            hydrated-object LRU (for cross-batch reuse). This makes correctness
            independent of the LRU's max size.
        """

        # Lookups for quick ID resolution
        target_lookup = self.create_lookup_dict(
            [x for x in target_batch if x.get("id")]
        )
        prev_lookup = self.create_lookup_dict(
            [x for x in (prev_batch or []) if x.get("id")]
        )
        next_lookup = self.create_lookup_dict(
            [x for x in (next_batch or []) if x.get("id")]
        )

        # Reset per batch; set when a match[id] request fails (transport/HTTP),
        # as opposed to an id the server simply does not have.
        self.last_hydration_failed = False

        # Resolve every needed ref into a LOCAL dict before touching the LRU.
        # Two levels: the target batch's refs, then the refs of the objects
        # attached at level one (their author identity, marking definitions,
        # relationship endpoints), so attached objects arrive consistent.
        resolved: Dict[str, Dict[str, Any]] = {}
        pending = self.extract_relationship_refs(target_batch)
        for _level in range(2):
            still_missing: List[str] = []
            newly_resolved: List[Dict[str, Any]] = []
            for oid in pending:
                if oid in target_lookup or oid in resolved:
                    continue
                if oid in prev_lookup:
                    obj = prev_lookup[oid]
                elif oid in next_lookup:
                    obj = next_lookup[oid]
                elif oid in self.hydrated_objects:
                    # Membership above does not reorder; the read below does.
                    self.hydrated_objects.move_to_end(oid)
                    obj = self.hydrated_objects[oid]
                else:
                    still_missing.append(oid)
                    continue
                resolved[oid] = obj
                newly_resolved.append(obj)

            # Hydrate the genuinely-missing refs via match[id].
            if still_missing:
                try:
                    hydrated = self.get_objects_by_match_id(
                        collection_id, still_missing
                    )
                except Exception as err:  # pylint: disable=broad-exception-caught
                    self.last_hydration_failed = True
                    self.logger.warning(
                        "[LUMINAR] Hydration via match[id] failed",
                        {"error": f"{err.__class__.__name__}: {err}"},
                    )
                    hydrated = []
                for obj in hydrated:
                    oid = obj.get("id") if isinstance(obj, dict) else None
                    if oid and oid not in resolved and oid not in target_lookup:
                        resolved[oid] = obj
                        newly_resolved.append(obj)
                unresolved = len(set(still_missing) - set(resolved))
                if unresolved:
                    self.logger.debug(
                        "[LUMINAR] Some referenced objects could not be hydrated",
                        {"collection_id": collection_id, "unresolved": unresolved},
                    )
            pending = self.extract_relationship_refs(newly_resolved)

        # Now update the cross-batch LRU. Eviction here is harmless: everything
        # this batch needs is already held in `resolved`. Eviction runs per
        # insert so the cache never transiently exceeds its cap.
        for oid, obj in resolved.items():
            if oid in self.hydrated_objects:
                self.hydrated_objects.move_to_end(oid)
            self.hydrated_objects[oid] = obj
            while (
                self.hydrated_objects
                and len(self.hydrated_objects) > self.hydrated_objects_max_size
            ):
                self.hydrated_objects.popitem(last=False)

        # Build augmented list: all target records plus every referenced
        # object resolved above (complete, never evicted).
        augmented: List[Dict[str, Any]] = list(target_batch)
        augmented.extend(resolved.values())
        return augmented

    # ----- client-facing feed API -----

    def get_objects(
        self,
        feed_name: str,
        added_after: Optional[str] = None,
    ) -> Iterator[Dict[str, Any]]:
        """Client-facing generator: yield resolved batches for a feed alias.

        `feed_name` is a TAXII collection alias (e.g. "iocs",
        "leakedrecords", "cyberfeeds"). `added_after` overrides the
        instance-level default for this feed only -- pass the persisted
        per-feed checkpoint to resume, or omit to use the constructor value.

        Authentication and collection discovery happen lazily on first use:
        the bearer token is fetched if the session has none, and the
        alias -> collection_id map is fetched once and cached on
        `self.taxi_collection`.

        Yields one dict per resolved batch:

            {
                "results": {
                    "data": [...],          # raw STIX records (+ hydrated refs)
                    "last_success": "...",  # checkpoint for this batch
                    "hydration_complete": bool,  # match[id] lookups succeeded
                },
                "error": None or "<error text>",
            }

        Consume `results["data"]` inside the loop, then persist
        `results["last_success"]` as the feed's resume checkpoint. A non-None
        `error` marks the final yield of a run that failed part-way; batches
        already yielded remain valid.

        Raises ValueError for a blank feed_name, an unknown alias, or a
        missing/malformed added_after; raises LuminarAPIError if the
        initial token request or collection discovery fails.
        """
        if not isinstance(feed_name, str) or not feed_name.strip():
            raise ValueError("feed_name must be a non-empty string")
        feed_name = feed_name.strip()

        # Authenticate lazily: the first call obtains a token; later calls
        # reuse it and mid-run 401s are handled per-request by
        # _refresh_token().
        if "Authorization" not in self.session.headers:
            if not self._refresh_token():
                raise LuminarAPIError(
                    self.last_api_error or "Failed to obtain Luminar access token"
                )

        # Resolve alias -> collection_id, discovering collections once.
        if not self.taxi_collection:
            self.taxi_collection = self.get_taxi_collections()
            if not self.taxi_collection:
                raise LuminarAPIError(
                    self.last_api_error or "No TAXII collections discovered"
                )
        collection_id = self.taxi_collection.get(feed_name)
        if not collection_id:
            raise ValueError(
                f"Unknown feed_name {feed_name!r}; available aliases: "
                f"{sorted(self.taxi_collection)}"
            )

        anchor = added_after or self.added_after
        if not anchor or not isinstance(anchor, str):
            raise ValueError(
                "added_after is required: pass it to get_objects() or set it "
                "on the LuminarManager constructor"
            )
        try:
            datetime.strptime(anchor, LUMINAR_DATE_FORMAT)
        except ValueError:
            raise ValueError(
                "added_after must match LUMINAR_DATE_FORMAT "
                f"({LUMINAR_DATE_FORMAT}), got {anchor!r}"
            )

        yield from self.iter_collection_batches(collection_id, anchor)

    # ----- sliding window engine per collection -----

    def _batch_result(
        self,
        collection_id: str,
        data: List[Dict[str, Any]],
        last_success: Optional[str],
        error: Optional[str],
    ) -> Dict[str, Any]:
        """Build one yield of iter_collection_batches and log it."""
        self.logger.debug(
            "[LUMINAR] Batch ready for processing",
            {
                "collection_id": collection_id,
                "records": len(data),
                "last_success": last_success,
                "error": error,
            },
        )
        return {
            "results": {
                # Copy so the caller owns the list: the local buffers are
                # cleared right after the yield for memory hygiene.
                "data": list(data),
                "last_success": last_success,
                # False when referenced objects could not be fetched because
                # match[id] requests failed; the caller should not advance its
                # checkpoint past this batch.
                "hydration_complete": not self.last_hydration_failed,
            },
            "error": error,
        }

    def iter_collection_batches(
        self,
        collection_id: str,
        added_after: str,
    ) -> Iterator[Dict[str, Any]]:
        """
        Page-wise batching + 3-batch sliding window. GENERATOR: yields one
        result dict per resolved batch.

        Each batch = up to `pages_per_batch` pages from iter_page_batches.
        Sliding window holds at most 3 such batches: [prev, center, next].

        Startup:    resolve B1 using B2 + B3 as ref-lookup context.
        Steady:     resolve the center batch using prev + next as context,
                    then drop prev, shift the window, fetch a new next batch.
        Tail (>3):  on StopIteration after steady, resolve the final center
                    batch using the previous (already yielded) batch as
                    reference context -- prev must NOT be merged back in or
                    its records would be delivered twice.
        Small (<=3): if iter exhausted during preload, merge all and resolve once.

        `last_success` is the X-TAXII-Date-Added-Last of the batch just
        resolved (NOT the latest fetched batch); persist it after consuming
        `data` to resume from it on the next run. A non-None `error` marks the
        final yield of a run that failed part-way; batches already yielded
        remain valid.
        """
        # Reset the cross-batch hydration cache at the start of every
        # collection: entries from a previous collection have no re-reference
        # value here and would only occupy LRU slots.
        self.hydrated_objects.clear()
        self.last_api_error = None

        api_error: Optional[str] = None

        try:
            page_iter = self.iter_page_batches(collection_id, added_after)
        except ValueError as err:
            self.logger.error(
                "[LUMINAR] Cannot start iteration",
                {"collection_id": collection_id, "error": str(err)},
            )
            yield self._batch_result(collection_id, [], None, str(err))
            return

        batches: List[List[Dict[str, Any]]] = []
        batch_last_addeds: List[str] = []
        exhausted = False

        # Preload up to 3 batches
        for _ in range(3):
            try:
                batch, last_added_to_save = next(page_iter)
                batches.append(batch)
                batch_last_addeds.append(last_added_to_save)
                self.logger.debug(
                    "[LUMINAR] Fetched batch",
                    {
                        "batch": len(batches),
                        "collection_id": collection_id,
                        "records": len(batch),
                        "last_added": last_added_to_save,
                    },
                )
            except StopIteration:
                exhausted = True
                break
            except Exception as err:  # pylint: disable=broad-exception-caught
                api_error = (
                    str(err)
                    if isinstance(err, LuminarAPIError)
                    else f"{err.__class__.__name__}: {err}"
                )
                self.logger.error(
                    "[LUMINAR] Error fetching batch during preload",
                    {"collection_id": collection_id, "error": api_error},
                )
                # Fetching is over for this run, so fall through to the
                # merge-and-resolve path and deliver whatever was already
                # retrieved rather than losing it.
                exhausted = True
                break

        if not batches:
            self.logger.debug(
                "[LUMINAR] No batches to process", {"collection_id": collection_id}
            )
            if api_error:
                # Surface the preload failure on the error channel instead of
                # ending the generator silently.
                yield self._batch_result(collection_id, [], None, api_error)
            return

        # Small dataset (<=3 batches total) and fetching complete
        if exhausted:
            merged: List[Dict[str, Any]] = []
            for b in batches:
                merged.extend(b)
            augmented = self.resolve_and_augment_batch(
                collection_id, merged, None, None
            )
            yield self._batch_result(
                collection_id, augmented, batch_last_addeds[-1], api_error
            )
            augmented.clear()
            merged.clear()
            batches.clear()
            return

        # We have exactly 3 batches loaded and more may be available.
        B1, B2, B3 = batches[0], batches[1], batches[2]

        # Phase A: Startup (resolve B1 using B2 + B3 as context)
        augmented_b1 = self.resolve_and_augment_batch(collection_id, B1, None, B2 + B3)
        yield self._batch_result(
            collection_id, augmented_b1, batch_last_addeds[0], None
        )
        augmented_b1.clear()
        # Keep B1 in memory; B2 will need it as prev context.

        # Steady-state
        prev_batch = B1
        center_batch = B2
        next_batch = B3
        center_idx = 1  # index into batch_last_addeds for the current center

        while True:
            # Phase B: resolve center batch using prev and next
            augmented_center = self.resolve_and_augment_batch(
                collection_id,
                center_batch,
                prev_batch,
                next_batch,
            )
            yield self._batch_result(
                collection_id, augmented_center, batch_last_addeds[center_idx], None
            )
            augmented_center.clear()

            # Drop prev batch from memory now that we no longer need it.
            prev_batch.clear()

            # Shift window: prev <- center, center <- next, next <- fetched
            prev_batch = center_batch
            center_batch = next_batch
            center_idx += 1

            # Fetch next batch
            try:
                new_batch, new_last_added = next(page_iter)
                next_batch = new_batch
                batch_last_addeds.append(new_last_added)
                self.logger.debug(
                    "[LUMINAR] Fetched next batch",
                    {
                        "collection_id": collection_id,
                        "records": len(next_batch),
                        "last_added": new_last_added,
                    },
                )
            except StopIteration:
                # Tail end: prev_batch was already delivered as the previous
                # CENTER; only center_batch is still unprocessed. Resolve it
                # with prev as reference context.
                augmented_tail = self.resolve_and_augment_batch(
                    collection_id,
                    center_batch,
                    prev_batch,
                    None,
                )
                yield self._batch_result(
                    collection_id, augmented_tail, batch_last_addeds[-1], None
                )
                augmented_tail.clear()
                prev_batch.clear()
                center_batch.clear()
                break
            except Exception as err:  # pylint: disable=broad-exception-caught
                api_error = (
                    str(err)
                    if isinstance(err, LuminarAPIError)
                    else f"{err.__class__.__name__}: {err}"
                )
                self.logger.error(
                    "[LUMINAR] Error fetching next batch; flushing what we have",
                    {"collection_id": collection_id, "error": api_error},
                )
                # Don't lose what's already in memory: resolve the still
                # unprocessed center_batch with prev as context (prev was
                # already yielded, so merging it back in would duplicate
                # its records).
                try:
                    augmented_tail = self.resolve_and_augment_batch(
                        collection_id,
                        center_batch,
                        prev_batch,
                        None,
                    )
                except Exception as inner:  # pylint: disable=broad-exception-caught
                    self.logger.error(
                        "[LUMINAR] Failed to resolve tail batch after fetch error",
                        {
                            "collection_id": collection_id,
                            "error": f"{inner.__class__.__name__}: {inner}",
                        },
                    )
                    # Still report the original fetch failure to the caller.
                    yield self._batch_result(collection_id, [], None, api_error)
                    break
                yield self._batch_result(
                    collection_id, augmented_tail, batch_last_addeds[-1], api_error
                )
                augmented_tail.clear()
                break
