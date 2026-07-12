import hashlib
import json
import time
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Any
from urllib.parse import quote

import requests
from pycti import OpenCTIConnectorHelper


class RansomLookAPIError(RuntimeError):
    """Represent a normalized failure while querying the RansomLook API."""


class RansomLookCycleBudgetExhausted(RuntimeError):
    """Stop a run when its aggregate request count or deadline is exhausted."""


class RansomLookPostWindowTooLarge(RansomLookAPIError):
    """Indicate that one date range must be subdivided or deferred."""


@dataclass(frozen=True)
class DeferredPostWindow:
    """One unpageable post range retained for bounded later retry."""

    start: str
    end: str
    reason: str


@dataclass(frozen=True)
class PostBatch:
    """Accepted posts plus source windows that could not be consumed safely."""

    posts: list[dict[str, Any]]
    deferred_windows: list[DeferredPostWindow]

    def __iter__(self):
        return iter(self.posts)

    def __len__(self) -> int:
        return len(self.posts)

    def __getitem__(self, index):
        return self.posts[index]

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, list):
            return self.posts == other and not self.deferred_windows
        if isinstance(other, PostBatch):
            return (
                self.posts == other.posts
                and self.deferred_windows == other.deferred_windows
            )
        return NotImplemented


class RansomLookCapabilityUnavailable(RansomLookAPIError):
    """Indicate that an optional upstream capability cannot be consumed."""

    def __init__(self, capability: str, status_code: int | None = None) -> None:
        self.capability = capability
        self.status_code = status_code
        detail = f" (HTTP {status_code})" if status_code is not None else ""
        super().__init__(f"RansomLook capability '{capability}' is unavailable{detail}")


class RansomLookAPIClient:
    """Query and validate the documented public RansomLook REST API.

    Endpoint contracts are based on the public Swagger document exposed at
    ``/swagger.json``. Responses stay bounded before JSON decoding, and each
    collection adapter applies a record limit as a second independent bound.
    """

    _POST_WINDOW_DAYS = 7
    _READ_CHUNK_SIZE = 64 * 1024
    _TORRENT_PAGE_SIZE = 200
    _TRANSIENT_STATUS = (429, 500, 502, 503, 504)
    _MAX_ATTEMPTS = 5

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        base_url: str,
        api_key: str | None = None,
        max_response_size_mb: int = 32,
        max_records: int = 1000,
        max_pages: int = 10,
        max_requests_per_run: int = 2000,
        max_run_duration_seconds: int = 2700,
    ) -> None:
        if max_response_size_mb < 1:
            raise ValueError("max_response_size_mb must be at least 1")
        if max_records < 1:
            raise ValueError("max_records must be at least 1")
        if max_pages < 1:
            raise ValueError("max_pages must be at least 1")
        if max_requests_per_run < 1:
            raise ValueError("max_requests_per_run must be at least 1")
        if max_run_duration_seconds < 1:
            raise ValueError("max_run_duration_seconds must be at least 1")
        self.helper = helper
        self.base_url = base_url.rstrip("/")
        self.max_response_bytes = max_response_size_mb * 1024 * 1024
        self.max_records = max_records
        self.max_pages = max_pages
        self.max_requests_per_run = max_requests_per_run
        self.max_run_duration_seconds = max_run_duration_seconds
        self.session = requests.Session()
        self.request_attempts = 0
        self.run_started = time.monotonic()
        self.run_deadline = self.run_started + self.max_run_duration_seconds
        self.session.headers.update(
            {
                "Accept": "application/json",
                "User-Agent": (
                    "OpenCTI-Connector-RansomLook/7.260710.0 "
                    "(+https://github.com/OpenCTI-Platform/connectors)"
                ),
            }
        )
        if api_key:
            self.session.headers["Authorization"] = api_key

    def begin_run(self) -> None:
        """Reset the physical-request counter and shared monotonic deadline."""
        self.request_attempts = 0
        self.run_started = time.monotonic()
        self.run_deadline = self.run_started + self.max_run_duration_seconds

    @property
    def remaining_requests(self) -> int:
        """Return the remaining physical-request attempts for this run."""
        return max(0, self.max_requests_per_run - self.request_attempts)

    def remaining_seconds(self) -> float:
        """Return remaining run time or raise the distinct terminal signal."""
        remaining = self.run_deadline - time.monotonic()
        if remaining <= 0:
            raise RansomLookCycleBudgetExhausted(
                "RansomLook run duration budget exhausted"
            )
        return remaining

    def _consume_attempt(self) -> float:
        remaining = self.remaining_seconds()
        if self.request_attempts >= self.max_requests_per_run:
            raise RansomLookCycleBudgetExhausted(
                "RansomLook request-attempt budget exhausted"
            )
        self.request_attempts += 1
        return remaining

    def _get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        allow_404: bool = False,
        log_errors: bool = True,
        optional_capability: str | None = None,
    ) -> Any:
        """Perform one bounded GET and decode its JSON response."""
        url = f"{self.base_url}/{path.lstrip('/')}"
        response: requests.Response | None = None
        last_error: BaseException | None = None
        try:
            for attempt in range(self._MAX_ATTEMPTS):
                remaining = self._consume_attempt()
                response = None
                try:
                    response = self.session.get(
                        url,
                        params=params,
                        timeout=(min(10.0, remaining), min(60.0, remaining)),
                        stream=True,
                    )
                    if allow_404 and response.status_code == 404:
                        return []
                    if optional_capability and response.status_code in (401, 403, 404):
                        raise RansomLookCapabilityUnavailable(
                            optional_capability, response.status_code
                        )
                    response.raise_for_status()
                    return self._decode_json(response)
                except RansomLookCapabilityUnavailable:
                    raise
                except RansomLookCycleBudgetExhausted:
                    raise
                except (requests.RequestException, TypeError, ValueError) as exc:
                    last_error = exc
                    retryable_status = (
                        response is not None
                        and response.status_code in self._TRANSIENT_STATUS
                    )
                    if attempt + 1 >= self._MAX_ATTEMPTS or (
                        response is not None and not retryable_status
                    ):
                        raise
                    retry_after = 0.0
                    if response is not None:
                        try:
                            retry_after = float(response.headers.get("Retry-After", 0))
                        except (TypeError, ValueError):
                            retry_after = 0.0
                    delay = max(retry_after, float(2**attempt))
                    remaining = self.remaining_seconds()
                    if delay >= remaining:
                        raise RansomLookCycleBudgetExhausted(
                            "RansomLook retry delay exceeds the run deadline"
                        ) from exc
                    time.sleep(delay)
                finally:
                    if response is not None:
                        response.close()
                        response = None
            raise RansomLookAPIError(
                f"Unable to query RansomLook endpoint '{path}'"
            ) from last_error
        except RansomLookCapabilityUnavailable:
            raise
        except RansomLookCycleBudgetExhausted:
            raise
        except RansomLookAPIError as exc:
            if log_errors:
                self.helper.connector_logger.error(
                    "RansomLook API response rejected",
                    {
                        "endpoint_sha256": hashlib.sha256(path.encode()).hexdigest()[
                            :16
                        ],
                        "error_type": type(exc).__name__,
                    },
                )
            raise
        except (requests.RequestException, TypeError, ValueError) as exc:
            if log_errors:
                self.helper.connector_logger.error(
                    "RansomLook API request failed",
                    {
                        "endpoint_sha256": hashlib.sha256(path.encode()).hexdigest()[
                            :16
                        ],
                        "error_type": type(exc).__name__,
                    },
                )
            raise RansomLookAPIError(
                f"Unable to query RansomLook endpoint '{path}'"
            ) from exc
        finally:
            if response is not None:
                response.close()

    def _decode_json(self, response: requests.Response) -> Any:
        """Read and decode one size-bounded JSON response without payload logging."""
        content_length = response.headers.get("Content-Length")
        if content_length is not None:
            try:
                declared_size = int(content_length)
            except ValueError as exc:
                raise RansomLookAPIError(
                    "RansomLook returned an invalid Content-Length header"
                ) from exc
            if declared_size < 0:
                raise RansomLookAPIError(
                    "RansomLook returned an invalid Content-Length header"
                )
            if declared_size > self.max_response_bytes:
                raise RansomLookAPIError(
                    "RansomLook response exceeds the configured size limit"
                )

        payload = bytearray()
        for chunk in response.iter_content(chunk_size=self._READ_CHUNK_SIZE):
            self.remaining_seconds()
            if not chunk:
                continue
            payload.extend(chunk)
            if len(payload) > self.max_response_bytes:
                raise RansomLookAPIError(
                    "RansomLook response exceeds the configured size limit"
                )
        try:
            return json.loads(payload)
        except (UnicodeDecodeError, ValueError, RecursionError) as exc:
            raise RansomLookAPIError("RansomLook returned invalid JSON") from exc

    def _dict_list(self, data: Any, endpoint: str) -> list[dict[str, Any]]:
        if not isinstance(data, list) or not all(
            isinstance(item, dict) for item in data
        ):
            raise RansomLookAPIError(
                f"Unexpected response from RansomLook {endpoint} endpoint"
            )
        if len(data) > self.max_records:
            error = f"RansomLook {endpoint} response exceeds the record limit"
            if endpoint == "posts":
                raise RansomLookPostWindowTooLarge(error)
            raise RansomLookAPIError(error)
        return data

    @staticmethod
    def _dict(data: Any, endpoint: str) -> dict[str, Any]:
        if not isinstance(data, dict):
            raise RansomLookAPIError(
                f"Unexpected response from RansomLook {endpoint} endpoint"
            )
        return data

    def _evidence_record(self, data: dict[str, Any], endpoint: str) -> dict[str, Any]:
        """Validate capture carriers while retaining their bounded encoded value.

        Actual base64/MIME/decoded-size validation belongs to the evidence layer.
        Here the encoded capture is allowed only as a scalar string and can never
        exceed the already-enforced response byte limit.
        """
        for field in ("screen", "source"):
            value = data.get(field)
            if value is not None and not isinstance(value, str):
                raise RansomLookAPIError(
                    f"Unexpected {field} field in RansomLook {endpoint} response"
                )
            if isinstance(value, str) and len(value) > self.max_response_bytes:
                raise RansomLookAPIError(
                    f"RansomLook {endpoint} capture exceeds the response size limit"
                )
        return data

    def get_posts(
        self,
        start: datetime,
        end: datetime,
        record_budget: int | None = None,
    ) -> PostBatch:
        """Return posts, recursively subdividing and deferring oversized ranges."""
        if start > end:
            raise RansomLookAPIError("RansomLook post window start is after its end")
        collection_limit = self.max_records
        if record_budget is not None:
            if record_budget < 0:
                raise ValueError("record_budget cannot be negative")
            collection_limit = min(collection_limit, record_budget)

        posts: list[dict[str, Any]] = []
        deferred: list[DeferredPostWindow] = []
        if collection_limit == 0:
            return PostBatch(
                [],
                [
                    DeferredPostWindow(
                        start.date().isoformat(),
                        end.date().isoformat(),
                        "post collection record budget exhausted",
                    )
                ],
            )
        subdivisions = 0

        def fetch_range(window_start: date, window_end: date) -> None:
            nonlocal posts, subdivisions
            if subdivisions >= self.max_pages:
                deferred.append(
                    DeferredPostWindow(
                        window_start.isoformat(),
                        window_end.isoformat(),
                        "post subdivision budget exhausted",
                    )
                )
                return
            subdivisions += 1
            try:
                data = self._get(
                    "posts",
                    params={
                        "from": window_start.isoformat(),
                        "to": window_end.isoformat(),
                    },
                )
                if isinstance(data, dict):
                    data = data.get("posts")
                chunk = self._dict_list(data, "posts")
                validated = [self._evidence_record(post, "posts") for post in chunk]
                candidate_posts = self._deduplicate_posts([*posts, *validated])
                if len(candidate_posts) > collection_limit:
                    raise RansomLookPostWindowTooLarge(
                        "RansomLook posts collection exceeds the cycle record limit"
                    )
            except RansomLookCycleBudgetExhausted:
                raise
            except (RansomLookPostWindowTooLarge, RansomLookAPIError) as exc:
                oversize = isinstance(exc, RansomLookPostWindowTooLarge) or any(
                    marker in str(exc) for marker in ("size limit", "record limit")
                )
                if not oversize:
                    raise
                if window_start >= window_end:
                    deferred.append(
                        DeferredPostWindow(
                            window_start.isoformat(),
                            window_end.isoformat(),
                            type(exc).__name__,
                        )
                    )
                    return
                span = (window_end - window_start).days
                midpoint = window_start + timedelta(days=span // 2)
                fetch_range(window_start, midpoint)
                fetch_range(midpoint + timedelta(days=1), window_end)
                return
            posts = candidate_posts

        window_start = start.date()
        end_date = end.date()
        while window_start <= end_date:
            window_end = min(
                window_start + timedelta(days=self._POST_WINDOW_DAYS - 1), end_date
            )
            fetch_range(window_start, window_end)
            window_start = window_end + timedelta(days=1)
        return PostBatch(self._deduplicate_posts(posts), deferred)

    def get_group(self, name: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """Return group metadata and its bounded post history."""
        data = self._get(
            f"group/{quote(name, safe='')}", allow_404=True, log_errors=False
        )
        if data == []:
            return {}, []
        if not isinstance(data, list) or len(data) < 2:
            raise RansomLookAPIError(
                "Unexpected response from RansomLook group endpoint"
            )
        group = self._dict(data[0], "group")
        posts = self._dict_list(data[1], "group posts")
        locations = group.get("locations", [])
        if not isinstance(locations, list) or not all(
            isinstance(location, dict) for location in locations
        ):
            raise RansomLookAPIError(
                "Unexpected locations field in RansomLook group response"
            )
        if len(locations) > self.max_records:
            raise RansomLookAPIError(
                "RansomLook group locations exceed the record limit"
            )
        group["locations"] = [
            self._evidence_record(location, "group location") for location in locations
        ]
        return group, [self._evidence_record(post, "group post") for post in posts]

    def get_group_locations(self, name: str) -> list[dict[str, Any]]:
        """Return validated actor-profile locations for one group."""
        group, _ = self.get_group(name)
        return group.get("locations", [])

    def get_post(self, group: str, title: str) -> dict[str, Any]:
        """Return one detailed claim, including bounded capture carriers."""
        path = f"post/{quote(group, safe='')}/{quote(title, safe='')}"
        data = self._get(path, allow_404=True, log_errors=False)
        if data == []:
            return {}
        if isinstance(data, list):
            if len(data) != 1 or not isinstance(data[0], dict):
                raise RansomLookAPIError(
                    "Unexpected response from RansomLook post endpoint"
                )
            data = data[0]
        return self._evidence_record(self._dict(data, "post"), "post")

    def get_actors(self) -> list[dict[str, Any]]:
        """Return the bounded public actor summary collection."""
        data = self._get("actors/", log_errors=False, optional_capability="actors")
        return self._dict_list(data, "actors")

    def get_actor(self, name: str) -> dict[str, Any]:
        """Return one public named-actor profile."""
        data = self._get(
            f"actors/{quote(name, safe='')}",
            log_errors=False,
            optional_capability="actors",
        )
        return self._dict(data, "actor")

    def get_group_notes(self, name: str) -> list[dict[str, Any]]:
        """Return bounded ransom-note summaries associated with a group."""
        data = self._get(
            f"notes/group/{quote(name, safe='')}",
            log_errors=False,
            optional_capability="notes",
        )
        return self._dict_list(data, "notes")

    def get_note(self, note_id: str) -> dict[str, Any]:
        data = self._get(
            f"notes/{quote(note_id, safe='')}",
            log_errors=False,
            optional_capability="notes",
        )
        return self._dict(data, "note")

    def get_group_crypto(self, name: str) -> dict[str, Any]:
        """Return chain-grouped wallets for one group, enforcing a total cap."""
        data = self._get(
            f"crypto/{quote(name, safe='')}",
            log_errors=False,
            optional_capability="crypto",
        )
        result = self._dict(data, "crypto")
        by_chain = result.get("by_chain")
        if not isinstance(by_chain, dict):
            raise RansomLookAPIError(
                "Unexpected by_chain field in RansomLook crypto response"
            )
        count = 0
        for wallets in by_chain.values():
            count += len(self._dict_list(wallets, "crypto wallets"))
        if count > self.max_records:
            raise RansomLookAPIError(
                "RansomLook crypto response exceeds the record limit"
            )
        return result

    def get_torrents(self, group: str | None = None) -> list[dict[str, Any]]:
        """Return bounded torrent-health metadata through documented pagination."""
        records: list[dict[str, Any]] = []
        for page in range(1, self.max_pages + 1):
            params: dict[str, Any] = {
                "page": page,
                "per_page": min(self._TORRENT_PAGE_SIZE, self.max_records),
            }
            if group:
                params["q"] = group
            data = self._get(
                "torrent/health",
                params=params,
                log_errors=False,
                optional_capability="torrents",
            )
            envelope = self._dict(data, "torrent")
            results = self._dict_list(envelope.get("results"), "torrent results")
            if len(records) + len(results) > self.max_records:
                records.extend(results[: self.max_records - len(records)])
                break
            records.extend(results)
            total = envelope.get("total")
            if not isinstance(total, int) or total < 0:
                raise RansomLookAPIError(
                    "Unexpected total field in RansomLook torrent response"
                )
            if len(records) >= self.max_records or len(records) >= total or not results:
                break
        return records

    def get_leaks(self) -> list[dict[str, Any]]:
        """Return the bounded public data-leak summary collection."""
        data = self._get("leaks/leaks", log_errors=False, optional_capability="leaks")
        # This documented endpoint is currently an unpageable full corpus. If
        # it exceeds the configured bound, treat that as an unavailable
        # optional capability rather than keeping every encountered group in a
        # permanent retry loop.
        if isinstance(data, list) and len(data) > self.max_records:
            raise RansomLookCapabilityUnavailable("leaks")
        return self._dict_list(data, "leaks")

    def get_leak(self, leak_id: str | int) -> dict[str, Any]:
        data = self._get(
            f"leaks/leaks/{quote(str(leak_id), safe='')}",
            log_errors=False,
            optional_capability="leaks",
        )
        return self._dict(data, "leak")

    @staticmethod
    def get_group_analyses(name: str) -> list[dict[str, Any]]:
        """Report the absent JSON analysis capability without guessing a route."""
        del name
        raise RansomLookCapabilityUnavailable("analyses")

    @staticmethod
    def _deduplicate_posts(posts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Deduplicate valid index records; retain malformed identities for caller skips."""
        result: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()
        for post in posts:
            group_name = post.get("group_name")
            post_title = post.get("post_title")
            discovered = post.get("discovered")
            if not all(
                isinstance(item, str) for item in (group_name, post_title, discovered)
            ):
                result.append(post)
                continue
            identity = (group_name, post_title, discovered)
            if identity in seen:
                continue
            seen.add(identity)
            result.append(post)
        return result
