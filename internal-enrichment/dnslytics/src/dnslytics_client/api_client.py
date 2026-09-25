import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone

import requests
from pycti import OpenCTIConnectorHelper

DATASET_DOMAINS_CREDITS = 10
IP2ASN_BASE_URL = "https://freeapi.dnslytics.net"
IP2ASN_DAILY_CAP = 2500
REQUESTS_PER_MINUTE = 30
RETRYABLE_STATUS_CODES = (429, 503)
RETRY_DELAYS_SECONDS = (5, 15)
TIMEOUT_SECONDS = 30


class DnslyticsApiError(Exception):
    """DNSlytics answered `{"status": "error", "data": "<reason>"}` or an HTTP error."""

    def __init__(self, reason: str, status_code: int | None = None):
        super().__init__(reason)
        self.reason = reason
        self.status_code = status_code

    def __str__(self) -> str:
        if self.status_code is None:
            return f"DNSlytics error: {self.reason}"
        return f"DNSlytics error (HTTP {self.status_code}): {self.reason}"


@dataclass
class DomainHit:
    domain: str
    active: bool


@dataclass
class DomainSearchResult:
    ndomains: int
    domains: list[DomainHit] = field(default_factory=list)


@dataclass
class AsInfo:
    number: int
    name: str | None


class RateLimiter:
    """Sliding-window limiter: at most `max_calls` calls per `period` seconds."""

    def __init__(self, max_calls: int, period: float = 60.0, clock=time.monotonic):
        self.max_calls = max_calls
        self.period = period
        self._clock = clock
        self._calls: deque[float] = deque()
        self._lock = threading.Lock()

    def wait(self) -> None:
        with self._lock:
            now = self._clock()
            while self._calls and now - self._calls[0] >= self.period:
                self._calls.popleft()
            if len(self._calls) >= self.max_calls:
                time.sleep(self.period - (now - self._calls[0]))
                self._calls.popleft()
            self._calls.append(self._clock())


class DnslyticsClient:
    """
    Client for the two DNSlytics endpoints used by the connector:
    - `GET {api_base_url}/v2/dataset/domains` (premium, 10 credits per call)
    - `GET https://freeapi.dnslytics.net/v1/ip2asn/<ip>` (free, 2,500 calls/day)
    and the free `v1/accountinfo` endpoint, used to check a key without spending credits.
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        api_base_url: str,
        api_key: str,
        ip2asn_base_url: str = IP2ASN_BASE_URL,
        session: requests.Session | None = None,
        sleep=time.sleep,
    ):
        self.helper = helper
        self.api_base_url = str(api_base_url).rstrip("/")
        self.ip2asn_base_url = ip2asn_base_url.rstrip("/")
        self._api_key = api_key
        self.session = session or requests.Session()
        self._sleep = sleep
        self._limiter = RateLimiter(REQUESTS_PER_MINUTE)
        self._ip2asn_day = None
        self._ip2asn_calls = 0
        self._ip2asn_lock = threading.Lock()

    def _get(self, url: str, params: dict | None = None) -> dict:
        """
        GET `url` and return the decoded JSON body.
        429 and 503 are retried with a delay; 403 and any other error are raised at once.
        """
        attempts = len(RETRY_DELAYS_SECONDS) + 1
        for attempt in range(attempts):
            self._limiter.wait()
            try:
                response = self.session.get(url, params=params, timeout=TIMEOUT_SECONDS)
            except requests.RequestException as err:
                # The message can contain the full URL, API key included
                message = str(err)
                if self._api_key:
                    message = message.replace(self._api_key, "***")
                raise DnslyticsApiError(message) from None
            self.helper.connector_logger.debug(
                "[API] HTTP GET", {"url_path": url, "status": response.status_code}
            )
            if (
                response.status_code in RETRYABLE_STATUS_CODES
                and attempt < attempts - 1
            ):
                delay = RETRY_DELAYS_SECONDS[attempt]
                self.helper.connector_logger.warning(
                    "[API] DNSlytics is throttling or unavailable, retrying",
                    {"status": response.status_code, "delay_seconds": delay},
                )
                self._sleep(delay)
                continue
            return self._decode(response)
        raise AssertionError("unreachable")

    @staticmethod
    def _decode(response: requests.Response) -> dict:
        try:
            body = response.json()
        except ValueError:
            body = None
        if isinstance(body, dict) and body.get("status") == "error":
            raise DnslyticsApiError(str(body.get("data")), response.status_code)
        if not response.ok:
            raise DnslyticsApiError(
                response.reason or "HTTP error", response.status_code
            )
        if not isinstance(body, dict):
            raise DnslyticsApiError(
                "Response is not a JSON object", response.status_code
            )
        return body

    def search_domains(self, query: str, page: int = 1) -> DomainSearchResult:
        """
        Run a query on the domains dataset. Costs 10 credits.
        The query is sent verbatim; `requests` URL-encodes it.
        """
        body = self._get(
            f"{self.api_base_url}/v2/dataset/domains",
            params={"q": query, "page": page, "apikey": self._api_key},
        )
        data = body.get("data") or {}
        hits = [
            DomainHit(domain=item["domain"], active=bool(item.get("active")))
            for item in data.get("domains") or []
            if item.get("domain")
        ]
        return DomainSearchResult(
            ndomains=int(data.get("ndomains", len(hits))), domains=hits
        )

    def ip2asn(self, ip: str) -> AsInfo | None:
        """
        Return the AS announcing `ip`, or None if the IP is not announced. Free.
        Raises when the client-side count reaches the 2,500 calls/day cap.
        """
        with self._ip2asn_lock:
            today = datetime.now(timezone.utc).date()
            if self._ip2asn_day != today:
                self._ip2asn_day = today
                self._ip2asn_calls = 0
            if self._ip2asn_calls >= IP2ASN_DAILY_CAP:
                raise DnslyticsApiError(
                    f"IP2ASN daily cap of {IP2ASN_DAILY_CAP} calls reached"
                )
            self._ip2asn_calls += 1
        body = self._get(f"{self.ip2asn_base_url}/v1/ip2asn/{ip}")
        if not body.get("announced") or body.get("asn") is None:
            return None
        name = body.get("shortname")
        return AsInfo(
            number=int(body["asn"]),
            name=name.strip() if isinstance(name, str) and name.strip() else None,
        )

    def account_info(self) -> dict:
        """Return `apicredits`, `apilimits` and `apicalls` for the key. Free."""
        body = self._get(
            f"{self.api_base_url}/v1/accountinfo", params={"apikey": self._api_key}
        )
        return body.get("data") or {}
