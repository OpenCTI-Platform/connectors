import io
import ipaddress
import logging
import socket
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse, urlsplit, urlunsplit

import requests
from dateutil import parser as dateutil_parser
from polyswarm_enrichment.polyswarm_client import PolyswarmAPI, polyswarm_exceptions
from polyswarm_enrichment.quota import is_quota_exhausted_error

# OpenCTI entity types enriched by URL search (and IOC search for IPs/domains)
NETWORK_OBSERVABLE_TYPES = ("Url", "Domain-Name", "IPv4-Addr", "IPv6-Addr")

# Suffixes of names that only resolve inside a private network
_INTERNAL_DOMAIN_SUFFIXES = (
    ".local",
    ".internal",
    ".lan",
    ".corp",
    ".home.arpa",
    ".localhost",
)


def _is_private_or_noise(ip_str: str) -> bool:
    """Filter out private, multicast, loopback, link-local IPs."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return (
            addr.is_private
            or addr.is_multicast
            or addr.is_loopback
            or addr.is_link_local
        )
    except ValueError:
        return False


# RFC 6598 shared address space (carrier-grade NAT), not globally routable
_SHARED_ADDRESS_SPACE = ipaddress.ip_network("100.64.0.0/10")

# Characters of a legacy numeric IPv4 form (127.1, 0x7f.0.0.1, 2130706433)
_LEGACY_IPV4_CHARS = frozenset("0123456789abcdefx.")


def _is_non_public_ip(ip_str: str) -> bool:
    """Private or noise IPs, plus reserved, shared and unspecified, or not an IP."""
    value = ip_str.strip()
    # Exactly one pair of brackets ([2001:db8::1]); anything else is malformed
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        # CIDR ranges, legacy numeric forms and malformed values are never looked up
        return True
    # IPv4-mapped IPv6 (::ffff:10.0.0.1) is checked as the IPv4 it carries
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return (
        _is_private_or_noise(str(addr))
        or addr.is_reserved
        or addr.is_unspecified
        or not addr.is_global
        or (addr.version == 4 and addr in _SHARED_ADDRESS_SPACE)
    )


def _is_legacy_ipv4(host: str) -> bool:
    """True for a numeric IPv4 host that is not a canonical dotted quad.

    Resolvers accept forms like ``127.1``, ``10.1``, ``0x7f.0.0.1`` and
    ``2130706433``; ``socket.inet_aton`` normalises them. They are never
    sent, whatever address they normalise to.
    """
    if not host or not set(host.lower()) <= _LEGACY_IPV4_CHARS:
        return False
    try:
        canonical = socket.inet_ntoa(socket.inet_aton(host))
    except (OSError, ValueError):
        return False
    return canonical != host


def _is_non_public_host(host: str) -> bool:
    """Check a domain or URL host: IP literals as IPs, everything else as a name."""
    name = host.strip().rstrip(".").lower()
    if not name or _is_legacy_ipv4(name):
        return True
    if ":" in name or name.startswith("["):
        # IPv6 literal (brackets already removed by urlparse for URLs)
        return _is_non_public_ip(name)
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return _is_non_public_domain(name)
    return _is_non_public_ip(name)


def _is_non_public_domain(domain: str) -> bool:
    """Single-label names and internal-only suffixes (.local, .corp, ...)."""
    name = domain.strip().rstrip(".").lower()
    if "." not in name:
        return True
    return f".{name}".endswith(_INTERNAL_DOMAIN_SUFFIXES)


def _parse_url(value: str):
    """urlparse that also accepts a scheme-less URL (example.com/path)."""
    return urlparse(value if "://" in value else f"//{value}")


def url_has_userinfo(value: str) -> bool:
    """True when a URL carries a username or password (user:pass@host)."""
    try:
        parsed = _parse_url(value)
        return bool(parsed.username or parsed.password or "@" in parsed.netloc)
    except ValueError:
        return False


def url_for_lookup(value: str, send_query: bool = False) -> str:
    """The URL sent to PolySwarm: without query string and fragment unless opted in."""
    if send_query:
        return value
    parts = urlsplit(value.strip())
    if not parts.scheme or not parts.netloc:
        return value.strip().split("#", 1)[0].split("?", 1)[0]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def loggable_network_value(value: str, observable_type: str) -> str:
    """Value safe to log: a URL is reduced to its scheme and host."""
    if observable_type != "Url":
        return value
    try:
        parsed = _parse_url(value)
        host = parsed.hostname or ""
    except ValueError:
        return "<unparseable URL>"
    if ":" in host:
        host = f"[{host}]"
    return f"{parsed.scheme}://{host}" if parsed.scheme else host


def is_non_public_network_value(value: str, observable_type: str) -> bool:
    """Return True when a URL, domain or IP value must not be sent to PolySwarm."""
    if observable_type in ("IPv4-Addr", "IPv6-Addr"):
        return _is_non_public_ip(value)
    if observable_type == "Domain-Name":
        return _is_non_public_host(value)
    if observable_type == "Url":
        try:
            hostname = _parse_url(value).hostname
        except ValueError:
            return True
        if not hostname:
            return True
        return _is_non_public_host(hostname)
    return True


def _parse_scan_date(value: Any) -> datetime | None:
    """Parse a scan timestamp into an aware UTC datetime (None if unusable)."""
    if not value:
        return None
    try:
        parsed = (
            value if isinstance(value, datetime) else dateutil_parser.parse(str(value))
        )
    except (ValueError, OverflowError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


class _TooLarge(Exception):
    """Raised by _CappedBuffer to stop a download that passes the size limit."""


class _CappedBuffer(io.BytesIO):
    """In-memory download target that aborts once more than ``limit`` bytes arrive."""

    def __init__(self, limit: int) -> None:
        super().__init__()
        self.limit = limit
        self.exceeded = False

    def write(self, data) -> int:
        if self.tell() + len(data) > self.limit:
            self.exceeded = True
            raise _TooLarge("download passed the size limit")
        return super().write(data)


class CircuitBreaker:
    """
    Simple circuit breaker to prevent hammering failing APIs.

    States:
    - CLOSED: Normal operation, requests pass through
    - OPEN: Too many failures, requests blocked for cooldown period
    - HALF_OPEN: Cooldown expired, allow one test request
    """

    def __init__(self, failure_threshold: int = 5, cooldown_seconds: int = 300):
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        self.failure_count = 0
        self.last_failure_time: datetime | None = None
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN

    def record_success(self) -> None:
        """Record a successful request, reset failure count."""
        self.failure_count = 0
        self.state = "CLOSED"

    def record_failure(self) -> None:
        """Record a failed request, potentially open the circuit."""
        self.failure_count += 1
        self.last_failure_time = datetime.now()

        if self.failure_count >= self.failure_threshold:
            self.state = "OPEN"

    def can_execute(self) -> tuple[bool, str | None]:
        """
        Check if a request can be executed.
        Returns: (can_execute, reason_if_blocked)
        """
        if self.state == "CLOSED":
            return True, None

        if self.state == "OPEN" and self.last_failure_time:
            # Check if cooldown period has passed
            elapsed = datetime.now() - self.last_failure_time
            if elapsed > timedelta(seconds=self.cooldown_seconds):
                self.state = "HALF_OPEN"
                return True, None
            remaining = self.cooldown_seconds - elapsed.total_seconds()
            return (
                False,
                f"Circuit breaker OPEN. {int(remaining)}s until retry.",
            )

        if self.state == "HALF_OPEN":
            return True, None

        return True, None

    def get_status(self) -> dict[str, Any]:
        """Get circuit breaker status for logging."""
        return {
            "state": self.state,
            "failure_count": self.failure_count,
            "threshold": self.failure_threshold,
            "cooldown_seconds": self.cooldown_seconds,
        }


class ConnectorClient:
    """PolySwarm API client with circuit breaker and multi-community support."""

    def __init__(self, helper: object, config: object) -> None:
        """
        Initialize the client with necessary configurations.

        Args:
            helper: OpenCTI connector helper for logging.
            config: PolySwarmConfig Pydantic model (or duck-typed equivalent).
        """
        self.helper = helper
        self.config = config

        # The SDK logs every searched value (full URLs, query strings included)
        # at INFO; keep only its warnings so lookups don't leak into connector logs
        logging.getLogger("polyswarm_api").setLevel(logging.WARNING)

        # PolySwarm SDK Initialization
        api_key = config.api_key
        self.polyswarm_api_key = (
            api_key.get_secret_value()
            if hasattr(api_key, "get_secret_value")
            else api_key
        )
        self.polyswarm_community = config.community

        # Circuit breakers for each community
        self._circuit_breakers: dict[str, CircuitBreaker] = {}

        # Initialize primary PolySwarm SDK instance
        self.polyswarm = PolyswarmAPI(
            key=self.polyswarm_api_key, community=self.polyswarm_community
        )
        self._circuit_breakers[self.polyswarm_community] = CircuitBreaker()

        # If community is "private", also initialize default community instance
        self.polyswarm_default: PolyswarmAPI | None = None
        if self.polyswarm_community.lower() == "private":
            self.polyswarm_default = PolyswarmAPI(
                key=self.polyswarm_api_key, community="default"
            )
            self._circuit_breakers["default"] = CircuitBreaker()
            self.helper.connector_logger.info(
                "PolySwarm SDK initialized for DUAL communities: private + default"
            )
        else:
            self.helper.connector_logger.info(
                f"PolySwarm SDK initialized (Community: {self.polyswarm_community})"
            )

        # Validate API key and community access at startup — fail fast
        self._validate_api_access()

        # polykg knowledge-graph API (malware family profiles)
        self._polykg_url = config.polykg_api_url
        if self._polykg_url:
            self._polykg_url = self._polykg_url.rstrip("/")
        # polykg enrichment is opt-in: a blank POLYKG_API_URL disables every
        # profile / attack-pattern lookup. Guard on this flag rather than
        # building a schemeless "/v3/kg/..." URL, which raises MissingSchema.
        self._polykg_enabled = bool(self._polykg_url)
        self._circuit_breakers["polykg"] = CircuitBreaker(
            failure_threshold=1, cooldown_seconds=300
        )
        if self._polykg_enabled:
            self._check_polykg_connectivity()
        else:
            self.helper.connector_logger.info(
                "[CLIENT] polykg enrichment disabled (POLYKG_API_URL not set); "
                "skipping malware-profile and attack-pattern lookups"
            )

    def _validate_api_access(self) -> None:
        """Verify API key and community access. Raises on auth failure."""
        communities_to_check = [
            (self.polyswarm, self.polyswarm_community),
        ]
        if self.polyswarm_default:
            communities_to_check.append((self.polyswarm_default, "default"))

        for api_instance, community_name in communities_to_check:
            try:
                # exists() is a lightweight HEAD request — no data transfer
                api_instance.exists("a" * 64, hash_type="sha256")
                self.helper.connector_logger.info(
                    f"[CLIENT] API access verified for community: {community_name}"
                )
            except polyswarm_exceptions.NoResultsException:
                # Hash not found is fine — means API access works
                self.helper.connector_logger.info(
                    f"[CLIENT] API access verified for community: {community_name}"
                )
            except polyswarm_exceptions.RequestException as e:
                error_str = str(e)
                if "401" in error_str or "403" in error_str:
                    raise ValueError(
                        f"PolySwarm API access denied for community '{community_name}'. "
                        f"Check POLYSWARM_API_KEY and POLYSWARM_COMMUNITY. Error: {error_str}"
                    ) from e
                # Other request errors (429, 5xx) are transient — warn but don't die
                self.helper.connector_logger.warning(
                    f"[CLIENT] Could not verify API access for {community_name} "
                    f"(transient error: {error_str}). Will retry on first enrichment."
                )
            except (ConnectionError, TimeoutError, OSError) as e:
                self.helper.connector_logger.warning(
                    f"[CLIENT] Could not reach PolySwarm API for {community_name}: {e}. "
                    "Will retry on first enrichment."
                )

    def _parse_result(self, result, community_name: str) -> dict[str, Any] | None:
        """Parse a single PolySwarm result into a data dictionary."""
        try:
            if result.failed or not result.assertions:
                return None

            # Data Extraction
            poly_labels = []

            # Extract malware family (READ-5: formatted for readability)
            # NOTE: PolySwarm SDK uses __getattr__ that raises AttributeError
            # for missing keys — must use getattr() with default, not direct access
            polyunite_data = (
                getattr(result.metadata, "polyunite", None) if result.metadata else None
            )
            malware_family = (
                polyunite_data.get("malware_family") if polyunite_data else None
            )
            # Normalize: treat None, empty string, and "Unknown" as no family
            if not malware_family or str(malware_family).strip().lower() in (
                "unknown",
                "none",
                "",
            ):
                malware_family = None

            # Extract file type
            exiftool_data = (
                getattr(result.metadata, "exiftool", None) if result.metadata else None
            )
            if exiftool_data:
                file_type = exiftool_data.get("filetype", result.mimetype)
            else:
                file_type = result.mimetype if result.mimetype else "Unknown"

            # Get PolyUnite labels
            polyunite_labels = (
                polyunite_data.get("labels", []) if polyunite_data else []
            )
            if polyunite_labels:
                for label in polyunite_labels:
                    poly_labels.append(f"malware_type:{label}")

            # Add malware family label (skip if no family identified)
            if malware_family:
                poly_labels.append(f"PolyUnite:{malware_family}")

            # Get operating system labels
            os_labels = (
                polyunite_data.get("operating_system", []) if polyunite_data else []
            )
            if os_labels:
                for os_label in os_labels:
                    poly_labels.append(f"os_type:{os_label}")

            # Detection counts — use pre-computed API field
            api_detections = result.json.get("detections", {})
            positives = api_detections.get("malicious", 0)
            total = api_detections.get("total", 0)

            polyscore = result.polyscore if result.polyscore is not None else 0.0
            poly_score_int = int(polyscore * 100)

            # Description
            family_text = (
                f"The Malware family (PolyUnite) for this file is {malware_family}. "
                if malware_family
                else ""
            )
            poly_description = (
                f"PolySwarm ({community_name}) saw this file for the first time on '{str(result.first_seen)}'. "
                f"Malware score (PolyScore) for this file is {poly_score_int} / 100. "
                f"{family_text}"
                f"Note: {positives} of {total} AV engines have classified this as malicious in the last scan."
            )

            # Extended hashes from metadata (top-level sha256/sha1/md5 used directly below)
            hash_data = (
                getattr(result.metadata, "hash", None) if result.metadata else {}
            )
            hash_data = hash_data or {}

            # Fetch curated platform tags via TagLink API
            tag_link_tags = []
            tag_link_families = []
            try:
                tag_link = self.polyswarm.tag_link_get(result.sha256)
                if tag_link:
                    if tag_link.tags:
                        for tag in tag_link.tags:
                            if not tag.startswith("feed:"):
                                tag_link_tags.append(tag)
                                poly_labels.append(f"polyswarm:{tag}")
                    if tag_link.families:
                        tag_link_families = list(tag_link.families)
                        for family in tag_link_families:
                            poly_labels.append(f"polyswarm-family:{family}")
                    if tag_link_tags or tag_link_families:
                        self.helper.connector_logger.info(
                            f"[CLIENT] TagLink: tags={tag_link_tags}, families={tag_link_families}"
                        )
            except polyswarm_exceptions.NoResultsException:
                pass  # Not all artifacts have tag links
            except Exception as e:
                self.helper.connector_logger.debug(
                    f"[CLIENT] TagLink fetch failed: {e}"
                )

            # Build data dictionary
            return {
                "community": community_name,
                "confidence": 100,
                "x_opencti_score": poly_score_int,
                "x_opencti_labels": poly_labels,
                "x_opencti_description": poly_description,
                "sha256": result.sha256 if result.sha256 else None,
                "md5": result.md5 if result.md5 else None,
                "sha1": result.sha1 if result.sha1 else None,
                "sha3_256": hash_data.get("sha3_256") or None,
                "sha3_512": hash_data.get("sha3_512") or None,
                "sha512": hash_data.get("sha512") or None,
                "ssdeep": hash_data.get("ssdeep") or None,
                "tlsh": hash_data.get("tlsh") or None,
                "mime_type": result.mimetype if result.mimetype else "Unknown",
                "file_type": file_type,
                "permalink": result.permalink if result.permalink else None,
                "polyswarm_id": result.id if result.id else None,
                "polyscore": polyscore,
                "first_seen": str(result.first_seen) if result.first_seen else "N/A",
                "last_seen": str(result.last_seen) if result.last_seen else "N/A",
                "last_seen_dt": result.last_seen,
                "poly_unite": [malware_family] if malware_family else [],
                "tag_link_families": tag_link_families,
                "filenames": [result.filename] if result.filename else [],
                "size": getattr(result, "size", None),
                "last_scanned_dt": getattr(result, "last_scanned", None),
                "detections": {"malicious": positives, "total": total},
            }

        except (AttributeError, TypeError, KeyError) as e:
            self.helper.connector_logger.error(
                f"Error parsing PolySwarm result: {str(e)}"
            )
            return None

    def _parse_api_error(self, error: Exception, community_name: str) -> dict[str, Any]:
        """Parse API error and return structured error info."""
        error_str = str(error)
        error_info = {
            "community": community_name,
            "error_type": "unknown",
            "error_code": None,
            "error_message": error_str,
            "is_access_error": False,
            "is_quota_error": False,
            "is_no_results": False,
        }

        # Check for specific error types
        if "401" in error_str:
            error_info["error_type"] = "access_denied"
            error_info["error_code"] = 401
            error_info["is_access_error"] = True
            if "private" in error_str.lower():
                error_info["error_message"] = (
                    f"Account does not have access to {community_name} community"
                )
            else:
                error_info["error_message"] = (
                    f"Authentication failed for {community_name} community (Invalid API key?)"
                )

        elif "403" in error_str:
            error_info["error_type"] = "forbidden"
            error_info["error_code"] = 403
            error_info["is_access_error"] = True
            error_info["error_message"] = (
                f"Access forbidden to {community_name} community"
            )

        elif (
            isinstance(error, polyswarm_exceptions.UsageLimitsExceededException)
            or "429" in error_str
        ):
            error_info["error_type"] = "quota_exceeded"
            error_info["error_code"] = 429
            error_info["is_quota_error"] = True
            error_info["error_message"] = (
                f"API quota exceeded or rate limited for {community_name} community"
            )

        elif "no results" in error_str.lower() or isinstance(
            error, polyswarm_exceptions.NoResultsException
        ):
            error_info["error_type"] = "no_results"
            error_info["is_no_results"] = True
            error_info["error_message"] = (
                f"No results found in {community_name} community"
            )

        elif "timeout" in error_str.lower():
            error_info["error_type"] = "timeout"
            error_info["error_message"] = (
                f"Request timeout for {community_name} community"
            )

        elif "500" in error_str or "502" in error_str or "503" in error_str:
            error_info["error_type"] = "server_error"
            error_info["error_code"] = 500
            error_info["error_message"] = (
                f"PolySwarm server error for {community_name} community"
            )

        return error_info

    def _query_single_community(
        self, hash_value: str, polyswarm_instance: PolyswarmAPI, community_name: str
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        """
        Query a single PolySwarm community with circuit breaker protection.

        Returns: (data_dict, error_info) tuple
        - If successful: (data, None)
        - If no results: (None, error_info with is_no_results=True)
        - If API error: (None, error_info with error details)
        - If circuit open: (None, error_info with circuit_breaker_open=True)
        """
        # Check circuit breaker
        circuit = self._circuit_breakers.get(community_name)
        if circuit:
            can_execute, reason = circuit.can_execute()
            if not can_execute:
                self.helper.connector_logger.warning(
                    f"[CLIENT] Circuit breaker OPEN for {community_name}: {reason}"
                )
                return None, {
                    "community": community_name,
                    "error_type": "circuit_breaker_open",
                    "error_code": None,
                    "error_message": f"Circuit breaker open for {community_name}. {reason}",
                    "is_access_error": False,
                    "is_quota_error": False,
                    "is_no_results": False,
                    "is_circuit_breaker": True,
                }

        try:
            self.helper.connector_logger.info(
                f"Searching PolySwarm ({community_name}) for hash: {hash_value}"
            )

            results = list(polyswarm_instance.search(hash_value))

            data = None
            for result in results:
                data = self._parse_result(result, community_name)
                if data:
                    # Kept for the opt-in rescan decision, removed before returning
                    data["_source_result"] = result
                    break

            if data:
                # Success - reset circuit breaker
                if circuit:
                    circuit.record_success()

                self.helper.connector_logger.info(
                    f"[CLIENT] PolySwarm ({community_name}) data: "
                    f"SHA256={data['sha256']}, Score={data['x_opencti_score']}, "
                    f"Last Seen={data['last_seen']}"
                )
                return data, None

            # No results found (but no error) - this is not a failure
            self.helper.connector_logger.info(
                f"Hash not found in PolySwarm ({community_name})"
            )
            error_info = {
                "community": community_name,
                "error_type": "no_results",
                "error_code": None,
                "error_message": f"Hash not found in {community_name} community",
                "is_access_error": False,
                "is_quota_error": False,
                "is_no_results": True,
            }
            if results:
                # PolySwarm holds the sample but nothing usable finished scanning
                error_info["held_results"] = results
            return None, error_info

        except polyswarm_exceptions.NoResultsException:
            self.helper.connector_logger.info(
                f"No results in PolySwarm ({community_name})"
            )
            error_info = {
                "community": community_name,
                "error_type": "no_results",
                "error_code": None,
                "error_message": f"Hash not found in {community_name} community",
                "is_access_error": False,
                "is_quota_error": False,
                "is_no_results": True,
            }
            return None, error_info

        except polyswarm_exceptions.RequestException as e:
            # Record failure in circuit breaker
            if circuit:
                circuit.record_failure()
                self.helper.connector_logger.warning(
                    f"[CLIENT] Circuit breaker status for {community_name}: "
                    f"{circuit.get_status()}"
                )

            self.helper.connector_logger.error(
                f"PolySwarm API error ({community_name}): {str(e)}"
            )
            error_info = self._parse_api_error(e, community_name)
            return None, error_info

        except (ConnectionError, TimeoutError, OSError) as e:
            # Network/connection errors - record in circuit breaker
            if circuit:
                circuit.record_failure()
                self.helper.connector_logger.warning(
                    f"[CLIENT] Circuit breaker status for {community_name}: "
                    f"{circuit.get_status()}"
                )

            self.helper.connector_logger.error(
                f"Network error querying PolySwarm ({community_name}): {str(e)}"
            )
            error_info = {
                "community": community_name,
                "error_type": "network_error",
                "error_code": None,
                "error_message": f"Network error: {str(e)}",
                "is_access_error": False,
                "is_quota_error": False,
                "is_no_results": False,
            }
            return None, error_info

        except (ValueError, TypeError, KeyError, AttributeError) as e:
            # Data parsing errors - don't necessarily trigger circuit breaker
            self.helper.connector_logger.error(
                f"Data parsing error for PolySwarm ({community_name}): {str(e)}"
            )
            self.helper.connector_logger.error(f"Traceback: {traceback.format_exc()}")
            error_info = self._parse_api_error(e, community_name)
            return None, error_info

        except Exception as e:
            # Unexpected errors - record failure in circuit breaker
            if circuit:
                circuit.record_failure()

            self.helper.connector_logger.error(
                f"Unexpected error querying PolySwarm ({community_name}): {str(e)}"
            )
            self.helper.connector_logger.error(f"Traceback: {traceback.format_exc()}")
            error_info = self._parse_api_error(e, community_name)
            return None, error_info

    def _search_communities(self, hash_value: str) -> dict[str, Any]:
        """
        Query PolySwarm API with circuit breaker protection.

        If community is "private", queries BOTH private and default communities.

        Returns a dict with:
        - "data": enrichment data (or None)
        - "errors": list of error_info dicts for any API errors
        - "multi_community": True if queried both communities
        - "primary"/"secondary": data for multi-community mode

        Error types that should be reported to user:
        - access_denied (401): No access to community
        - forbidden (403): Access forbidden
        - quota_exceeded (429): Rate limited / quota exceeded
        - server_error (5xx): PolySwarm server issues
        - circuit_breaker_open: Too many failures, requests blocked
        """
        result = {
            "data": None,
            "errors": [],
            "multi_community": False,
            "primary": None,
            "secondary": None,
        }

        try:
            # If community is private, query both communities IN PARALLEL
            if self.polyswarm_community.lower() == "private" and self.polyswarm_default:
                self.helper.connector_logger.info(
                    f"Querying BOTH private and default communities in PARALLEL for hash: {hash_value}"
                )
                result["multi_community"] = True

                # Query both communities in parallel using ThreadPoolExecutor
                private_data, private_error = None, None
                default_data, default_error = None, None

                with ThreadPoolExecutor(max_workers=2) as executor:
                    futures = {
                        executor.submit(
                            self._query_single_community,
                            hash_value,
                            self.polyswarm,
                            "private",
                        ): "private",
                        executor.submit(
                            self._query_single_community,
                            hash_value,
                            self.polyswarm_default,
                            "default",
                        ): "default",
                    }

                    for future in as_completed(futures):
                        community = futures[future]
                        try:
                            data, error = future.result()
                            if community == "private":
                                private_data, private_error = data, error
                            else:
                                default_data, default_error = data, error
                        except Exception as e:
                            self.helper.connector_logger.error(
                                f"[CLIENT] Parallel query failed for {community}: {str(e)}"
                            )
                            if community == "private":
                                private_error = {
                                    "community": "private",
                                    "error_type": "thread_error",
                                    "error_message": str(e),
                                    "is_no_results": False,
                                }
                            else:
                                default_error = {
                                    "community": "default",
                                    "error_type": "thread_error",
                                    "error_message": str(e),
                                    "is_no_results": False,
                                }

                result["_held"] = [
                    (name, err["held_results"])
                    for name, err in (
                        ("private", private_error),
                        ("default", default_error),
                    )
                    if err and err.get("held_results")
                ]

                # Collect reportable errors (not just "no results")
                if private_error and not private_error.get("is_no_results"):
                    result["errors"].append(private_error)
                if default_error and not default_error.get("is_no_results"):
                    result["errors"].append(default_error)

                # Determine what to return based on results
                if private_data and default_data:
                    # Both have results - determine which is more recent
                    self.helper.connector_logger.info(
                        "[CLIENT] Results found in BOTH private and default communities"
                    )

                    private_last_seen = private_data.get("last_seen_dt")
                    default_last_seen = default_data.get("last_seen_dt")

                    if private_last_seen and default_last_seen:
                        if private_last_seen >= default_last_seen:
                            result["primary"] = private_data
                            result["secondary"] = default_data
                            self.helper.connector_logger.info(
                                f"[CLIENT] Using PRIVATE as primary "
                                f"(last_seen: {private_data['last_seen']} >= {default_data['last_seen']})"
                            )
                        else:
                            result["primary"] = default_data
                            result["secondary"] = private_data
                            self.helper.connector_logger.info(
                                f"[CLIENT] Using DEFAULT as primary "
                                f"(last_seen: {default_data['last_seen']} > {private_data['last_seen']})"
                            )
                    elif private_last_seen:
                        result["primary"] = private_data
                        result["secondary"] = default_data
                    elif default_last_seen:
                        result["primary"] = default_data
                        result["secondary"] = private_data
                    else:
                        result["primary"] = private_data
                        result["secondary"] = default_data

                    result["data"] = result["primary"]

                elif private_data:
                    self.helper.connector_logger.info(
                        "[CLIENT] Results found only in PRIVATE community"
                    )
                    result["data"] = private_data
                    result["primary"] = private_data

                elif default_data:
                    self.helper.connector_logger.info(
                        "[CLIENT] Results found only in DEFAULT community"
                    )
                    result["data"] = default_data
                    result["primary"] = default_data

                else:
                    self.helper.connector_logger.info(
                        "[CLIENT] No results found in either community"
                    )
                    # Add "no results" info if no other errors
                    if not result["errors"]:
                        result["errors"].append(
                            {
                                "community": "private + default",
                                "error_type": "no_results",
                                "error_code": None,
                                "error_message": "Hash not found in any PolySwarm community",
                                "is_access_error": False,
                                "is_quota_error": False,
                                "is_no_results": True,
                            }
                        )

            else:
                # Single community query (default behavior)
                data, error = self._query_single_community(
                    hash_value, self.polyswarm, self.polyswarm_community
                )

                if error and error.get("held_results"):
                    result["_held"] = [
                        (self.polyswarm_community, error["held_results"])
                    ]
                if data:
                    result["data"] = data
                    result["primary"] = data
                elif error:
                    if not error.get("is_no_results"):
                        result["errors"].append(error)
                    else:
                        # Still add no_results for single community
                        result["errors"].append(error)

            return result

        except Exception as e:
            self.helper.connector_logger.error(
                f"Error querying PolySwarm SDK: {str(e)}"
            )
            self.helper.connector_logger.error(f"Traceback: {traceback.format_exc()}")
            result["errors"].append(
                {
                    "community": self.polyswarm_community,
                    "error_type": "unknown",
                    "error_code": None,
                    "error_message": str(e),
                    "is_access_error": False,
                    "is_quota_error": False,
                    "is_no_results": False,
                }
            )
            return result

    # ------------------------------------------------------------------
    # Rescan (opt-in)
    # ------------------------------------------------------------------

    @staticmethod
    def _scan_time(result) -> datetime | None:
        """When a scan result was produced (None if the result doesn't say)."""
        stamp = getattr(result, "last_scanned", None) or getattr(
            result, "created", None
        )
        return _parse_scan_date(stamp)

    def _rescan_reason(self, held: list, data: dict | None, source=None) -> str | None:
        """Why a held sample should be rescanned, or None to leave it alone.

        ``source`` is the scan result ``data`` was built from, so the age is
        that of the scan actually used.
        """
        days = getattr(getattr(self, "config", None), "rescan_older_than_days", 0)
        if not days or days <= 0:
            return None
        if data is None:
            # PolySwarm holds the sample but nothing usable finished scanning.
            # A scan that is still running is left to finish, never doubled.
            in_progress = any(
                not getattr(r, "failed", False)
                and not getattr(r, "window_closed", True)
                for r in held
            )
            return None if in_progress else "no completed scan"
        scanned = (
            self._scan_time(source) if source is not None else None
        ) or _parse_scan_date(data.get("last_scanned_dt"))
        if scanned is None:
            return None
        age_days = (datetime.now(timezone.utc) - scanned).days
        if age_days > days:
            return f"latest scan is {age_days} days old (limit {days})"
        return None

    def _instance_for(self, community_name: str) -> PolyswarmAPI:
        """The SDK instance bound to a community."""
        if community_name != self.polyswarm_community and self.polyswarm_default:
            return self.polyswarm_default
        return self.polyswarm

    def _run_rescan(
        self, sha256: str, instance: PolyswarmAPI, community_name: str, reason: str
    ) -> tuple[dict | None, dict]:
        """Rescan in one community and wait. Returns (fresh data or None, outcome).

        Nothing is uploaded: PolySwarm rescans its own copy. Timeouts and errors
        never fail the enrichment; ``outcome`` records what happened.
        """
        timeout = getattr(self.config, "rescan_timeout", 300)
        self.helper.connector_logger.info(
            f"[CLIENT] Rescanning in PolySwarm ({community_name}): {reason}"
        )
        outcome = {"reason": reason, "status": "failed", "timeout": timeout}
        fresh = None
        try:
            started = instance.rescan(sha256, hash_type="sha256")
            done = instance.wait_for(started, timeout=timeout)
            fresh = self._parse_result(done, community_name)
            outcome["status"] = "completed" if fresh else "no_result"
        except polyswarm_exceptions.TimeoutException:
            outcome["status"] = "timed_out"
            self.helper.connector_logger.warning(
                f"[CLIENT] Rescan did not finish within {timeout}s ({community_name})"
            )
        except Exception as e:  # quota, auth, network: never fail the enrichment
            outcome["error"] = type(e).__name__
            if is_quota_exhausted_error(e):
                outcome["quota_exhausted"] = True
            self.helper.connector_logger.warning(
                f"[CLIENT] Rescan failed ({community_name}): {type(e).__name__}"
            )
        return fresh, outcome

    def query_polyswarm(
        self, hash_value: str, allow_rescan: bool = True
    ) -> dict[str, Any]:
        """Query PolySwarm (both communities in private mode), then rescan once.

        The opt-in rescan is decided after the primary result is chosen, so at
        most one rescan runs per enrichment, in the community of the result the
        enrichment uses. See ``_search_communities`` for the result shape; a
        top-level ``rescan`` key is set when a rescan was due but no result
        exists to carry it.
        """
        result = self._search_communities(hash_value)
        held = result.pop("_held", [])
        if not allow_rescan:
            return result
        try:
            data = result.get("data")
            source = data.get("_source_result") if data else None
            if data:
                held_results = [source] if source is not None else []
                community = data.get("community") or self.polyswarm_community
            elif held:
                community, held_results = held[0]
            else:
                return result
            reason = self._rescan_reason(held_results, data, source)
            if reason:
                sha256 = data["sha256"] if data else held_results[0].sha256
                fresh, outcome = self._run_rescan(
                    sha256, self._instance_for(community), community, reason
                )
                if fresh:
                    fresh["rescan"] = outcome
                    result["data"] = result["primary"] = fresh
                    result["errors"] = [
                        e for e in result["errors"] if not e.get("is_no_results")
                    ]
                elif data:
                    data["rescan"] = outcome
                else:
                    result["rescan"] = outcome
        finally:
            for entry in (
                result.get("data"),
                result.get("primary"),
                result.get("secondary"),
            ):
                if entry:
                    entry.pop("_source_result", None)
        return result

    # ------------------------------------------------------------------
    # Sample download (opt-in)
    # ------------------------------------------------------------------

    def download_sample(self, data: dict) -> tuple[bytes | None, str | None]:
        """Download the sample PolySwarm holds for ``data`` (opt-in, spends quota).

        Returns (bytes, None) or (None, reason). When PolySwarm reports the size
        it is checked against POLYSWARM_DOWNLOAD_MAX_SIZE_MB before anything is
        downloaded; otherwise the download is aborted as soon as the bytes
        received pass the limit. The sample is held in memory only.
        """
        max_mb = getattr(self.config, "download_max_size_mb", 20)
        sha256 = data.get("sha256")
        if not sha256:
            return None, "no SHA-256 for the sample"
        size = data.get("size")
        if size is not None and size > max_mb * 1024 * 1024:
            return None, f"sample is {size} bytes, over the {max_mb} MB limit"
        community = data.get("community") or self.polyswarm_community
        instance = (
            self.polyswarm_default
            if community == "default" and self.polyswarm_default
            else self.polyswarm
        )
        limit = max_mb * 1024 * 1024
        handle = _CappedBuffer(limit)
        try:
            instance.download_to_handle(sha256, handle, hash_type="sha256")
        except Exception as e:
            if handle.exceeded:
                return None, f"sample is over the {max_mb} MB limit (download stopped)"
            # Only the exception type is logged: request errors can carry a
            # presigned download URL with a query string.
            self.helper.connector_logger.warning(
                f"[CLIENT] Sample download failed: {type(e).__name__}"
            )
            return None, f"download failed ({type(e).__name__})"
        if handle.exceeded:
            return None, f"sample is over the {max_mb} MB limit (download stopped)"
        return handle.getvalue(), None

    # ------------------------------------------------------------------
    # polykg — malware family profiles
    # ------------------------------------------------------------------

    def _polykg_headers(self) -> dict:
        """Auth headers for polykg requests."""
        if self.polyswarm_api_key:
            return {"Authorization": f"Bearer {self.polyswarm_api_key}"}
        return {}

    def _check_polykg_connectivity(self) -> None:
        """Log whether the polykg profile endpoint is reachable."""
        try:
            resp = requests.get(
                f"{self._polykg_url}/v3/kg/profile",
                headers=self._polykg_headers(),
                timeout=2,
            )
            if resp.status_code in (200, 204):
                self.helper.connector_logger.info(
                    f"[CLIENT] Connected to polykg profile API at {self._polykg_url}"
                )
            else:
                resp.raise_for_status()
        except requests.RequestException as e:
            self.helper.connector_logger.warning(
                f"[CLIENT] polykg profile API at {self._polykg_url} is not reachable: {e}. "
                "Profile enrichment will attempt lookups on demand."
            )

    def get_profile(self, family_name: str) -> dict | None:
        """Fetch a malware family profile from the polykg knowledge graph.

        Returns the profile dict or None if not found / unreachable.
        """
        if not self._polykg_enabled:
            return None
        if not family_name:
            return None

        circuit = self._circuit_breakers["polykg"]
        can_execute, reason = circuit.can_execute()
        if not can_execute:
            self.helper.connector_logger.debug(
                f"[CLIENT] polykg circuit open: {reason}"
            )
            return None

        try:
            resp = requests.post(
                f"{self._polykg_url}/v3/kg/profile",
                headers=self._polykg_headers(),
                json={"family_name": family_name.strip()},
                timeout=10,
            )

            if resp.status_code == 404:
                self.helper.connector_logger.debug(
                    f"[CLIENT] No polykg profile for: {family_name}"
                )
                return None

            resp.raise_for_status()
            circuit.record_success()
            profile = resp.json()
            self.helper.connector_logger.info(
                f"[CLIENT] Fetched polykg profile for: {family_name}"
            )
            return profile

        except requests.exceptions.ConnectionError:
            circuit.record_failure()
            self.helper.connector_logger.warning(
                f"[CLIENT] Cannot reach polykg API for {family_name}. "
                f"Circuit breaker open for {circuit.cooldown_seconds}s."
            )
            return None
        except requests.RequestException as e:
            self.helper.connector_logger.error(
                f"[CLIENT] Error fetching profile for {family_name}: {e}"
            )
            return None

    def has_profiles(self) -> bool:
        """Check if the polykg profile endpoint is reachable."""
        if not self._polykg_enabled:
            return False
        try:
            resp = requests.get(
                f"{self._polykg_url}/v3/kg/profile",
                headers=self._polykg_headers(),
                timeout=2,
            )
            return resp.status_code in (200, 204)
        except requests.RequestException:
            return False

    def fetch_attack_patterns(self) -> dict[str, Any] | None:
        """Fetch TTP database and type mappings from polykg.

        Returns dict with 'techniques' and 'type_mappings' keys,
        or None if polykg is unreachable.
        """
        if not self._polykg_enabled:
            return None
        circuit = self._circuit_breakers["polykg"]
        can_execute, reason = circuit.can_execute()
        if not can_execute:
            self.helper.connector_logger.debug(
                f"[CLIENT] polykg circuit open: {reason}"
            )
            return None

        try:
            resp = requests.get(
                f"{self._polykg_url}/v3/kg/opencti/attack-patterns",
                headers=self._polykg_headers(),
                timeout=2,
            )
            resp.raise_for_status()
            circuit.record_success()
            data = resp.json()
            self.helper.connector_logger.info(
                f"[CLIENT] Loaded {len(data.get('techniques', {}))} techniques, "
                f"{len(data.get('type_mappings', {}))} type mappings from polykg"
            )
            return data
        except requests.exceptions.ConnectionError:
            circuit.record_failure()
            self.helper.connector_logger.warning(
                f"[CLIENT] Cannot reach polykg for attack patterns. "
                f"Circuit breaker open for {circuit.cooldown_seconds}s."
            )
            return None
        except requests.RequestException as e:
            self.helper.connector_logger.warning(
                f"[CLIENT] polykg attack-patterns fetch failed: {e}"
            )
            return None

    # ------------------------------------------------------------------
    # Network IOC extraction
    # ------------------------------------------------------------------

    def fetch_iocs(self, sha256: str) -> dict[str, Any] | None:
        """Fetch network IOCs for a hash from the PolySwarm IOC API.

        Returns parsed dict with keys: ips, urls, domains, ttps, imphash.
        Returns None if no IOC data available (normal for most hashes).
        """
        if not sha256:
            return None

        try:
            self.helper.connector_logger.info(
                f"[CLIENT] Fetching IOCs for hash: {sha256}"
            )
            result = self.polyswarm.iocs_by_hash("sha256", sha256, hide_known_good=True)
            data = result.json

            # Filter IPs: remove private, multicast, loopback, link-local
            raw_ips = data.get("ips", [])
            filtered_ips = [ip for ip in raw_ips if not _is_private_or_noise(ip)]

            # Extract unique domains from URLs
            domains: set[str] = set()
            for url in data.get("urls", []):
                try:
                    hostname = urlparse(url).hostname
                    if hostname and not _is_private_or_noise(hostname):
                        domains.add(hostname)
                except (ValueError, AttributeError):
                    pass

            ioc_data = {
                "ips": filtered_ips,
                "urls": data.get("urls", []),
                "domains": sorted(domains),
                "ttps": data.get("ttps", []),
                "imphash": data.get("imphash", ""),
            }

            self.helper.connector_logger.info(
                f"[CLIENT] IOCs found: {len(filtered_ips)} IPs "
                f"(filtered from {len(raw_ips)}), "
                f"{len(ioc_data['urls'])} URLs, "
                f"{len(ioc_data['domains'])} domains, "
                f"{len(ioc_data['ttps'])} TTPs"
            )
            return ioc_data

        except polyswarm_exceptions.NoResultsException:
            self.helper.connector_logger.info(
                f"[CLIENT] No IOC data for hash: {sha256}"
            )
            return None
        except (ConnectionError, TimeoutError, OSError) as e:
            self.helper.connector_logger.warning(
                f"[CLIENT] IOC fetch network error: {e}"
            )
            return None
        except polyswarm_exceptions.RequestException as e:
            self.helper.connector_logger.warning(f"[CLIENT] IOC fetch API error: {e}")
            return None

    # ------------------------------------------------------------------
    # URL, domain and IP observable lookups (search only, nothing uploaded)
    # ------------------------------------------------------------------

    def _parse_url_scan(self, result, community_name: str) -> dict[str, Any] | None:
        """Parse a URL-type scan result into a data dictionary."""
        try:
            data = result.json or {}
            detections = data.get("detections") or {}
            malicious = int(detections.get("malicious") or 0)
            total = int(detections.get("total") or 0)
            benign = detections.get("benign")
            benign = int(benign) if benign is not None else max(total - malicious, 0)
            raw_date = data.get("last_scanned") or data.get("created")
            scan_date = _parse_scan_date(raw_date)
            permalink = data.get("permalink") or getattr(result, "permalink", None)

            # Score from the engine verdicts (malicious / total)
            score = round(100 * malicious / total) if total > 0 else None

            return {
                "community": community_name,
                "malicious": malicious,
                "benign": benign,
                "total": total,
                "x_opencti_score": score,
                "scan_date": scan_date.isoformat() if scan_date else None,
                "scan_date_dt": scan_date,
                "window_closed": data.get("window_closed"),
                "permalink": permalink or None,
                "polyswarm_id": str(data["id"]) if data.get("id") else None,
            }
        except (AttributeError, TypeError, ValueError) as e:
            self.helper.connector_logger.error(
                "[CLIENT] Error parsing PolySwarm URL scan",
                {"community": community_name, "error": str(e)},
            )
            return None

    def _search_url_single_community(
        self,
        value: str,
        polyswarm_instance: PolyswarmAPI,
        community_name: str,
        log_value: str | None = None,
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        """
        Search the latest URL-type scan of a value in one community.

        ``log_value`` is what gets logged instead of the value (a URL is
        reduced to scheme and host). Returns: (scan_dict, error_info), same
        contract as ``_query_single_community``.
        """
        log_value = log_value if log_value is not None else value
        circuit = self._circuit_breakers.get(community_name)
        if circuit:
            can_execute, reason = circuit.can_execute()
            if not can_execute:
                self.helper.connector_logger.warning(
                    "[CLIENT] Circuit breaker OPEN",
                    {"community": community_name, "reason": reason},
                )
                return None, {
                    "community": community_name,
                    "error_type": "circuit_breaker_open",
                    "error_code": None,
                    "error_message": f"Circuit breaker open for {community_name}. {reason}",
                    "is_access_error": False,
                    "is_quota_error": False,
                    "is_no_results": False,
                    "is_circuit_breaker": True,
                }

        no_results = {
            "community": community_name,
            "error_type": "no_results",
            "error_code": None,
            "error_message": f"No scan found in {community_name} community",
            "is_access_error": False,
            "is_quota_error": False,
            "is_no_results": True,
        }

        try:
            self.helper.connector_logger.info(
                "[CLIENT] Searching PolySwarm URL scans",
                {"community": community_name, "value": log_value},
            )
            # Take the first (latest) scan only
            for result in polyswarm_instance.search_url(value):
                scan = self._parse_url_scan(result, community_name)
                if circuit:
                    circuit.record_success()
                if scan:
                    return scan, None
                break
            return None, no_results

        except polyswarm_exceptions.NoResultsException:
            if circuit:
                circuit.record_success()
            self.helper.connector_logger.info(
                "[CLIENT] No PolySwarm URL scan found",
                {"community": community_name, "value": log_value},
            )
            return None, no_results

        except polyswarm_exceptions.RequestException as e:
            if circuit:
                circuit.record_failure()
            self.helper.connector_logger.error(
                "[CLIENT] PolySwarm API error on URL search",
                {"community": community_name, "error": str(e)},
            )
            return None, self._parse_api_error(e, community_name)

        except (ConnectionError, TimeoutError, OSError) as e:
            if circuit:
                circuit.record_failure()
            self.helper.connector_logger.error(
                "[CLIENT] Network error on URL search",
                {"community": community_name, "error": str(e)},
            )
            return None, {
                "community": community_name,
                "error_type": "network_error",
                "error_code": None,
                "error_message": f"Network error: {str(e)}",
                "is_access_error": False,
                "is_quota_error": False,
                "is_no_results": False,
            }

    def _search_related_files(
        self,
        ioc_kind: str,
        value: str,
        polyswarm_instance: PolyswarmAPI,
        community_name: str,
        limit: int,
    ) -> tuple[list[str], dict[str, Any] | None]:
        """
        Return up to ``limit`` SHA-256 hashes of files linked to an IP or domain.

        Returns: (hashes, error_info). error_info is set when the search
        failed with an API or network error, so it is not reported as a
        clean "no related files" result.
        """
        circuit = self._circuit_breakers.get(community_name)
        if circuit and not circuit.can_execute()[0]:
            return [], None

        hashes: list[str] = []
        try:
            for item in polyswarm_instance.search_by_ioc(**{ioc_kind: value}):
                # The SDK yields IOC resources whose .json is the SHA-256 string
                sha256 = item if isinstance(item, str) else getattr(item, "json", "")
                sha256 = (sha256 if isinstance(sha256, str) else "").strip().lower()
                if (
                    len(sha256) == 64
                    and all(c in "0123456789abcdef" for c in sha256)
                    and sha256 not in hashes
                ):
                    hashes.append(sha256)
                if len(hashes) >= limit:
                    break
            if circuit:
                circuit.record_success()
        except polyswarm_exceptions.NoResultsException:
            pass
        except polyswarm_exceptions.RequestException as e:
            if circuit:
                circuit.record_failure()
            self.helper.connector_logger.warning(
                "[CLIENT] Related file search failed",
                {"community": community_name, "error": str(e)},
            )
            return hashes, self._parse_api_error(e, community_name)
        except (ConnectionError, TimeoutError, OSError) as e:
            if circuit:
                circuit.record_failure()
            self.helper.connector_logger.warning(
                "[CLIENT] Related file search failed",
                {"community": community_name, "error": str(e)},
            )
            return hashes, {
                "community": community_name,
                "error_type": "network_error",
                "error_code": None,
                "error_message": f"Network error on related file search: {str(e)}",
                "is_access_error": False,
                "is_quota_error": False,
                "is_no_results": False,
            }
        return hashes, None

    def lookup_network_observable(
        self, value: str, observable_type: str, related_files_max: int = 0
    ) -> dict[str, Any]:
        """
        Look up a URL, domain or IP in PolySwarm. Search only: nothing is
        submitted or uploaded.

        Runs ``search_url`` in each configured community (private + default in
        dual-community mode) and keeps the most recent scan. For IPs and
        domains, also runs ``search_by_ioc`` for up to ``related_files_max``
        related file SHA-256 hashes (0 disables it).

        Returns a dict with:
        - "scan": parsed scan dict (or None when no scan exists)
        - "related_files": list of SHA-256 strings
        - "errors": reportable error_info dicts (never "no results")
        """
        result: dict[str, Any] = {"scan": None, "related_files": [], "errors": []}
        log_value = loggable_network_value(value, observable_type)

        communities = [(self.polyswarm, self.polyswarm_community)]
        if self.polyswarm_community.lower() == "private" and self.polyswarm_default:
            communities.append((self.polyswarm_default, "default"))

        scans = []
        for polyswarm_instance, community_name in communities:
            scan, error = self._search_url_single_community(
                value, polyswarm_instance, community_name, log_value
            )
            if scan:
                scans.append(scan)
            elif error and not error.get("is_no_results"):
                result["errors"].append(error)

        if scans:
            oldest = datetime.min.replace(tzinfo=timezone.utc)
            result["scan"] = max(scans, key=lambda s: s["scan_date_dt"] or oldest)

        ioc_kind = {"IPv4-Addr": "ip", "IPv6-Addr": "ip", "Domain-Name": "domain"}.get(
            observable_type
        )
        if ioc_kind and related_files_max > 0:
            for polyswarm_instance, community_name in communities:
                remaining = related_files_max - len(result["related_files"])
                if remaining <= 0:
                    break
                hashes, error = self._search_related_files(
                    ioc_kind, value, polyswarm_instance, community_name, remaining
                )
                if error:
                    result["errors"].append(error)
                for sha256 in hashes:
                    if sha256 not in result["related_files"]:
                        result["related_files"].append(sha256)

        self.helper.connector_logger.info(
            "[CLIENT] Network observable lookup done",
            {
                "value": log_value,
                "scan_found": result["scan"] is not None,
                "related_files": len(result["related_files"]),
                "errors": len(result["errors"]),
            },
        )
        return result
