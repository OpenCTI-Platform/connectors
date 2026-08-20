import ipaddress
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlparse

import requests
from polyswarm_enrichment.polyswarm_client import PolyswarmAPI, polyswarm_exceptions


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
            "429" in error_str
            or "quota" in error_str.lower()
            or "rate" in error_str.lower()
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

            results = polyswarm_instance.search(hash_value)

            for result in results:
                data = self._parse_result(result, community_name)
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

    def query_polyswarm(self, hash_value: str) -> dict[str, Any]:
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
