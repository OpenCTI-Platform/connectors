"""DataDog API client for OpenCTI connector"""

import time
from datetime import UTC, datetime
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class DataDogClient:
    """Client for DataDog API interactions"""

    # Cap how many times ``_make_request`` will sleep + retry after a
    # 429 response before giving up and returning ``None``. The previous
    # shape recursed unboundedly on every 429, which would hit Python's
    # recursion limit (~1000) when DataDog kept the rate-limit active —
    # turning a transient API condition into a hard process crash.
    _MAX_RATE_LIMIT_RETRIES = 5
    _MAX_RATE_LIMIT_SLEEP = 300

    # Hard ceiling on the number of Security Signals a single
    # ``get_alerts`` cycle will pull from the v2 endpoint. The cap is
    # a defensive backstop against an operator pointing the connector
    # at a huge import window (``DATADOG_IMPORT_START_DATE``) paired
    # with chatty rules — without it a single cycle could paginate
    # forever and exhaust memory before any bundle is sent. Hitting
    # the cap is treated as a pagination failure (``get_alerts``
    # returns ``None``) so the state cursor is NOT advanced and the
    # connector retries the same window on the next cycle — giving
    # the operator a chance to narrow the window / tighten the
    # filters before the cap silently truncates more data.
    _MAX_SIGNALS_PER_CYCLE = 10000

    def __init__(
        self,
        api_token: str,
        app_key: str,
        base_url: str,
        helper,
        batch_size: int = 100,
    ):
        """
        Initialize the API client

        Args:
            api_token: API authentication token
            app_key: DataDog App Key for incidents
            base_url: Base URL for API requests
            helper: OpenCTI connector helper instance
            batch_size: Page-size for paginated ``page[limit]`` queries
                against the v2 endpoints (DataDog caps this at 1000).
        """
        self.api_token = api_token
        self.app_key = app_key
        self.base_url = base_url.rstrip("/")
        self.helper = helper
        # Clamp the batch size to DataDog's documented v2 limit so we
        # never send a ``page[limit]`` that DataDog will reject.
        self.batch_size = max(1, min(int(batch_size), 1000))

        # Setup HTTP session with retry strategy.
        #
        # 429 (Too Many Requests) is intentionally NOT in the
        # ``status_forcelist``: ``_make_request`` already runs its own
        # 429 handler that respects the server-supplied
        # ``Retry-After`` header (capped at ``_MAX_RATE_LIMIT_SLEEP``)
        # and bounds the retry count via
        # ``_MAX_RATE_LIMIT_RETRIES``. Letting the adapter ALSO retry
        # on 429 used to multiply the two budgets (3 adapter retries
        # ×  5 manual retries = up to 15 attempts per request, with
        # cumulative delays from both layers' backoff) — which both
        # made rate-limit windows much slower than intended and
        # triggered DataDog's longer-window throttle on top of the
        # short-window one. Keep the adapter focused on transient
        # 5xx-class server failures (where requests' default Retry
        # policy is appropriate) and leave 429 to the explicit
        # rate-limit handler downstream.
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Set default headers for the DataDog Security Monitoring v2
        # API. Both the API key (``DD-API-KEY``) and the application
        # key (``DD-APPLICATION-KEY``) are required on every signal-
        # search call — the v2 ``/api/v2/security_monitoring/signals``
        # endpoint rejects calls missing the App key with a 403, so
        # the App key MUST live on the session itself rather than on
        # a request-specific override (and there is no longer a
        # second header dict for an unimplemented Incidents API path
        # that used to live here).
        self.session.headers.update(
            {
                "DD-API-KEY": self.api_token,
                "DD-APPLICATION-KEY": self.app_key,
                "Content-Type": "application/json",
                "User-Agent": "OpenCTI-DataDog-Connector/1.0.0",
            }
        )

    def _make_request(
        self, method: str, endpoint: str, **kwargs
    ) -> dict[str, Any] | None:
        """
        Make HTTP request to API

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path
            **kwargs: Additional arguments for requests

        Returns:
            Response JSON data or None if error
        """
        url = f"{self.base_url}/{endpoint.lstrip('/')}"

        for attempt in range(self._MAX_RATE_LIMIT_RETRIES + 1):
            try:
                response = self.session.request(method, url, timeout=30, **kwargs)
            except requests.exceptions.RequestException as exc:
                self.helper.log_error(f"API request failed: {exc}")
                return None

            # Handle rate limiting with a bounded retry loop rather
            # than recursion — DataDog can keep returning 429s for a
            # long while during a rate-limit window, and the previous
            # recursive shape would eventually hit Python's recursion
            # limit (~1000) and crash the connector. We respect the
            # server-supplied ``Retry-After`` header, capped at
            # ``_MAX_RATE_LIMIT_SLEEP`` so a misbehaving server can't
            # pin a worker for hours.
            if response.status_code == 429:
                if attempt >= self._MAX_RATE_LIMIT_RETRIES:
                    self.helper.log_error(
                        "Rate limited after "
                        f"{self._MAX_RATE_LIMIT_RETRIES} retries; giving up"
                    )
                    return None
                try:
                    retry_after = int(response.headers.get("Retry-After", "60"))
                except (TypeError, ValueError):
                    retry_after = 60
                retry_after = max(1, min(retry_after, self._MAX_RATE_LIMIT_SLEEP))
                self.helper.log_warning(
                    "Rate limited, waiting "
                    f"{retry_after}s (attempt {attempt + 1}/"
                    f"{self._MAX_RATE_LIMIT_RETRIES})"
                )
                time.sleep(retry_after)
                continue

            try:
                response.raise_for_status()
                return response.json()
            except requests.exceptions.RequestException as exc:
                self.helper.log_error(f"API request failed: {exc}")
                return None
            except ValueError as exc:
                self.helper.log_error(f"Invalid JSON response: {exc}")
                return None

        return None

    def get_alerts(
        self,
        since: datetime,
        priorities: list[str] | None = None,
        tags_filter: list[str] | None = None,
    ) -> dict[str, Any] | None:
        """
        Get DataDog security signals

        Args:
            since: Start time for security signals
            priorities: Signal severities to filter by (P1-P5)
            tags_filter: Tags to filter by

        Returns:
            Security signals data or None if error
        """
        try:
            # Use DataDog v2 Security Monitoring API
            endpoint = "api/v2/security_monitoring/signals"

            # Format timestamps for API (milliseconds since epoch)
            since_aware = since.replace(tzinfo=UTC) if since.tzinfo is None else since
            now = datetime.now(UTC)

            params = {
                "filter[from]": int(since_aware.timestamp() * 1000),
                "filter[to]": int(now.timestamp() * 1000),
                "page[limit]": self.batch_size,
                "sort": "-timestamp",
            }

            # Add tag filtering if specified
            if tags_filter:
                params["filter[query]"] = " ".join(
                    [f"@tags:{tag}" for tag in tags_filter]
                )

            # No per-request ``headers`` override — the session
            # itself carries both ``DD-API-KEY`` and
            # ``DD-APPLICATION-KEY`` (set in ``__init__``), which is
            # exactly what the v2 Security Monitoring API requires
            # on every signal-search call.
            all_signals = []
            next_cursor = None
            # ``pagination_failed`` flips to True if any page fetch
            # returns ``None`` (the bounded 429 retry exhausted, a 5xx
            # blew through, etc.). We MUST surface that to the caller
            # — silently returning ``success=True`` with partial data
            # would cause the connector to advance the state cursor
            # past signals it never actually fetched, permanently
            # skipping them on the next cycle.
            pagination_failed = False

            # Paginate through results
            while True:
                if next_cursor:
                    params["page[cursor]"] = next_cursor

                response = self._make_request("GET", endpoint, params=params)
                if not response:
                    self.helper.log_error(
                        "Security Signals pagination aborted: page fetch failed "
                        f"after {len(all_signals)} signal(s); the state cursor "
                        "will NOT be advanced so the remaining window is "
                        "retried on the next cycle."
                    )
                    pagination_failed = True
                    break

                signals = response.get("data", [])
                all_signals.extend(signals)

                # Per-page progress is a debug-only diagnostic. With a
                # small ``DATADOG_BATCH_SIZE`` (the documented sample
                # default is 100) and a large import window
                # (``DATADOG_IMPORT_START_DATE`` set to days ago after
                # a connector outage), the previous ``log_info`` here
                # produced hundreds of "Fetched N signals (total so
                # far: M)" lines per cycle in production — drowning
                # out the once-per-cycle "Security Signals API
                # returned N total signals" / "Signal filtering: N →
                # M passed filters" info-level summary just below.
                # The cycle-level summary lines remain at ``info``;
                # only the per-page breadcrumb is debug.
                self.helper.log_debug(
                    f"Fetched {len(signals)} signals (total so far: {len(all_signals)})"
                )

                # Check for next page
                next_cursor = response.get("meta", {}).get("page", {}).get("after")
                if not next_cursor:
                    break

                # Defensive cap on the per-cycle signal count.
                #
                # Hitting the cap is treated as a pagination failure:
                # ``get_alerts`` returns ``None``, the connector flags
                # the Work as in-error, and the state cursor is NOT
                # advanced — so the same window is retried on the
                # next cycle instead of advancing past the (still
                # unfetched) tail of signals. The previous shape
                # broke the loop and returned ``success=True`` with
                # the partial set, which would advance the cursor
                # past the cap on the next ``send_stix2_bundle`` and
                # silently drop every signal beyond the 10,000th
                # forever. Operators who genuinely need a larger
                # window should narrow it via
                # ``DATADOG_IMPORT_START_DATE`` /
                # ``DATADOG_IMPORT_INTERVAL`` or tighten filters
                # rather than trust a silent truncation.
                if len(all_signals) >= self._MAX_SIGNALS_PER_CYCLE:
                    self.helper.log_error(
                        "Security Signals pagination aborted: hit the "
                        f"{self._MAX_SIGNALS_PER_CYCLE:,}-signal per-cycle cap "
                        f"after {len(all_signals)} signal(s); the state cursor "
                        "will NOT be advanced so the same window is retried on "
                        "the next cycle. Narrow DATADOG_IMPORT_START_DATE / "
                        "DATADOG_IMPORT_INTERVAL or tighten "
                        "DATADOG_ALERT_PRIORITIES / DATADOG_ALERT_TAGS_FILTER "
                        "to bring the per-cycle volume back under the cap."
                    )
                    pagination_failed = True
                    break

            if pagination_failed:
                return None

            self.helper.log_info(
                f"Security Signals API returned {len(all_signals)} total signals"
            )

            # Convert signals to alert format and filter
            filtered_alerts = []
            severity_filtered = 0

            for signal in all_signals:
                # Convert signal to alert-like structure
                alert = self._convert_signal_to_alert(signal)
                if not alert:
                    continue

                # Filter by severity (mapped to priority in config)
                if priorities and alert.get("priority"):
                    # Map severity to priority format for filtering
                    severity_priority_map = {
                        "critical": "P1",
                        "high": "P2",
                        "medium": "P3",
                        "low": "P4",
                        "info": "P5",
                    }
                    signal_priority = severity_priority_map.get(
                        alert.get("severity", "").lower()
                    )
                    if signal_priority and signal_priority not in priorities:
                        severity_filtered += 1
                        continue

                filtered_alerts.append(alert)

            self.helper.log_info(
                f"Signal filtering: {len(all_signals)} total → {len(filtered_alerts)} passed filters"
            )

            return {
                "success": True,
                "alerts": filtered_alerts,
                "total": len(filtered_alerts),
            }

        except Exception as e:
            self.helper.log_error(f"Error fetching security signals: {str(e)}")
            return None

    def _convert_signal_to_alert(self, signal: dict[str, Any]) -> dict[str, Any] | None:
        """
        Convert DataDog security signal to alert structure

        Args:
            signal: Security signal data from v2 API

        Returns:
            Alert-like dictionary or None
        """
        try:
            attributes = signal.get("attributes", {})

            # Extract signal info
            signal_id = signal.get("id")

            # Title is nested in attributes.attributes.title
            nested_attrs = attributes.get("attributes", {})
            title = nested_attrs.get("title", "Security Signal")

            # Message is at the top level attributes - filter out %%% content
            message = attributes.get("message", "")
            # Remove the %%% ... %%% portion if present
            if message and "%%%" in message:
                # Split by %%% and take only non-%%% parts
                parts = message.split("%%%")
                # Keep only parts that don't look like the encoded data
                clean_parts = [
                    part.strip()
                    for part in parts
                    if part.strip() and not part.strip().startswith("{")
                ]
                message = " ".join(clean_parts) if clean_parts else ""

            severity = attributes.get("severity", "medium")
            status = attributes.get("status", "open")

            # Ensure severity and status are strings
            if isinstance(severity, int):
                # Map numeric severity to string
                severity_map = {
                    0: "info",
                    1: "low",
                    2: "medium",
                    3: "high",
                    4: "critical",
                }
                severity = severity_map.get(severity, "medium")
            elif not isinstance(severity, str):
                severity = str(severity).lower()
            else:
                severity = severity.lower()

            if not isinstance(status, str):
                status = str(status).lower()
            else:
                status = status.lower()

            # Get timestamps.
            #
            # Both the missing-timestamp branch and the parse-failure
            # branch leave ``created`` as ``None`` rather than falling
            # back to ``datetime.now(UTC)`` — the downstream
            # ``StixConverter`` derives deterministic STIX ids from
            # ``data.get("created") or _FALLBACK_TIMESTAMP``, and a
            # wall-clock fallback here would silently shift the
            # ``created`` value (and therefore the ``Incident`` /
            # ``CaseIncident`` / ``Note`` ids) on every retry of the
            # same signal, defeating dedup. The converter's fixed
            # epoch fallback only kicks in when ``created`` is falsy,
            # so propagating ``None`` here is what makes the
            # deterministic-id contract end-to-end.
            timestamp = attributes.get("timestamp")
            created: datetime | None = None
            if timestamp:
                try:
                    # Handle both string (ISO format) and int (milliseconds)
                    if isinstance(timestamp, str):
                        created = datetime.fromisoformat(
                            timestamp.replace("Z", "+00:00")
                        )
                    else:
                        # Convert milliseconds to datetime
                        created = datetime.fromtimestamp(timestamp / 1000, tz=UTC)
                except (ValueError, TypeError) as e:
                    self.helper.log_warning(
                        f"Failed to parse timestamp '{timestamp}': {e}"
                    )
                    created = None

            # Map severity to priority
            severity_priority_map = {
                "critical": "P1",
                "high": "P2",
                "medium": "P3",
                "low": "P4",
                "info": "P5",
            }
            priority = severity_priority_map.get(severity, "P3")

            # Map status to alert state
            status_map = {"open": "Alert", "under_review": "Alert", "archived": "OK"}
            alert_state = status_map.get(status, "Alert")

            # Extract additional context fields from nested attributes
            workflow = nested_attrs.get("workflow", {})
            rule_info = workflow.get("rule", {})
            appsec_info = nested_attrs.get("appsec", {})
            http_info = nested_attrs.get("http", {})
            service_list = attributes.get("service", [])

            # Build detailed description with extracted fields - one field per line with bold keys
            description_parts = []

            # Add signal and rule IDs
            if signal_id:
                description_parts.append(f"**Signal ID:** {signal_id}")
            if rule_info.get("id"):
                description_parts.append(f"**Rule ID:** {rule_info.get('id')}")
            if rule_info.get("name"):
                description_parts.append(f"**Rule Name:** {rule_info.get('name')}")

            # Add rule tags as comma-separated string
            if rule_info.get("tags"):
                description_parts.append(
                    f"**Rule Tags:** {', '.join(rule_info.get('tags', []))}"
                )

            # Add service information
            if service_list:
                description_parts.append(f"**Service:** {', '.join(service_list)}")

            # Add AppSec information - one field per line
            if appsec_info.get("attack_attempt"):
                description_parts.append(
                    f"**Attack Type:** {appsec_info.get('attack_attempt')}"
                )
            if appsec_info.get("category"):
                description_parts.append(
                    f"**Attack Category:** {appsec_info.get('category')}"
                )
            if appsec_info.get("blocked"):
                description_parts.append(f"**Blocked:** {appsec_info.get('blocked')}")

            # Add HTTP/Network information - flatten all nested fields
            if http_info.get("client_ip"):
                description_parts.append(f"**Client IP:** {http_info.get('client_ip')}")

            # Add geolocation as single fields
            client_ip_details = http_info.get("client_ip_details", {})
            if client_ip_details:
                # Country
                country = client_ip_details.get("country", {})
                if isinstance(country, dict):
                    country_name = country.get("name")
                    if country_name:
                        country_str = (
                            str(country_name)
                            if not isinstance(country_name, list)
                            else country_name[0]
                        )
                        description_parts.append(f"**Country:** {country_str}")
                elif country:
                    description_parts.append(f"**Country:** {str(country)}")

                # Subdivision/State
                subdivision = client_ip_details.get("subdivision", {})
                if isinstance(subdivision, dict):
                    subdiv_name = subdivision.get("name")
                    if subdiv_name:
                        subdiv_str = (
                            str(subdiv_name)
                            if not isinstance(subdiv_name, list)
                            else subdiv_name[0]
                        )
                        description_parts.append(f"**Subdivision:** {subdiv_str}")
                elif subdivision:
                    description_parts.append(f"**Subdivision:** {str(subdivision)}")

                # City
                city = client_ip_details.get("city", {})
                if isinstance(city, dict):
                    city_name = city.get("name")
                    if city_name:
                        city_str = (
                            str(city_name)
                            if not isinstance(city_name, list)
                            else city_name[0]
                        )
                        description_parts.append(f"**City:** {city_str}")
                elif city:
                    description_parts.append(f"**City:** {str(city)}")

                # AS information
                as_info = client_ip_details.get("as", {})
                if as_info.get("name"):
                    description_parts.append(f"**ASN Name:** {as_info.get('name')}")
                if as_info.get("number"):
                    description_parts.append(f"**ASN Number:** {as_info.get('number')}")
                if as_info.get("type"):
                    description_parts.append(f"**Network Type:** {as_info.get('type')}")

            # Add HTTP request details - one field per line
            if http_info.get("method"):
                description_parts.append(f"**HTTP Method:** {http_info.get('method')}")
            if http_info.get("status_code"):
                description_parts.append(
                    f"**HTTP Status Code:** {http_info.get('status_code')}"
                )

            # Add URL details - flatten
            url_details = http_info.get("url_details", {})
            if url_details.get("host"):
                description_parts.append(f"**Host:** {url_details.get('host')}")
            if url_details.get("path"):
                paths = url_details.get("path", [])
                if isinstance(paths, list) and paths:
                    description_parts.append(f"**Path:** {paths[0]}")
                elif isinstance(paths, str):
                    description_parts.append(f"**Path:** {paths}")

            # Add user agent
            if http_info.get("useragent"):
                description_parts.append(
                    f"**User Agent:** {http_info.get('useragent')}"
                )

            # Create clean description - line-by-line format with bold keys
            # Use double newlines for better markdown rendering
            full_description = "\n\n".join(description_parts)

            # Extract the rule query / creator / assignee that
            # ``_extract_alert_context`` (importer) and
            # ``_create_context_note`` (converter) consume — without
            # these three fields, the explanatory Note the README
            # advertises ("monitor query, tags and assignee") would
            # render with empty values for each missing field. The
            # DataDog Security Monitoring v2 signal payload carries
            # them under ``attributes.attributes.workflow``:
            #
            #   * ``workflow.rule.query`` — the monitor query string;
            #   * ``workflow.rule.creation_author_handle`` —
            #     historically the user handle that created the rule;
            #   * ``workflow.triage.assignee`` — the user that was
            #     assigned the triage for this signal (only set once
            #     a user has claimed it).
            #
            # ``_create_context_note`` expects ``creator`` /
            # ``assignee`` as dicts with a ``name`` key, so we
            # normalise to that shape here. Each one is omitted from
            # the alert dict when the upstream signal does not carry
            # the field so the Note rendering's truthiness guards
            # short-circuit cleanly.
            triage_info = workflow.get("triage", {})
            assignee_info = triage_info.get("assignee", {})
            assignee_handle = (
                assignee_info.get("handle") if isinstance(assignee_info, dict) else None
            )
            creator_handle = rule_info.get("creation_author_handle") or rule_info.get(
                "creator_handle"
            )

            alert_creator = {"name": creator_handle} if creator_handle else None
            alert_assignee = {"name": assignee_handle} if assignee_handle else None
            rule_query = rule_info.get("query") or ""

            # Include the raw signal data for observable extraction from samples
            alert = {
                "id": signal_id,
                "name": title,
                "message": full_description,
                "overall_state": alert_state,
                "priority": priority,
                "severity": severity,
                "tags": attributes.get("tags", []),
                # ``created`` is ``None`` when the signal carried no
                # parseable timestamp; serialise that through to the
                # importer as a literal ``None`` so
                # ``_extract_timestamp(None)`` returns ``None`` and
                # the converter picks up the deterministic
                # ``_FALLBACK_TIMESTAMP``. Calling ``.isoformat()`` on
                # a ``None`` here would crash; calling it on a
                # wall-clock ``datetime.now()`` would leak a fresh,
                # non-deterministic value into ``Incident.generate_id``
                # / ``CaseIncident.generate_id`` / ``Note.generate_id``
                # on every retry of the same signal.
                "created": created.isoformat() if created is not None else None,
                "modified": created.isoformat() if created is not None else None,
                "type": "alert",
                "signal_id": signal_id,
                "rule_id": rule_info.get("id"),
                "rule_name": rule_info.get("name"),
                "query": rule_query,
                "creator": alert_creator,
                "assignee": alert_assignee,
                "attack_type": appsec_info.get("attack_attempt", "unknown"),
                "user_agent": http_info.get(
                    "useragent"
                ),  # Add user agent for observable extraction
                "raw_signal": signal,  # Include raw signal for sample-based observable extraction
            }

            return alert

        except Exception as e:
            self.helper.log_error(f"Error converting signal to alert: {str(e)}")
            return None
