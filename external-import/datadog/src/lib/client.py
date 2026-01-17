"""DataDog API client for OpenCTI connector"""

import time
from datetime import UTC, datetime
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class DataDogClient:
    """Client for DataDog API interactions"""

    def __init__(self, api_token: str, app_key: str, base_url: str, helper):
        """
        Initialize the API client

        Args:
            api_token: API authentication token
            app_key: DataDog App Key for incidents
            base_url: Base URL for API requests
            helper: OpenCTI connector helper instance
        """
        self.api_token = api_token
        self.app_key = app_key
        self.base_url = base_url.rstrip("/")
        self.helper = helper

        # Setup HTTP session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Set default headers for DataDog API
        self.session.headers.update(
            {
                "DD-API-KEY": self.api_token,
                "Content-Type": "application/json",
                "User-Agent": "OpenCTI-DataDog-Connector/1.0.0",
            }
        )

        # Set headers for incidents API (requires app key)
        self.incident_headers = {
            "DD-API-KEY": self.api_token,
            "DD-APPLICATION-KEY": self.app_key,
            "Content-Type": "application/json",
            "User-Agent": "OpenCTI-DataDog-Connector/1.0.0",
        }

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

        try:
            response = self.session.request(method, url, timeout=30, **kwargs)

            # Handle rate limiting
            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", 60))
                self.helper.log_warning(f"Rate limited, waiting {retry_after} seconds")
                time.sleep(retry_after)
                return self._make_request(method, endpoint, **kwargs)

            response.raise_for_status()
            return response.json()

        except requests.exceptions.RequestException as e:
            self.helper.log_error(f"API request failed: {str(e)}")
            return None
        except ValueError as e:
            self.helper.log_error(f"Invalid JSON response: {str(e)}")
            return None

    def get_alerts(
        self,
        since: datetime,
        priorities: list[str] = None,
        tags_filter: list[str] = None,
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
                "page[limit]": 1000,
                "sort": "-timestamp",
            }

            # Add tag filtering if specified
            if tags_filter:
                params["filter[query]"] = " ".join(
                    [f"@tags:{tag}" for tag in tags_filter]
                )

            # Use headers with app key
            headers = {
                "DD-API-KEY": self.api_token,
                "DD-APPLICATION-KEY": self.app_key,
                "Content-Type": "application/json",
                "User-Agent": "OpenCTI-DataDog-Connector/1.0.0",
            }

            all_signals = []
            next_cursor = None

            # Paginate through results
            while True:
                if next_cursor:
                    params["page[cursor]"] = next_cursor

                response = self._make_request(
                    "GET", endpoint, params=params, headers=headers
                )
                if not response:
                    break

                signals = response.get("data", [])
                all_signals.extend(signals)

                self.helper.log_info(
                    f"Fetched {len(signals)} signals (total so far: {len(all_signals)})"
                )

                # Check for next page
                next_cursor = response.get("meta", {}).get("page", {}).get("after")
                if not next_cursor:
                    break

                # Safety limit
                if len(all_signals) >= 10000:
                    self.helper.log_warning(
                        "Reached 10,000 signal limit, stopping pagination"
                    )
                    break

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

            # Get timestamps
            timestamp = attributes.get("timestamp")
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
                    created = datetime.now(UTC)
            else:
                created = datetime.now(UTC)

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

            # Include the raw signal data for observable extraction from samples
            alert = {
                "id": signal_id,
                "name": title,
                "message": full_description,
                "overall_state": alert_state,
                "priority": priority,
                "severity": severity,
                "tags": attributes.get("tags", []),
                "created": created.isoformat(),
                "modified": created.isoformat(),
                "type": "alert",
                "signal_id": signal_id,
                "rule_id": rule_info.get("id"),
                "rule_name": rule_info.get("name"),
                "attack_type": appsec_info.get("attack_attempt", "unknown"),
                "user_agent": http_info.get(
                    "useragent"
                ),  # Add user agent for observable extraction
                "raw_signal": signal,  # Inaclude raw signal for sample-based observable extraction
            }

            return alert

        except Exception as e:
            self.helper.log_error(f"Error converting signal to alert: {str(e)}")
            return None
