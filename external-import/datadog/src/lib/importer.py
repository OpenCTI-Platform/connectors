import json
import re
from datetime import UTC, datetime
from typing import Any


class DataImporter:
    """Handles data import processing and validation"""

    def __init__(self, helper):
        """
        Initialize importer

        Args:
            helper: OpenCTI connector helper instance
        """
        self.helper = helper

    def process_datadog_data(
        self, import_data: list[dict[str, Any]], **kwargs
    ) -> dict[str, Any]:
        """
        Process DataDog alerts data

        Args:
            import_data: List of data dictionaries with type and data
            **kwargs: Processing options

        Returns:
            Processed data ready for STIX conversion
        """
        try:
            processed_items = []

            for data_source in import_data:
                data_type = data_source.get("type")
                data_items = data_source.get("data", [])

                self.helper.log_info(f"Processing {len(data_items)} {data_type}")

                if data_type == "alerts":
                    for alert in data_items:
                        processed_alert = self._process_datadog_alert(alert, **kwargs)
                        if processed_alert:
                            processed_items.append(processed_alert)

            return {
                "processed_items": processed_items,
                "total_processed": len(processed_items),
                "timestamp": datetime.now(UTC).isoformat(),
            }

        except Exception as e:
            self.helper.log_error(f"Error processing DataDog data: {str(e)}")
            return {"processed_items": [], "total_processed": 0}

    def _process_datadog_alert(
        self, alert: dict[str, Any], **kwargs
    ) -> dict[str, Any] | None:
        """
        Process a DataDog alert

        Args:
            alert: Raw alert data
            **kwargs: Processing options

        Returns:
            Processed alert or None if invalid
        """
        try:
            # Extract basic alert information
            alert_id = alert.get("id")
            alert_name = alert.get("name", "Unknown Alert")
            alert_message = alert.get("message", "")
            alert_status = alert.get("overall_state", "unknown")
            alert_priority = alert.get("priority", "P4")

            # Extract observables from HTTP request headers in samples
            observables = []
            if kwargs.get("extract_observables_from_alerts", True):
                observables = self._extract_observables_from_http_headers(alert)

            # Map priority to severity
            severity = self._map_priority_to_severity(alert_priority)

            # Extract attack type from alert (for security signals)
            attack_type = alert.get("attack_type", "unknown")

            # Create processed alert
            processed_alert = {
                "id": f"datadog-alert-{alert_id}",
                "type": "alert",
                "name": alert_name,
                "description": alert_message,
                "status": alert_status,
                "priority": alert_priority,
                "severity": severity,
                "attack_type": attack_type,
                "observables": observables,
                "created": self._extract_timestamp(alert.get("created")),
                "modified": self._extract_timestamp(alert.get("modified")),
                "source_data": alert,
                "metadata": {
                    "source": "DataDog",
                    "alert_id": alert_id,
                    "import_timestamp": datetime.now(UTC).isoformat(),
                },
            }

            # Add context if enabled
            if kwargs.get("include_alert_context", True):
                processed_alert["context"] = self._extract_alert_context(alert)

            return processed_alert

        except Exception as e:
            self.helper.log_error(
                f"Error processing alert {alert.get('id', 'unknown')}: {str(e)}"
            )
            return None

    def _extract_observables_from_http_headers(
        self, alert: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """
        Extract observables by recursively searching for specific fields in the response

        Args:
            alert: Alert data containing raw signal with samples

        Returns:
            List of extracted observables
        """
        observables = []

        try:
            # Get the raw signal data
            raw_signal = alert.get("raw_signal", {})
            if not raw_signal:
                self.helper.log_debug(
                    "No raw signal data available for observable extraction"
                )
                return observables

            self.helper.log_info("Recursively searching response for observable fields")

            # Recursively find all values for specific field names
            client_ips = self._find_values_by_key(raw_signal, "client_ip")
            x_real_ips = self._find_values_by_key(raw_signal, "x-real-ip")
            x_forwarded_fors = self._find_values_by_key(raw_signal, "x-forwarded-for")

            hosts = self._find_values_by_key(raw_signal, "host")
            hostnames = self._find_values_by_key(raw_signal, "hostname")

            urls = self._find_values_by_key(raw_signal, "url")

            user_agents = self._find_values_by_key(raw_signal, "user-agent")
            useragents = self._find_values_by_key(raw_signal, "useragent")

            # Process IPs
            all_ips = client_ips + x_real_ips
            for ip in all_ips:
                if isinstance(ip, str):
                    if self._is_valid_ipv4(ip):
                        observables.append(
                            {"type": "ip", "value": ip, "source": "field_search"}
                        )
                    elif self._is_valid_ipv6(ip):
                        observables.append(
                            {"type": "ipv6", "value": ip, "source": "field_search"}
                        )

            # Process x-forwarded-for (can have multiple IPs)
            for xff in x_forwarded_fors:
                if isinstance(xff, str):
                    ips = [ip.strip() for ip in xff.split(",")]
                    for ip in ips:
                        if self._is_valid_ipv4(ip):
                            observables.append(
                                {"type": "ip", "value": ip, "source": "field_search"}
                            )
                        elif self._is_valid_ipv6(ip):
                            observables.append(
                                {"type": "ipv6", "value": ip, "source": "field_search"}
                            )

            # Process hosts/hostnames
            all_hosts = hosts + hostnames
            for host in all_hosts:
                if isinstance(host, str):
                    domain = host.split(":")[0]  # Strip port
                    if self._is_valid_domain(domain):
                        observables.append(
                            {
                                "type": "domain",
                                "value": domain,
                                "source": "field_search",
                            }
                        )

            # Process URLs
            for url in urls:
                if isinstance(url, str) and self._is_valid_url(url):
                    observables.append(
                        {"type": "url", "value": url, "source": "field_search"}
                    )

            # Process user-agents
            all_user_agents = user_agents + useragents
            for ua in all_user_agents:
                if isinstance(ua, str) and ua.strip():
                    observables.append(
                        {"type": "user-agent", "value": ua, "source": "field_search"}
                    )

            # Scan for emails in the entire response
            response_str = json.dumps(raw_signal)
            email_pattern = r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
            email_matches = re.findall(email_pattern, response_str)
            for email in email_matches:
                observables.append(
                    {"type": "email", "value": email, "source": "field_search"}
                )

            # Deduplicate observables
            seen = set()
            unique_observables = []
            for obs in observables:
                key = (obs["type"], obs["value"])
                if key not in seen:
                    seen.add(key)
                    unique_observables.append(obs)

            # Log summary by type
            if unique_observables:
                type_counts = {}
                for obs in unique_observables:
                    obs_type = obs["type"]
                    type_counts[obs_type] = type_counts.get(obs_type, 0) + 1

                summary = ", ".join(
                    [f"{count} {obs_type}" for obs_type, count in type_counts.items()]
                )
                self.helper.log_info(
                    f"Extracted {len(unique_observables)} unique observables: {summary}"
                )
            else:
                self.helper.log_warning("No observables extracted from response")

            return unique_observables

        except Exception as e:
            self.helper.log_error(f"Error extracting observables: {str(e)}")
            import traceback

            self.helper.log_error(traceback.format_exc())
            return observables

    def _find_values_by_key(self, data: Any, target_key: str) -> list[Any]:
        """
        Recursively search for all values with a specific key name

        Args:
            data: Data structure to search (dict, list, or other)
            target_key: Key name to search for

        Returns:
            List of all values found for that key
        """
        results = []

        if isinstance(data, dict):
            for key, value in data.items():
                if key == target_key:
                    # Handle both single values and arrays
                    if isinstance(value, list):
                        results.extend(value)
                    else:
                        results.append(value)
                # Recursively search nested structures
                results.extend(self._find_values_by_key(value, target_key))
        elif isinstance(data, list):
            for item in data:
                results.extend(self._find_values_by_key(item, target_key))

        return results

    def _is_valid_ipv4(self, ip: str) -> bool:
        """
        Validate IPv4 address

        Args:
            ip: IP address string

        Returns:
            True if valid IPv4
        """
        ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        return bool(re.match(ipv4_pattern, ip))

    def _is_valid_ipv6(self, ip: str) -> bool:
        """
        Validate IPv6 address

        Args:
            ip: IP address string

        Returns:
            True if valid IPv6
        """
        ipv6_pattern = r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,7}:$|^:(?::[0-9a-fA-F]{1,4}){1,7}$|^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}$|^(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}$|^(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}$|^[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})$|^:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)$"
        return bool(re.match(ipv6_pattern, ip))

    def _is_valid_domain(self, domain: str) -> bool:
        """
        Validate domain name

        Args:
            domain: Domain name string

        Returns:
            True if valid domain
        """
        # Exclude internal/private domains and IPs
        if (
            not domain
            or domain.startswith("10.")
            or domain.startswith("192.168.")
            or domain.startswith("172.")
        ):
            return False

        domain_pattern = (
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        )
        return bool(re.match(domain_pattern, domain))

    def _is_valid_url(self, url: str) -> bool:
        """
        Validate URL

        Args:
            url: URL string

        Returns:
            True if valid URL
        """
        if not url or not isinstance(url, str):
            return False

        # HTTP/HTTPS URL pattern
        url_pattern = r"^https?://[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*(/.*)?$"
        return bool(re.match(url_pattern, url.strip()))

    def _extract_alert_context(self, alert: dict[str, Any]) -> dict[str, Any]:
        """
        Extract context information from alert

        Args:
            alert: Raw alert data

        Returns:
            Context dictionary
        """
        context = {
            "tags": alert.get("tags", []),
            "monitor_type": alert.get("type", "unknown"),
            "query": alert.get("query", ""),
            "options": alert.get("options", {}),
            "creator": alert.get("creator", {}),
            "org_id": alert.get("org_id"),
        }

        return context

    def _map_priority_to_severity(self, priority: str) -> str:
        """
        Map DataDog priority to severity level

        Args:
            priority: DataDog priority (P0-P5 or None)

        Returns:
            Severity level string
        """
        priority_map = {
            "P0": "critical",
            "P1": "high",
            "P2": "medium",
            "P3": "low",
            "P4": "low",
            "P5": "info",
            None: "unknown",
        }

        return priority_map.get(priority, "unknown")

    def _extract_timestamp(self, timestamp_value: Any) -> datetime | None:
        """
        Extract and parse timestamp

        Args:
            timestamp_value: Timestamp in various formats

        Returns:
            Parsed datetime or None
        """
        if not timestamp_value:
            return None

        try:
            if isinstance(timestamp_value, int | float):
                return datetime.fromtimestamp(timestamp_value)
            elif isinstance(timestamp_value, str):
                # Try ISO format first
                if "T" in timestamp_value:
                    return datetime.fromisoformat(
                        timestamp_value.replace("Z", "+00:00")
                    )
                # Try other common formats
                for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d"]:
                    try:
                        return datetime.strptime(timestamp_value, fmt)
                    except ValueError:
                        continue
        except Exception as e:
            self.helper.log_warning(
                f"Failed to parse timestamp '{timestamp_value}': {str(e)}"
            )

        return None
