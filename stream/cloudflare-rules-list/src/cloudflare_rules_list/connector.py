"""OpenCTI -> Cloudflare Rules List stream connector.

Listens to the OpenCTI live stream for IPv4 indicators/observables, maintains an
in-memory snapshot of all known IPv4 values, and periodically pushes the full
snapshot to a Cloudflare Rules List (snapshot/replace model).
"""

import json
import re
import sys
import time
from typing import Optional

from pycti import OpenCTIConnectorHelper

from .client import CloudflareAPIError, CloudflareRulesListClient
from .settings import ConnectorSettings

# STIX pattern for an IPv4 indicator: [ipv4-addr:value = '...']
_IPV4_PATTERN_RE = re.compile(r"\[ipv4-addr:value\s*=\s*'([^']+)'\]", re.IGNORECASE)


def _parse_interval(interval_str: str) -> int:
    """Parse an interval like '1h', '30m', '1h30m', or a bare number of seconds.

    Returns the total number of seconds, defaulting to 3600 if parsing fails.
    """
    interval_str = (interval_str or "").lower().strip()
    total_seconds = 0

    hours = re.search(r"(\d+)h", interval_str)
    if hours:
        total_seconds += int(hours.group(1)) * 3600

    minutes = re.search(r"(\d+)m", interval_str)
    if minutes:
        total_seconds += int(minutes.group(1)) * 60

    seconds = re.search(r"(\d+)s", interval_str)
    if seconds:
        total_seconds += int(seconds.group(1))

    if total_seconds == 0 and interval_str.isdigit():
        total_seconds = int(interval_str)

    return total_seconds if total_seconds > 0 else 3600


class Connector:
    """OpenCTI connector for Cloudflare Rules Lists (IPv4)."""

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        config: ConnectorSettings,
        client: CloudflareRulesListClient,
    ):
        self.helper = helper
        self.config = config
        self.client = client
        self.logger = helper.connector_logger

        self.list_id = config.cloudflare.list_id
        self.sync_interval = _parse_interval(config.connector.sync_interval)

        # Snapshot of IPv4 values keyed by OpenCTI id.
        self._indicator_cache: dict[str, str] = {}
        self._last_sync_time = 0.0

    # ------------------------------------------------------------------ #
    # IPv4 extraction
    # ------------------------------------------------------------------ #
    def _extract_ipv4(self, data: dict) -> Optional[str]:
        """Return the IPv4 value from an OpenCTI/STIX object, or None.

        Two representations reach this method with different type keys:
          * Live-stream / STIX shape uses the lowercase STIX ``type`` field
            (``"indicator"``, ``"ipv4-addr"``).
          * OpenCTI API objects (full sync via ``helper.api.*.list``) use the
            capitalized ``entity_type`` field (``"Indicator"``, ``"IPv4-Addr"``)
            and leave ``type`` unset.

        Both indicator shapes carry a STIX ``pattern``; both observable shapes
        carry the address in ``value`` / ``observable_value``.
        """
        stix_type = data.get("type", "")
        entity_type = data.get("entity_type", "")

        # Indicator (stream: type=="indicator"; API: entity_type=="Indicator").
        if stix_type == "indicator" or entity_type == "Indicator":
            pattern = data.get("pattern", "")
            match = _IPV4_PATTERN_RE.search(pattern) if pattern else None
            return match.group(1) if match else None

        # IPv4 observable (stream: type=="ipv4-addr"; API: entity_type=="IPv4-Addr").
        observable_type = entity_type or stix_type
        if observable_type in ("ipv4-addr", "IPv4-Addr"):
            return data.get("value") or data.get("observable_value")

        return None

    @staticmethod
    def _object_id(data: dict) -> Optional[str]:
        """Return the OpenCTI id for a stream/STIX object."""
        return data.get("id") or data.get("x_opencti_id")

    # ------------------------------------------------------------------ #
    # Stream handling
    # ------------------------------------------------------------------ #
    def process_message(self, msg) -> None:
        """Callback for each OpenCTI live-stream event."""
        try:
            try:
                data = json.loads(msg.data)["data"]
            except (json.JSONDecodeError, KeyError, TypeError):
                self.logger.warning("Could not parse stream message data")
                return

            # The initial catch-up event type may be "message"; treat as create.
            event_type = msg.event if getattr(msg, "event", None) else "create"
            if event_type == "message":
                event_type = "create"

            if event_type in ("create", "update"):
                self._handle_upsert(data)
            elif event_type == "delete":
                self._handle_delete(data)
        except (KeyboardInterrupt, SystemExit):
            self.logger.info("Connector stopped")
            sys.exit(0)
        except Exception as exc:  # noqa: BLE001 - never let the stream die
            self.logger.error(
                "Error processing stream message", meta={"error": str(exc)}
            )

    def _handle_upsert(self, data: dict) -> None:
        value = self._extract_ipv4(data)
        if not value:
            return

        indicator_id = self._object_id(data)
        if not indicator_id:
            return

        self._indicator_cache[indicator_id] = value
        self.logger.debug(
            "Cached IPv4 indicator", meta={"id": indicator_id, "value": value}
        )
        self._check_sync()

    def _handle_delete(self, data: dict) -> None:
        indicator_id = self._object_id(data)
        if indicator_id and indicator_id in self._indicator_cache:
            del self._indicator_cache[indicator_id]
            self.logger.debug("Removed indicator from cache", meta={"id": indicator_id})
            self._check_sync()

    # ------------------------------------------------------------------ #
    # Sync to Cloudflare
    # ------------------------------------------------------------------ #
    def _check_sync(self) -> None:
        """Sync to Cloudflare if the configured interval has elapsed."""
        if time.monotonic() - self._last_sync_time >= self.sync_interval:
            self._sync_to_cloudflare()

    def _sync_to_cloudflare(self) -> None:
        """Push the full IPv4 snapshot to the Cloudflare Rules List."""
        if not self._indicator_cache:
            # Nothing to push -- do not open the throttle window, otherwise the
            # first real indicator to arrive could be delayed by up to
            # sync_interval before it is synced.
            self.logger.info("No indicators to sync")
            return

        self._last_sync_time = time.monotonic()

        self.logger.info(
            "Syncing indicators to Cloudflare",
            meta={"count": len(self._indicator_cache), "list_id": self.list_id},
        )

        items = [
            {"ip": value, "comment": f"OpenCTI: {indicator_id}"}
            for indicator_id, value in self._indicator_cache.items()
        ]

        try:
            result = self.client.replace_list_items(self.list_id, items)
            operation_id = result.get("operation_id")
            if operation_id:
                self.logger.info(
                    "Bulk operation started", meta={"operation_id": operation_id}
                )
                final_status = self.client.wait_for_operation(operation_id)
                self.logger.info(
                    "Snapshot uploaded",
                    meta={"count": len(items), "status": final_status.get("status")},
                )
            else:
                self.logger.info("Snapshot uploaded", meta={"count": len(items)})
        except CloudflareAPIError as exc:
            self.logger.error("Failed to sync to Cloudflare", meta={"error": str(exc)})

    # ------------------------------------------------------------------ #
    # Full sync (startup)
    # ------------------------------------------------------------------ #
    def _full_sync(self) -> None:
        """Load all IPv4 indicators and observables from OpenCTI, then sync."""
        self.logger.info("Starting full sync from OpenCTI")
        self._indicator_cache = {}

        indicators = self.helper.api.indicator.list(getAll=True)
        self.logger.info(
            "Fetched indicators from OpenCTI", meta={"count": len(indicators)}
        )
        for indicator in indicators:
            value = self._extract_ipv4(indicator)
            indicator_id = indicator.get("id")
            if value and indicator_id:
                self._indicator_cache[indicator_id] = value

        try:
            observables = self.helper.api.stix_cyber_observable.list(
                types=["IPv4-Addr"], getAll=True
            )
            for observable in observables:
                value = self._extract_ipv4(observable)
                obs_id = observable.get("id")
                if value and obs_id:
                    self._indicator_cache[obs_id] = value
        except Exception as exc:  # noqa: BLE001
            self.logger.warning(
                "Could not fetch IPv4 observables", meta={"error": str(exc)}
            )

        self.logger.info(
            "Loaded IPv4 indicators for sync",
            meta={"count": len(self._indicator_cache)},
        )
        self._sync_to_cloudflare()

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    def run(self) -> None:
        """Verify the target list, full-sync, then listen to the live stream."""
        self.logger.info("Starting Cloudflare Rules List connector")

        # Verify the configured list exists before doing any work.
        try:
            list_info = self.client.get_list(self.list_id)
            self.logger.info(
                "Using Cloudflare list",
                meta={
                    "name": list_info.get("name"),
                    "id": self.list_id,
                    "kind": list_info.get("kind"),
                },
            )
        except CloudflareAPIError as exc:
            self.logger.error(
                "Could not find Cloudflare list",
                meta={"list_id": self.list_id, "error": str(exc)},
            )
            raise

        try:
            self._full_sync()
        except Exception as exc:  # noqa: BLE001
            self.logger.error("Initial full sync failed", meta={"error": str(exc)})

        self.helper.listen_stream(message_callback=self.process_message)
