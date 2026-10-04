"""OpenCTI -> Cloudflare Rules List stream connector.

Listens to the OpenCTI live stream for IPv4 indicators/observables, maintains an
in-memory snapshot of all known IPv4 values, and periodically pushes the full
snapshot to a Cloudflare Rules List (snapshot/replace model).
"""

import json
import re
import sys
import threading
import time
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Optional

from cloudflare_rules_list.client import (
    CloudflareAPIError,
    CloudflareOperationError,
    CloudflareRulesListClient,
)
from cloudflare_rules_list.settings import ConnectorSettings
from connectors_sdk.connectors.stream.deployment import (
    DeploymentReport,
    DeploymentStatus,
    deployment_failure_reason,
    normalize_value,
    parse_datetime,
)
from pycti import OpenCTIConnectorHelper

if TYPE_CHECKING:
    from connectors_sdk import DeploymentAssurance

# STIX pattern for an IPv4 indicator: [ipv4-addr:value = '...']
_IPV4_PATTERN_RE = re.compile(r"\[ipv4-addr:value\s*=\s*'([^']+)'\]", re.IGNORECASE)

# Prefix of the list item comments, followed by the OpenCTI id of the object.
COMMENT_PREFIX = "OpenCTI: "

PLATFORM_NAME = "Cloudflare"
"""Name of the security platform in the deployment failure reasons."""

UPLOAD_ACTION = "list update"
"""What Cloudflare is asked to do when the snapshot is uploaded."""


def failure_reason(error: CloudflareAPIError) -> str:
    """Return the reason OpenCTI shows for indicators Cloudflare did not take.

    Args:
        error: The error raised while uploading the snapshot.

    Returns:
        One short sentence naming Cloudflare and the cause; the Cloudflare response
        is left to the logs.
    """
    if isinstance(error, CloudflareOperationError):
        if error.timed_out:
            return f"{PLATFORM_NAME} did not complete the {UPLOAD_ACTION} in time"
        return f"{PLATFORM_NAME} refused the {UPLOAD_ACTION}: the bulk operation failed"
    return deployment_failure_reason(PLATFORM_NAME, UPLOAD_ACTION, error.status_code)


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
        self.sync_interval = config.cloudflare.sync_interval.total_seconds()

        # Snapshot of IPv4 values keyed by OpenCTI id.
        self._indicator_cache: dict[str, str] = {}
        # Keys of the snapshot that are indicators (observables are pushed, not reported).
        self._indicator_keys: set[str] = set()
        # Indicators of the last snapshot uploaded, for the deployment write-back.
        self._synced: dict[str, str] = {}
        # Whether the last snapshot uploaded had items (an emptied snapshot clears the list).
        self._list_has_items = False
        # Snapshots accepted so far: each upload gives the list items new ids.
        self._uploads = 0
        # Whether a full sync built the snapshot: before, it only holds the objects of
        # the stream events, and uploading it would remove every other item of the list.
        self._full_sync_done = False
        # The stream and the deployment reconciliation both change the snapshot.
        self._lock = threading.RLock()
        # time.monotonic() counts from the host boot: never synced must open the
        # throttle window whatever the uptime.
        self._last_sync_time = float("-inf")
        # Deployment write-back (dissemination assurance), set by `main.py`.
        self.assurance: "DeploymentAssurance | None" = None

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
        if self._is_indicator(data):
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

    @staticmethod
    def _api_object_id(data: dict) -> Optional[str]:
        """Return the snapshot key of an OpenCTI API object: its STIX standard id, the
        `id` of the same object in the live stream, else its internal id."""
        return data.get("standard_id") or data.get("id")

    @staticmethod
    def _is_indicator(data: dict) -> bool:
        """Tell whether a stream or API object is an indicator (deployment reported)."""
        return data.get("type") == "indicator" or data.get("entity_type") == "Indicator"

    @staticmethod
    def _is_live(data: dict) -> bool:
        """Tell whether an object may be uploaded: neither revoked nor past its
        `valid_until` (objects without validity, such as observables, always are)."""
        if data.get("revoked") is True:
            return False
        valid_until = parse_datetime(data.get("valid_until"))
        return valid_until is None or valid_until > datetime.now(UTC)

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
                changed = self._handle_upsert(data)
            elif event_type == "delete":
                changed = self._handle_delete(data)
            else:
                changed = False
            # Until a full sync succeeds, every stream event retries it.
            if changed or not self._full_sync_done:
                self._check_sync()
        except (KeyboardInterrupt, SystemExit):
            self.logger.info("Connector stopped")
            sys.exit(0)
        except Exception as exc:  # noqa: BLE001 - never let the stream die
            self.logger.error(
                "Error processing stream message", meta={"error": str(exc)}
            )

    def _handle_upsert(self, data: dict) -> bool:
        """Cache the IPv4 value of a created or updated object.

        An object updated without an IPv4 value, revoked or past its `valid_until`
        leaves the snapshot.

        Returns:
            Whether the snapshot was updated.
        """
        indicator_id = self._object_id(data)
        if not indicator_id:
            return False

        value = self._extract_ipv4(data)
        if not value or not self._is_live(data):
            return self._evict(indicator_id)

        with self._lock:
            self._indicator_cache[indicator_id] = value
            if self._is_indicator(data):
                self._indicator_keys.add(indicator_id)
        self.logger.debug(
            "Cached IPv4 indicator", meta={"id": indicator_id, "value": value}
        )
        return True

    def _handle_delete(self, data: dict) -> bool:
        """Drop a deleted object from the snapshot.

        Returns:
            Whether the snapshot was updated.
        """
        indicator_id = self._object_id(data)
        return bool(indicator_id) and self._evict(indicator_id)

    def _evict(self, indicator_id: str) -> bool:
        """Drop an object from the snapshot; the next upload reports it `removed`.

        Returns:
            Whether the snapshot held the object.
        """
        with self._lock:
            if indicator_id not in self._indicator_cache:
                return False
            del self._indicator_cache[indicator_id]
            self._indicator_keys.discard(indicator_id)
        self.logger.debug("Removed indicator from cache", meta={"id": indicator_id})
        return True

    # ------------------------------------------------------------------ #
    # Sync to Cloudflare
    # ------------------------------------------------------------------ #
    def _check_sync(self) -> None:
        """Sync to Cloudflare if the configured interval has elapsed.

        Until a full sync succeeds, the full sync is retried instead (at most once per
        interval) and nothing else is uploaded.
        """
        if time.monotonic() - self._last_sync_time < self.sync_interval:
            return
        if self._full_sync_done:
            self._sync_to_cloudflare()
        else:
            self._retry_full_sync()

    def _retry_full_sync(self) -> None:
        """Retry a failed initial full sync, then start the deployment reconciliation."""
        self._last_sync_time = time.monotonic()
        try:
            self._full_sync()
        except Exception as exc:  # noqa: BLE001 - retried after the next interval
            self.logger.error("Full sync retry failed", meta={"error": str(exc)})
            return
        if self.assurance is not None:
            self.assurance.start()

    def _sync_to_cloudflare(self) -> None:
        """Push the full IPv4 snapshot to the Cloudflare Rules List."""
        with self._lock:
            if not self._indicator_cache and not self._list_has_items:
                # Nothing to push -- do not open the throttle window, otherwise the
                # first real indicator to arrive could be delayed by up to
                # sync_interval before it is synced. An empty snapshot is only
                # uploaded to clear a list the connector filled before.
                self.logger.info("No indicators to sync")
                return
            try:
                self._upload_snapshot()
            except CloudflareAPIError as exc:
                self.logger.error(
                    "Failed to sync to Cloudflare", meta={"error": str(exc)}
                )

    def _upload_snapshot(self) -> None:
        """Replace the Cloudflare Rules List with the snapshot, then report the
        indicators added (`deployed`), dropped (`removed`) or not uploaded (`failed`).

        Raises:
            CloudflareAPIError: When Cloudflare refuses the snapshot.
        """
        with self._lock:
            self._last_sync_time = time.monotonic()
            snapshot = dict(self._indicator_cache)
            indicators = {
                key: value
                for key, value in snapshot.items()
                if key in self._indicator_keys
            }

            self.logger.info(
                "Syncing indicators to Cloudflare",
                meta={"count": len(snapshot), "list_id": self.list_id},
            )

            items = [
                {"ip": value, "comment": f"{COMMENT_PREFIX}{owner}"}
                for value, owner in self._item_owners(snapshot).items()
            ]

            try:
                result = self.client.replace_list_items(self.list_id, items)
                operation_id = result["operation_id"]
                self.logger.info(
                    "Bulk operation started", meta={"operation_id": operation_id}
                )
                final_status = self.client.wait_for_operation(operation_id)
                self.logger.info(
                    "Snapshot uploaded",
                    meta={
                        "count": len(items),
                        "status": final_status.get("status"),
                    },
                )
            except CloudflareAPIError as exc:
                self._report(
                    self._changed(indicators),
                    DeploymentStatus.FAILED,
                    error_message=failure_reason(exc),
                )
                raise
            self._uploads += 1
            self._report(self._changed(indicators), DeploymentStatus.DEPLOYED)
            self._report(
                [key for key in self._synced if key not in indicators],
                DeploymentStatus.REMOVED,
            )
            self._synced = indicators
            self._list_has_items = bool(items)

    @property
    def uploads(self) -> int:
        """Return the number of snapshots Cloudflare accepted so far."""
        with self._lock:
            return self._uploads

    def _item_owners(self, snapshot: dict[str, str]) -> dict[str, str]:
        """Return the object named in the comment of each IP address of a snapshot.

        A Cloudflare list holds an IP address once: an address shared by several
        objects is uploaded as one item, whose comment names the first indicator
        holding it (else the first observable).
        """
        owners: dict[str, str] = {}
        for key, value in snapshot.items():
            owner = owners.get(value)
            if owner is None or (
                owner not in self._indicator_keys and key in self._indicator_keys
            ):
                owners[value] = key
        return owners

    def indicators_of(self, ip: str) -> list[str]:
        """Return the indicators of the last uploaded snapshot holding an IP address."""
        with self._lock:
            return [key for key, value in self._synced.items() if value == ip]

    def forget_absent(self, listed: set[str]) -> None:
        """Forget the uploaded indicators whose IP address the list no longer holds.

        The reconciliation reports an item deleted outside the connector `removed`;
        once forgotten, the indicator differs from the last upload, so the upload
        restoring its item reports it `deployed` again.

        Args:
            listed: Every IP address of the list, read back in full.
        """
        with self._lock:
            for key in [
                key for key, value in self._synced.items() if value not in listed
            ]:
                del self._synced[key]

    def _changed(self, indicators: dict[str, str]) -> list[str]:
        """Return the indicators whose value differs from the last uploaded snapshot."""
        return [
            key for key, value in indicators.items() if self._synced.get(key) != value
        ]

    def _report(
        self, indicator_ids: Iterable[str], status: DeploymentStatus, **fields: Any
    ) -> None:
        """Queue a deployment report per indicator (no-op without write-back)."""
        if self.assurance is None:
            return
        for indicator_id in indicator_ids:
            self.assurance.reporter.enqueue(
                DeploymentReport(indicator_id=indicator_id, status=status, **fields)
            )

    # ------------------------------------------------------------------ #
    # Deployment reconciliation
    # ------------------------------------------------------------------ #
    def push_indicator(self, indicator: dict[str, Any]) -> None:
        """Add an OpenCTI indicator to the snapshot and upload it (reconciliation re-push).

        Args:
            indicator: The indicator, in the stream event shape.

        Raises:
            ValueError: When the indicator has no IPv4 pattern.
            CloudflareAPIError: When Cloudflare refuses the snapshot.
        """
        value = self._extract_ipv4(indicator)
        indicator_id = self._object_id(indicator)
        if not value or not indicator_id:
            if indicator_id:
                self._evict(indicator_id)
            raise ValueError("The indicator has no IPv4 pattern for Cloudflare")
        with self._lock:
            self._indicator_cache[indicator_id] = value
            self._indicator_keys.add(indicator_id)
            self._upload_snapshot()

    def forget_indicator(self, identifiers: Iterable[str]) -> None:
        """Drop an indicator withdrawn while absent from the list from the snapshot.

        The list no longer holds its item, so nothing is deleted and nothing is
        reported: the next upload simply does not restore it.

        Args:
            identifiers: The normalized identifiers of the indicator (OpenCTI ids).
        """
        identifiers = set(identifiers)
        with self._lock:
            for key in [
                key
                for key in self._indicator_cache
                if normalize_value(key) in identifiers
            ]:
                del self._indicator_cache[key]
                self._indicator_keys.discard(key)
                self._synced.pop(key, None)

    def withdraw_item(
        self,
        item_id: str,
        ip: str,
        identifiers: Iterable[str],
        uploads: Optional[int] = None,
    ) -> None:
        """Withdraw an indicator from the list and drop it from the snapshot.

        The list item is deleted, unless another object of the snapshot holds its IP
        address: the snapshot without the indicator is then uploaded again, so the
        item stays for that object and its comment names it. The snapshot is
        uploaded too when an upload since the read-back gave the item a new id
        (several indicators sharing the item withdrawn in one reconciliation).

        Args:
            item_id: The Cloudflare list item id, as read back.
            ip: The IP address of the item.
            identifiers: The normalized identifiers of the indicator (OpenCTI ids).
            uploads: The `uploads` count when the item was read back, if known.

        Raises:
            CloudflareAPIError: When Cloudflare refuses the deletion or the snapshot.
        """
        identifiers = set(identifiers)
        with self._lock:
            keys = [
                key
                for key in self._indicator_cache
                if normalize_value(key) in identifiers
            ]
            shared = any(
                value == ip
                for key, value in self._indicator_cache.items()
                if key not in keys
            )
            stale = uploads is not None and uploads != self._uploads
            if not shared and not stale:
                result = self.client.delete_list_items(self.list_id, [item_id])
                self.client.wait_for_operation(result["operation_id"])
            for key in keys:
                del self._indicator_cache[key]
                self._indicator_keys.discard(key)
                self._synced.pop(key, None)
            if shared or stale:
                self._upload_snapshot()

    # ------------------------------------------------------------------ #
    # Full sync (startup)
    # ------------------------------------------------------------------ #
    def _full_sync(self) -> None:
        """Load all IPv4 indicators and observables from OpenCTI, then upload them.

        The snapshot replaces the list, even when empty (the items a previous run left
        are cleared). The full sync only succeeds once Cloudflare accepted it: when a
        listing fails nothing is uploaded, and a rejected upload raises.

        Raises:
            CloudflareAPIError: When Cloudflare refuses the snapshot.
        """
        self.logger.info("Starting full sync from OpenCTI")
        cache: dict[str, str] = {}
        indicator_keys: set[str] = set()

        indicators = self.helper.api.indicator.list(getAll=True)
        self.logger.info(
            "Fetched indicators from OpenCTI", meta={"count": len(indicators)}
        )
        for indicator in indicators:
            value = self._extract_ipv4(indicator)
            indicator_id = self._api_object_id(indicator)
            if value and indicator_id and self._is_live(indicator):
                cache[indicator_id] = value
                indicator_keys.add(indicator_id)

        observables = self.helper.api.stix_cyber_observable.list(
            types=["IPv4-Addr"], getAll=True
        )
        for observable in observables:
            value = self._extract_ipv4(observable)
            obs_id = self._api_object_id(observable)
            if value and obs_id:
                cache[obs_id] = value

        self.logger.info(
            "Loaded IPv4 indicators for sync",
            meta={"count": len(cache)},
        )
        with self._lock:
            self._indicator_cache = cache
            self._indicator_keys = indicator_keys
            self._upload_snapshot()
            self._full_sync_done = True

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

        # The reconciliation uploads the snapshot: it only starts on a snapshot built by
        # a full sync (the full sync reports are queued until then). After a failed full
        # sync, the stream events retry it and the reconciliation starts once it succeeds.
        if self.assurance is not None:
            if self._full_sync_done:
                self.assurance.start()
            else:
                self.logger.warning(
                    "Deployment reconciliation not started: the initial full sync failed"
                )
                self.assurance.reporter.start()

        self.helper.listen_stream(message_callback=self.process_message)
