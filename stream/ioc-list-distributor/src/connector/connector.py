"""OpenCTI live stream -> local IOC store (see storage/).

Filtering is done by the live stream in OpenCTI. This process only:
- stores the IP / domain / URL / hash values of indicator create and update events,
- removes them on delete events (deleted, or no longer matching the stream filters),
  on revocation and on merges (the merged-away indicators).

Logging: once the pycti helper is up, every line goes through helper.connector_logger
(JSON, with indicator ids and counts as separate "attributes" fields). Routine per-indicator
lines (stored, skipped, deleted, revoked, merged) are DEBUG; at INFO a summary of the stream
activity is logged every SUMMARY_INTERVAL_SECONDS while events arrive.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
from collections import Counter
from typing import Any, Callable

from common import config
from common.storage import open_store
from common.timeutil import to_iso
from common.version import __version__
from connector.ioc_parser import (
    extract_iocs,
    get_score,
    indicator_key,
    opencti_extension,
)

# Used only until the pycti helper (and its connector_logger) exists.
log = logging.getLogger("ioc-connector")

SUMMARY_INTERVAL_SECONDS = 300
# Seconds to wait between tries of a storage call that failed (database locked or
# restarting, disk full): 5 tries over about 15 s, then the event is logged as failed.
STORE_RETRY_DELAYS = (1, 2, 4, 8)


class StoreError(Exception):
    """A storage call still failed after every retry."""


class IocStreamConnector:
    """Listens to one OpenCTI live stream and keeps the IOC store in step with it."""

    def __init__(self) -> None:
        self.settings = config.connector_settings()
        if config.apply_proxy_settings():
            log.info("Outbound proxy enabled for OpenCTI traffic")
        os.makedirs(config.DATA_DIR, exist_ok=True)
        self.store = open_store()
        log.info("IOC store: %s", self.store.describe())
        # Imported after the proxy variables are set.
        from pycti import (  # pylint: disable=import-outside-toplevel
            OpenCTIConnectorHelper,
        )

        self.helper = OpenCTIConnectorHelper(self.settings.helper_config())
        self.logger = self.helper.connector_logger
        self._sleep = time.sleep
        self._clock = time.monotonic
        self._init_counters()
        for warning in self.settings.warnings:
            self.logger.warning(warning)

    def _init_counters(self) -> None:
        self._lock = threading.Lock()
        self._processed = 0
        self._counts: Counter = Counter()
        self._skip_reasons: Counter = Counter()
        self._last_summary = self._clock()

    # ---------------------------------------------------------------- run loop
    def run(self) -> None:
        """Start listening; log the activity summary while the stream thread runs."""
        self.logger.info(
            f"IOC List Distributor {__version__}: connector: listening to live stream "
            f"{self.settings.live_stream_id} on {self.settings.opencti_url}",
            {"version": __version__, "live_stream_id": self.settings.live_stream_id},
        )
        # pycti replaces the listen_stream method with the thread it starts.
        stream = self.helper.listen_stream(  # pylint: disable=not-callable
            message_callback=self._on_message
        )
        # Recent pycti versions return the listening thread; keep the process alive with it.
        if stream is not None and hasattr(stream, "join"):
            while stream.is_alive():
                stream.join(timeout=30)
                self.log_summary()
            self.log_summary(force=True)

    # ------------------------------------------------------------------ events
    def _on_message(self, msg: Any) -> None:
        try:
            self._handle(msg)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            # Never let one bad event stop the stream.
            with self._lock:
                self._counts["failed"] += 1
            self.logger.error(
                f"Could not process stream event {getattr(msg, 'id', '?')} "
                f"({getattr(msg, 'event', '?')}): {exc}",
                {
                    "event_id": getattr(msg, "id", None),
                    "event": getattr(msg, "event", None),
                },
            )

    def _handle(self, msg: Any) -> None:
        event = getattr(msg, "event", None)
        if event not in ("create", "update", "delete", "merge"):
            return
        payload = json.loads(msg.data)
        data = payload.get("data") or {}
        if data.get("type") != "indicator":
            return
        key = indicator_key(data)
        if not key:
            self.logger.warning(
                "Indicator event without an id ignored", {"event": event}
            )
            return

        outcome, skip_reason = self._apply(event, key, data, payload)
        self._store_call(
            "record_event", self.store.record_event, event, outcome == "skipped"
        )
        with self._lock:
            self._processed += 1
            self._counts[event] += 1
            self._counts[outcome] += 1
            if skip_reason:
                self._skip_reasons[skip_reason] += 1
        self.log_summary()

    def _apply(
        self, event: str, key: str, data: dict, payload: dict
    ) -> tuple[str, str | None]:
        """Write one indicator event to the store. Returns (outcome, skip reason or None)."""
        meta = {"indicator_id": key, "event": event}
        if event == "merge":
            for source in (payload.get("context") or {}).get("sources") or []:
                source_key = indicator_key(source) if isinstance(source, dict) else None
                if source_key and source_key != key:
                    removed = self._store_call(
                        "delete_indicator",
                        self.store.delete_indicator,
                        source_key,
                        source.get("id"),
                    )
                    self.logger.debug(
                        f"Indicator {source_key} merged into {key}: {removed} IOC(s) removed",
                        {**meta, "merged_from": source_key, "removed": removed},
                    )

        if event == "delete":
            removed = self._store_call(
                "delete_indicator", self.store.delete_indicator, key, data.get("id")
            )
            self.logger.debug(
                f"Indicator {key} deleted or left the stream filters: {removed} IOC(s) removed",
                {**meta, "removed": removed},
            )
            return "deleted", None
        if data.get("revoked"):
            removed = self._store_call(
                "delete_indicator", self.store.delete_indicator, key, data.get("id")
            )
            self.logger.debug(
                f"Indicator {key} revoked: {removed} IOC(s) removed",
                {**meta, "removed": removed},
            )
            return "revoked", None

        iocs, reason = extract_iocs(data, self.settings.name_fallback)
        if not iocs:
            # The pattern may have been edited into something unsupported: drop old values.
            self._store_call(
                "delete_indicator", self.store.delete_indicator, key, data.get("id")
            )
            self.logger.debug(
                f"Indicator {key} ({data.get('name')}) skipped: {reason}",
                {**meta, "name": data.get("name"), "reason": reason},
            )
            return "skipped", reason

        ext = opencti_extension(data)
        added, updated, removed = self._store_call(
            "upsert_indicator",
            self.store.upsert_indicator,
            key,
            data.get("id"),
            iocs,
            name=data.get("name"),
            score=get_score(data),
            valid_until=to_iso(data.get("valid_until")),
            created=to_iso(data.get("created") or ext.get("created_at")),
            modified=to_iso(data.get("modified") or ext.get("updated_at")),
        )
        self.logger.debug(
            f"Indicator {key} ({event}): +{added} added, {updated} updated, -{removed} removed",
            {**meta, "added": added, "updated": updated, "removed": removed},
        )
        return "stored", None

    # ----------------------------------------------------------------- storage
    def _store_call(
        self, what: str, func: Callable[..., Any], *args: Any, **kwargs: Any
    ) -> Any:
        """Run one storage call, retrying it after STORE_RETRY_DELAYS when it fails.

        Every write is idempotent (an upsert replaces the indicator's values, a delete removes
        them), so a retry never duplicates anything. A call that still fails raises StoreError:
        the event is then logged as failed and the stream goes on.
        """
        tries = len(STORE_RETRY_DELAYS) + 1
        for attempt in range(1, tries + 1):
            try:
                return func(*args, **kwargs)
            except Exception as exc:  # pylint: disable=broad-exception-caught
                if attempt == tries:
                    raise StoreError(
                        f"storage {what} failed {tries} times: {exc}"
                    ) from exc
                delay = STORE_RETRY_DELAYS[attempt - 1]
                self.logger.warning(
                    f"Storage {what} failed (try {attempt} of {tries}), retrying in {delay} s: {exc}",
                    {"operation": what, "attempt": attempt, "retry_in_seconds": delay},
                )
                self._sleep(delay)
        return None  # not reached

    # ----------------------------------------------------------------- summary
    def log_summary(self, force: bool = False) -> None:
        """Log the stream activity since the last summary, at most every SUMMARY_INTERVAL_SECONDS."""
        with self._lock:
            now = self._clock()
            if not force and now - self._last_summary < SUMMARY_INTERVAL_SECONDS:
                return
            self._last_summary = now
            counts, reasons, total = self._counts, self._skip_reasons, self._processed
            self._counts, self._skip_reasons = Counter(), Counter()
        if not counts:
            return
        events = sum(counts[e] for e in ("create", "update", "delete", "merge"))
        parts = [
            f"{counts[o]} {o}"
            for o in ("stored", "deleted", "revoked", "skipped")
            if counts[o]
        ]
        if counts["failed"]:
            parts.append(f"{counts['failed']} failed")
        message = f"Stream: {events} indicator event(s) since the last summary ({', '.join(parts)})"
        if reasons:
            message += "; skipped: " + ", ".join(
                f"{reason} ({count})" for reason, count in sorted(reasons.items())
            )
        message += f"; {total} since start"
        meta = {
            o: counts[o] for o in ("stored", "deleted", "revoked", "skipped", "failed")
        }
        meta.update(
            {
                "events": events,
                "events_since_start": total,
                "skip_reasons": dict(reasons),
            }
        )
        self.logger.info(message, meta)


def main() -> None:
    """Entry point of the connector service."""
    config.setup_logging()
    try:
        IocStreamConnector().run()
    except KeyboardInterrupt:
        pass
    except Exception:  # pylint: disable=broad-exception-caught
        log.exception("Connector stopped on an error")
        sys.exit(1)


if __name__ == "__main__":
    main()
