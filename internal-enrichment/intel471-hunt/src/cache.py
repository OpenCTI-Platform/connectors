"""UUID + last_updated cache so repeated enrichments skip unchanged hunts."""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

LOGGER = logging.getLogger(__name__)


def _parse_iso(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


class HuntCache:
    """Tiny JSON-file cache, single-process safe via an in-memory lock."""

    def __init__(self, path: str, ttl_hours: int = 24):
        self._path = Path(path)
        self._ttl = timedelta(hours=ttl_hours)
        self._lock = threading.Lock()
        self._data: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            with self._path.open("r", encoding="utf-8") as fh:
                self._data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            LOGGER.warning("Cache load failed (%s); starting empty", exc)
            self._data = {}

    def _flush(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            prefix=self._path.name, dir=str(self._path.parent)
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self._data, fh, indent=2, sort_keys=True)
            os.replace(tmp_path, self._path)
        except OSError:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise

    def is_fresh(self, uuid: str, last_updated: str) -> bool:
        """True if (uuid, last_updated) is cached and still within TTL."""
        if not uuid:
            return False
        with self._lock:
            entry = self._data.get(uuid.lower())
        if not entry:
            return False
        if entry.get("last_updated") != last_updated:
            return False
        cached_at = _parse_iso(entry.get("cached_at", ""))
        if cached_at is None:
            return False
        return datetime.now(timezone.utc) - cached_at < self._ttl

    def mark(self, uuid: str, last_updated: str) -> None:
        if not uuid:
            return
        with self._lock:
            self._data[uuid.lower()] = {
                "last_updated": last_updated,
                "cached_at": datetime.now(timezone.utc).isoformat(),
            }
            self._flush()
