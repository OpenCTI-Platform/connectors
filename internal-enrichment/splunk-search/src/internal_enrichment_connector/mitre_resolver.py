from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

ENTERPRISE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/"
    "enterprise-attack.json"
)

INFRASTRUCTURE_TYPE_OV = {
    "amplification",
    "anonymization",
    "botnet",
    "command-and-control",
    "control-system",
    "exfiltration",
    "firewall",
    "hosting-malware",
    "hosting-target-lists",
    "phishing",
    "reconnaissance",
    "routers-switches",
    "staging",
    "workstation",
    "unknown",
}


class MITREResolver:
    """Fetches and caches MITRE ATT&CK enterprise bundle and provides lookups."""

    def __init__(self, cache_dir: str = ".cache", cache_ttl_days: int = 7):
        self._cache_dir = Path(cache_dir)
        self._cache_ttl_days = cache_ttl_days
        self._cache_path = self._cache_dir / "enterprise-attack.json"
        self._meta_path = self._cache_dir / "enterprise-attack.meta.json"

        self._lock = threading.RLock()
        self._available = False
        self._data_source_by_name: dict[str, dict[str, Any]] = {}
        self._asset_by_name: dict[str, dict[str, Any]] = {}
        self._components_by_source_id: dict[str, list[dict[str, Any]]] = {}

    def initialize(self) -> bool:
        """Fetch bundle if needed, then parse and index content."""
        with self._lock:
            bundle: Optional[dict[str, Any]] = None

            if self._is_cache_fresh():
                bundle = self._load_bundle(self._cache_path)
                if bundle is not None:
                    self._set_bundle(bundle)
                    return True

            bundle = self._fetch_bundle()
            if bundle is not None:
                self._cache_dir.mkdir(parents=True, exist_ok=True)
                self._cache_path.write_text(
                    json.dumps(bundle, ensure_ascii=True), encoding="utf-8"
                )
                self._meta_path.write_text(
                    json.dumps(
                        {
                            "fetched_at": datetime.now(timezone.utc)
                            .replace(microsecond=0)
                            .isoformat(),
                            "source_url": ENTERPRISE_ATTACK_URL,
                        },
                        ensure_ascii=True,
                    ),
                    encoding="utf-8",
                )
                self._set_bundle(bundle)
                return True

            stale_bundle = self._load_bundle(self._cache_path)
            if stale_bundle is not None:
                logger.warning(
                    "MITRE bundle fetch failed, using stale cache from %s",
                    self._cache_path,
                )
                self._set_bundle(stale_bundle)
                return True

            self._available = False
            self._data_source_by_name = {}
            self._asset_by_name = {}
            self._components_by_source_id = {}
            logger.warning("MITRE resolver unavailable: no network and no cache")
            return False

    def resolve_data_source(self, name: str) -> Optional[dict]:
        """Return data source object by exact name (case-insensitive)."""
        if not self._available:
            return None
        return self._data_source_by_name.get(name.casefold())

    def resolve_data_components(self, data_source_id: str) -> list[dict]:
        """Return all data components referencing a data source ID."""
        if not self._available:
            return []
        return list(self._components_by_source_id.get(data_source_id, []))

    def resolve_asset(self, name: str) -> Optional[dict]:
        """Return MITRE asset object by name (case-insensitive)."""
        if not self._available:
            return None
        return self._asset_by_name.get(name.casefold())

    def get_infrastructure_types(self, asset: dict) -> list[str]:
        """Map MITRE asset platform/sectors fields to STIX infrastructure types."""
        if not isinstance(asset, dict):
            return ["unknown"]

        values: list[str] = []
        values.extend(asset.get("x_mitre_platforms") or [])
        values.extend(asset.get("sectors") or [])
        combined = " ".join(str(v).lower() for v in values)

        resolved: set[str] = set()
        if any(k in combined for k in ("router", "switch", "network device")):
            resolved.add("routers-switches")
        if "firewall" in combined:
            resolved.add("firewall")
        if any(k in combined for k in ("workstation", "desktop", "laptop", "endpoint")):
            resolved.add("workstation")
        if any(k in combined for k in ("ics", "scada", "control system")):
            resolved.add("control-system")
        if any(
            k in combined for k in ("command and control", "command-and-control", "c2")
        ):
            resolved.add("command-and-control")
        if "phishing" in combined:
            resolved.add("phishing")
        if "recon" in combined:
            resolved.add("reconnaissance")
        if "staging" in combined:
            resolved.add("staging")
        if "botnet" in combined:
            resolved.add("botnet")
        if any(k in combined for k in ("anonym", "vpn", "tor", "proxy")):
            resolved.add("anonymization")
        if any(
            k in combined for k in ("hosting malware", "malware hosting", "malware")
        ):
            resolved.add("hosting-malware")
        if "target list" in combined:
            resolved.add("hosting-target-lists")
        if "exfil" in combined:
            resolved.add("exfiltration")
        if "amplification" in combined:
            resolved.add("amplification")

        if not resolved:
            return ["unknown"]
        return sorted(t for t in resolved if t in INFRASTRUCTURE_TYPE_OV)

    def validate_names(self, names: list[str]) -> list[str]:
        """Return names that do not match known MITRE data sources."""
        if not self._available:
            return list(names)

        invalid: list[str] = []
        for name in names:
            key = str(name).casefold()
            if key not in self._data_source_by_name:
                invalid.append(name)
        return invalid

    @property
    def is_available(self) -> bool:
        """True if the bundle has been loaded successfully."""
        return self._available

    @property
    def data_source_names(self) -> list[str]:
        """All known MITRE data source names."""
        return sorted(obj.get("name", "") for obj in self._data_source_by_name.values())

    def _is_cache_fresh(self) -> bool:
        if not self._cache_path.exists() or not self._meta_path.exists():
            return False
        try:
            meta = json.loads(self._meta_path.read_text(encoding="utf-8"))
            fetched_at = datetime.fromisoformat(meta["fetched_at"])
            if fetched_at.tzinfo is None:
                fetched_at = fetched_at.replace(tzinfo=timezone.utc)
            return datetime.now(timezone.utc) - fetched_at < timedelta(
                days=self._cache_ttl_days
            )
        except Exception:
            return False

    def _load_bundle(self, path: Path) -> Optional[dict[str, Any]]:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Failed reading MITRE bundle cache %s: %s", path, exc)
            return None

    def _fetch_bundle(self) -> Optional[dict[str, Any]]:
        try:
            response = requests.get(ENTERPRISE_ATTACK_URL, timeout=30)
            response.raise_for_status()
            return response.json()
        except Exception as exc:
            logger.warning("Failed fetching MITRE bundle: %s", exc)
            return None

    def _set_bundle(self, bundle: dict[str, Any]) -> None:
        objects = bundle.get("objects", []) if isinstance(bundle, dict) else []

        data_source_by_name: dict[str, dict[str, Any]] = {}
        asset_by_name: dict[str, dict[str, Any]] = {}
        components_by_source_id: dict[str, list[dict[str, Any]]] = {}

        for obj in objects:
            if not isinstance(obj, dict):
                continue
            obj_type = obj.get("type")
            name = obj.get("name")
            if obj_type == "x-mitre-data-source" and name:
                data_source_by_name[str(name).casefold()] = obj
            elif obj_type == "x-mitre-asset" and name:
                asset_by_name[str(name).casefold()] = obj
            elif obj_type == "x-mitre-data-component":
                source_id = obj.get("x_mitre_data_source_ref")
                if source_id:
                    components_by_source_id.setdefault(str(source_id), []).append(obj)

        self._data_source_by_name = data_source_by_name
        self._asset_by_name = asset_by_name
        self._components_by_source_id = components_by_source_id
        self._available = True
