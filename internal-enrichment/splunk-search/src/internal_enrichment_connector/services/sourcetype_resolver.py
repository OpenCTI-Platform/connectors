"""
SourcetypeResolver — loads sourcetype_map.yaml once at import time and
provides case-sensitive lookups for Splunk sourcetype → vendor/platform metadata.
"""

import logging
from copy import deepcopy
from importlib import resources
from typing import Dict, List

import yaml

logger = logging.getLogger(__name__)

_YAML_PACKAGE = "internal_enrichment_connector"
_YAML_RESOURCE = "data/sourcetype_map.yaml"


class SourcetypeResolver:
    """Load and query the static sourcetype → platform mapping.

    The YAML file is read exactly once during ``__init__``.  All lookups are
    O(1) dictionary access.  Keys starting with ``_`` (e.g. ``_metadata``) are
    ignored during loading.
    """

    def __init__(self) -> None:
        self._map: Dict[str, dict] = {}
        self._load()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _load(self) -> None:
        try:
            ref = resources.files(_YAML_PACKAGE).joinpath(_YAML_RESOURCE)
            raw = yaml.safe_load(ref.read_text(encoding="utf-8"))
            sourcetype_map = (
                raw.get("sourcetype_map", {}) if isinstance(raw, dict) else {}
            )
            self._map = {
                k: v for k, v in sourcetype_map.items() if not str(k).startswith("_")
            }
            logger.debug(
                "[RESOLVER] Loaded %d sourcetype mappings from %s",
                len(self._map),
                _YAML_RESOURCE,
            )
        except FileNotFoundError:
            logger.error(
                "[RESOLVER] sourcetype_map.yaml not found at '%s' — resolver will use defaults for all sourcetypes",
                _YAML_RESOURCE,
            )
            self._map = {}
        except Exception as exc:
            logger.error(
                "[RESOLVER] Failed to load sourcetype_map.yaml: %s — resolver will use defaults for all sourcetypes",
                exc,
            )
            self._map = {}

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def resolve(self, sourcetype: str) -> dict:
        """Return the mapping entry for *sourcetype* (case-sensitive).

        If the sourcetype is not found in the map, a default fallback entry is
        returned and a warning is logged.  If the entry has ``skip: true`` the
        entry is returned as-is; the caller is responsible for checking it.

        Args:
            sourcetype: The raw Splunk sourcetype string (e.g. ``"cisco:asa"``).

        Returns:
            A dict with keys: vendor, product, entity_type, datamodels, skip.
            Infrastructure entries additionally contain infrastructure_types.
        """
        entry = self._map.get(sourcetype)
        if entry is None:
            logger.warning(
                "[RESOLVER] Unrecognized sourcetype '%s', using default fallback",
                sourcetype,
            )
            return {
                "vendor": "Unknown",
                "product": sourcetype,
                "entity_type": "Software",
                "datamodels": [],
                "skip": False,
            }
        return entry

    def is_mapped(self, sourcetype: str) -> bool:
        """Return True if *sourcetype* has an explicit entry in the map.

        Returns False for sourcetypes that fall through to the default
        fallback, meaning no YAML entry was found for them.
        """
        return sourcetype in self._map

    def get_all_sourcetypes(self) -> List[str]:
        """Return all known sourcetype keys (for debugging / logging)."""
        return list(self._map.keys())

    def count(self) -> int:
        """Return the number of loaded sourcetype mappings."""
        return len(self._map)

    def get_mapping(self) -> Dict[str, dict]:
        """Return a defensive copy of the full sourcetype mapping."""
        return deepcopy(self._map)
