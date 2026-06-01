from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml


class CIMToMITREMapper:
    """Maps Splunk CIM data model names to MITRE ATT&CK Data Source names.

    Resolution order for a sourcetype entry:
    1. If mitre_data_sources is explicitly set in YAML, use it directly.
    2. If datamodels is set, resolve via CIM-to-MITRE mapping.
    3. If neither is present, return an empty list.
    """

    def __init__(self, mapping_path: Optional[Path] = None):
        """Initialize mapper and load mapping file.

        Args:
            mapping_path: Optional path to cim_to_mitre.yaml.
                Defaults to data/cim_to_mitre.yaml relative to this module.
        """
        self._mapping_path = mapping_path or (
            Path(__file__).parent / "data" / "cim_to_mitre.yaml"
        )
        self._mapping: dict[str, list[str]] = {}
        self._unmapped_models: set[str] = set()
        self._available = False
        self._load_mapping()

    def resolve(self, sourcetype_entry: dict) -> list[str]:
        """Resolve MITRE Data Source names for a sourcetype entry.

        Args:
            sourcetype_entry: Entry from sourcetype_map with optional
                mitre_data_sources and datamodels fields.

        Returns:
            Deduplicated, sorted MITRE Data Source names.
        """
        explicit_sources = sourcetype_entry.get("mitre_data_sources") or []
        if explicit_sources:
            return sorted({str(name) for name in explicit_sources if str(name).strip()})

        datamodels = sourcetype_entry.get("datamodels") or []
        if not datamodels or not self._available:
            return []

        resolved: set[str] = set()
        for datamodel in datamodels:
            model = str(datamodel)
            mapped_sources = self._mapping.get(model)
            if mapped_sources is None:
                self._unmapped_models.add(model)
                continue
            for source in mapped_sources:
                if str(source).strip():
                    resolved.add(str(source))

        return sorted(resolved)

    @property
    def unmapped_models(self) -> list[str]:
        """Return CIM data model names that had no MITRE mapping."""
        return sorted(self._unmapped_models)

    @property
    def is_available(self) -> bool:
        """True when mapping file loaded successfully."""
        return self._available

    @property
    def mapped_models_count(self) -> int:
        """Return number of CIM models defined in mapping file."""
        return len(self._mapping)

    def _load_mapping(self) -> None:
        try:
            raw = yaml.safe_load(self._mapping_path.read_text(encoding="utf-8")) or {}
            mapping = raw.get("mapping", {}) if isinstance(raw, dict) else {}
            if not isinstance(mapping, dict):
                self._available = False
                self._mapping = {}
                return

            normalized: dict[str, list[str]] = {}
            for key, value in mapping.items():
                model = str(key)
                if isinstance(value, list):
                    normalized[model] = [str(item) for item in value]
                else:
                    normalized[model] = []

            self._mapping = normalized
            self._available = True
        except Exception:
            self._mapping = {}
            self._available = False
