from __future__ import annotations

from typing import Optional

from pycti import Infrastructure as PyctiInfrastructure

from .mitre_resolver import INFRASTRUCTURE_TYPE_OV


class InfrastructureBuilder:
    """Builds STIX Infrastructure objects from sourcetype map entries."""

    def __init__(self, mitre_resolver: Optional["MITREResolver"] = None):
        self._mitre_resolver = mitre_resolver

    def build(self, sourcetype_entry: dict) -> Optional[dict]:
        """Build a STIX Infrastructure dict from a sourcetype mapping entry."""
        if sourcetype_entry.get("entity_type") != "Infrastructure":
            return None

        vendor = (sourcetype_entry.get("vendor") or "").strip()
        product = (sourcetype_entry.get("product") or "").strip()
        name = " ".join(part for part in (vendor, product) if part).strip() or product

        infrastructure_types: list[str] = []
        for raw_type in sourcetype_entry.get("infrastructure_types") or []:
            raw = str(raw_type).strip()
            if raw in INFRASTRUCTURE_TYPE_OV and raw not in infrastructure_types:
                infrastructure_types.append(raw)

        infrastructure_types.extend(
            t for t in self._resolve_types_from_mitre(sourcetype_entry) if t not in infrastructure_types
        )

        if not infrastructure_types:
            infrastructure_types = ["unknown"]

        output = {
            "type": "infrastructure",
            "id": self.generate_deterministic_id(name),
            "name": name,
            "infrastructure_types": infrastructure_types,
        }

        description = sourcetype_entry.get("description")
        if description:
            output["description"] = description

        return output

    def generate_deterministic_id(self, name: str) -> str:
        """Generate deterministic STIX Infrastructure ID from name."""
        return PyctiInfrastructure.generate_id(name=name)

    def _resolve_types_from_mitre(self, sourcetype_entry: dict) -> list[str]:
        if self._mitre_resolver is None or not self._mitre_resolver.is_available:
            return []

        resolved: list[str] = []
        for source_name in sourcetype_entry.get("mitre_data_sources") or []:
            source_obj = self._mitre_resolver.resolve_data_source(str(source_name))
            if not source_obj:
                continue
            for asset_name in source_obj.get("x_mitre_platforms") or []:
                asset = self._mitre_resolver.resolve_asset(str(asset_name))
                if not asset:
                    continue
                for infrastructure_type in self._mitre_resolver.get_infrastructure_types(asset):
                    if (
                        infrastructure_type in INFRASTRUCTURE_TYPE_OV
                        and infrastructure_type not in resolved
                    ):
                        resolved.append(infrastructure_type)

        return resolved
