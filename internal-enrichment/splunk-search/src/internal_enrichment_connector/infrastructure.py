from __future__ import annotations

from typing import Optional

from pycti import Infrastructure as PyctiInfrastructure

from .mitre_resolver import INFRASTRUCTURE_TYPE_OV

INFRASTRUCTURE_TYPE_NORMALIZATION = {
    "cloud-service": "unknown",
    "cloud-security": "unknown",
    "endpoint-security": "workstation",
    "endpoint": "workstation",
    "identity-provider": "unknown",
    "ids": "unknown",
    "network": "routers-switches",
    "network-device": "routers-switches",
    "vulnerability-scanner": "reconnaissance",
    "proxy": "unknown",
    "load-balancer": "unknown",
    "waf": "firewall",
    "siem": "unknown",
    "edr": "workstation",
    "ndr": "unknown",
    "soar": "unknown",
    "dlp": "unknown",
    "email-security": "unknown",
    "dns-security": "unknown",
    "casb": "unknown",
}


class InfrastructureBuilder:
    """Builds STIX Infrastructure objects from sourcetype map entries."""

    def __init__(
        self,
        mitre_resolver: Optional["MITREResolver"] = None,
        cim_mapper: Optional["CIMToMITREMapper"] = None,
    ):
        self._mitre_resolver = mitre_resolver
        self._cim_mapper = cim_mapper

    def build(self, sourcetype_entry: dict) -> Optional[dict]:
        """Build a STIX Infrastructure dict from a sourcetype mapping entry."""
        if sourcetype_entry.get("entity_type") != "Infrastructure":
            return None

        vendor = (sourcetype_entry.get("vendor") or "").strip()
        product = (sourcetype_entry.get("product") or "").strip()
        name = " ".join(part for part in (vendor, product) if part).strip() or product

        infrastructure_types: list[str] = []
        original_types: list[str] = []
        for raw_type in sourcetype_entry.get("infrastructure_types") or []:
            raw = str(raw_type).strip().lower()
            if not raw:
                continue
            original_types.append(raw)
            normalized = INFRASTRUCTURE_TYPE_NORMALIZATION.get(raw, raw)
            if (
                normalized in INFRASTRUCTURE_TYPE_OV
                and normalized not in infrastructure_types
            ):
                infrastructure_types.append(normalized)

        mitre_sources = self._resolve_mitre_sources(sourcetype_entry)
        infrastructure_types.extend(
            t
            for t in self._resolve_types_from_mitre(mitre_sources)
            if t not in infrastructure_types
        )

        if not infrastructure_types:
            infrastructure_types = ["unknown"]

        output = {
            "type": "infrastructure",
            "id": self.generate_deterministic_id(name),
            "name": name,
            "infrastructure_types": infrastructure_types,
        }

        description = (sourcetype_entry.get("description") or "").strip()
        if original_types:
            platform_type = ",".join(sorted(set(original_types)))
            if description:
                description = f"{description} (platform_type: {platform_type})"
            else:
                description = f"platform_type: {platform_type}"
        if mitre_sources:
            mitre_text = ", ".join(mitre_sources)
            if description:
                description = f"{description} | MITRE Data Sources: {mitre_text}"
            else:
                description = f"MITRE Data Sources: {mitre_text}"
        if description:
            output["description"] = description

        external_refs = self._build_mitre_external_references(mitre_sources)
        if external_refs:
            output["external_references"] = external_refs

        return output

    def generate_deterministic_id(self, name: str) -> str:
        """Generate deterministic STIX Infrastructure ID from name."""
        return PyctiInfrastructure.generate_id(name=name)

    def _resolve_mitre_sources(self, sourcetype_entry: dict) -> list[str]:
        explicit = sourcetype_entry.get("mitre_data_sources") or []
        if explicit:
            return sorted({str(name) for name in explicit if str(name).strip()})
        if self._cim_mapper is None or not self._cim_mapper.is_available:
            return []
        return self._cim_mapper.resolve(sourcetype_entry)

    def _resolve_types_from_mitre(self, mitre_sources: list[str]) -> list[str]:
        if self._mitre_resolver is None or not self._mitre_resolver.is_available:
            return []

        resolved: list[str] = []
        for source_name in mitre_sources:
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

    def _build_mitre_external_references(self, mitre_sources: list[str]) -> list[dict]:
        if self._mitre_resolver is None or not self._mitre_resolver.is_available:
            return []

        refs: list[dict] = []
        for source_name in mitre_sources:
            source_obj = self._mitre_resolver.resolve_data_source(str(source_name))
            if source_obj is None:
                continue
            source_id = source_obj.get("id")
            if not source_id:
                continue
            refs.append(
                {
                    "source_name": "mitre-attack-data-source",
                    "external_id": source_id,
                    "description": str(source_obj.get("name") or source_name),
                }
            )
        return refs
