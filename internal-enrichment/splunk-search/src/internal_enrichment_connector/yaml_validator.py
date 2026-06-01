from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from .infrastructure import INFRASTRUCTURE_TYPE_NORMALIZATION
from .mitre_resolver import INFRASTRUCTURE_TYPE_OV

if TYPE_CHECKING:
    from .cim_mitre_mapper import CIMToMITREMapper
    from .mitre_resolver import MITREResolver

VALID_ENTITY_TYPES = {"SecurityPlatform", "Infrastructure", "Software"}


@dataclass
class ValidationResult:
    """Result of YAML validation."""

    valid: bool
    errors: list[str]
    warnings: list[str]


class YAMLValidator:
    """Validates sourcetype map entries against MITRE and STIX vocabularies."""

    def __init__(
        self,
        mitre_resolver: "MITREResolver",
        cim_mapper: Optional["CIMToMITREMapper"] = None,
    ):
        """Initialize YAML validator.

        Args:
            mitre_resolver: Resolver used to validate MITRE data source names.
            cim_mapper: Optional mapper to resolve MITRE data sources from datamodels.
        """
        self._mitre_resolver = mitre_resolver
        self._cim_mapper = cim_mapper

    def validate(self, yaml_entries: dict) -> ValidationResult:
        """Validate sourcetype map entries and return errors/warnings."""
        errors: list[str] = []
        warnings: list[str] = []

        entries = yaml_entries.get("sourcetype_map", yaml_entries)
        if not isinstance(entries, dict):
            return ValidationResult(
                valid=False,
                errors=["YAML validation: expected a mapping of sourcetype entries"],
                warnings=[],
            )

        for sourcetype, entry in entries.items():
            if str(sourcetype).startswith("_"):
                continue
            if not isinstance(entry, dict):
                errors.append(
                    f"{sourcetype}: entry must be a mapping, got {type(entry).__name__}"
                )
                continue

            if entry.get("skip") is True:
                continue

            entity_type = entry.get("entity_type")
            if entity_type not in VALID_ENTITY_TYPES:
                errors.append(
                    f"{sourcetype}: invalid entity_type '{entity_type}', expected SecurityPlatform, Infrastructure, or Software"
                )
                continue

            if entity_type != "Infrastructure":
                continue

            mitre_sources = self._resolve_mitre_sources(entry)
            if not mitre_sources:
                warnings.append(f"{sourcetype}: missing MITRE coverage")
            elif self._mitre_resolver.is_available:
                invalid = self._mitre_resolver.validate_names(mitre_sources)
                for invalid_name in invalid:
                    errors.append(
                        f"{sourcetype}: invalid MITRE data source '{invalid_name}'"
                    )
            else:
                warnings.append(
                    f"{sourcetype}: MITRE resolver unavailable, data source names not validated"
                )

            infrastructure_types = entry.get("infrastructure_types") or []
            if not infrastructure_types:
                warnings.append(
                    f"{sourcetype}: missing infrastructure_types for Infrastructure entry"
                )
            for value in infrastructure_types:
                raw = str(value).strip().lower()
                if raw in INFRASTRUCTURE_TYPE_OV:
                    continue
                if raw in INFRASTRUCTURE_TYPE_NORMALIZATION:
                    warnings.append(
                        f"{sourcetype}: normalizable infrastructure_type '{raw}'"
                    )
                    continue
                normalized = INFRASTRUCTURE_TYPE_NORMALIZATION.get(raw)
                if normalized and normalized in INFRASTRUCTURE_TYPE_OV:
                    warnings.append(
                        f"{sourcetype}: normalizable infrastructure_type '{raw}'"
                    )
                    continue
                if raw not in INFRASTRUCTURE_TYPE_OV:
                    errors.append(f"{sourcetype}: invalid infrastructure_type '{raw}'")

        return ValidationResult(
            valid=len(errors) == 0, errors=errors, warnings=warnings
        )

    def _resolve_mitre_sources(self, entry: dict) -> list[str]:
        explicit = entry.get("mitre_data_sources") or []
        if explicit:
            return sorted({str(name) for name in explicit if str(name).strip()})

        if (
            self._cim_mapper is not None
            and self._cim_mapper.is_available
            and entry.get("datamodels")
        ):
            return self._cim_mapper.resolve(entry)
        return []
