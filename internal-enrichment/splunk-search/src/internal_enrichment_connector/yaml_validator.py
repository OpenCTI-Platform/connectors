from __future__ import annotations

from dataclasses import dataclass

from .mitre_resolver import INFRASTRUCTURE_TYPE_OV


@dataclass
class ValidationResult:
    """Result of YAML validation."""

    valid: bool
    errors: list[str]
    warnings: list[str]


class YAMLValidator:
    """Validates sourcetype map entries against MITRE and STIX vocabularies."""

    def __init__(self, mitre_resolver: "MITREResolver"):
        self._mitre_resolver = mitre_resolver

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

            entity_type = entry.get("entity_type")
            if entity_type not in {"SecurityPlatform", "Infrastructure"}:
                errors.append(
                    f"{sourcetype}: invalid entity_type '{entity_type}', expected SecurityPlatform or Infrastructure"
                )

            mitre_sources = entry.get("mitre_data_sources")
            if not mitre_sources:
                warnings.append(f"{sourcetype}: missing mitre_data_sources")
            elif self._mitre_resolver.is_available:
                invalid = self._mitre_resolver.validate_names(
                    [str(name) for name in mitre_sources]
                )
                for invalid_name in invalid:
                    errors.append(
                        f"{sourcetype}: invalid MITRE data source '{invalid_name}'"
                    )
            else:
                warnings.append(
                    f"{sourcetype}: MITRE resolver unavailable, data source names not validated"
                )

            infrastructure_types = entry.get("infrastructure_types") or []
            if entity_type == "Infrastructure" and not infrastructure_types:
                warnings.append(
                    f"{sourcetype}: missing infrastructure_types for Infrastructure entry"
                )
            for value in infrastructure_types:
                if value not in INFRASTRUCTURE_TYPE_OV:
                    errors.append(
                        f"{sourcetype}: invalid infrastructure_type '{value}'"
                    )

        return ValidationResult(valid=len(errors) == 0, errors=errors, warnings=warnings)
