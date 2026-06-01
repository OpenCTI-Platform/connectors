"""Transform CVE 5.1 records into STIX 2.1 objects and send them to OpenCTI."""

from __future__ import annotations

import json
import re
from typing import Any, Iterable

import stix2
from pycti import (
    Identity,
    Note,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    Vulnerability,
)

# CVE record states that should not be ingested as live vulnerabilities.
SKIPPED_STATES = {"REJECTED", "RESERVED"}
CWE_PATTERN = re.compile(r"\bCWE-\d+\b")
SECTIONS_TO_NOTES = {
    "workarounds": "workaround",
    "solutions": "solution",
    "exploits": "exploit",
    "configurations": "configuration",
}
# CVSS version keys used when searching metrics lists.
CVSS_V3_VERSIONS = ("cvssV3_1", "cvssV3_0")
CVSS_V4_VERSIONS = ("cvssV4_0",)


class CVEProcessor:
    """Convert CVE records to STIX bundles and push them to OpenCTI."""

    def __init__(self, helper: OpenCTIConnectorHelper) -> None:
        self.helper = helper
        self.author = self._create_author()

    def process_cve_file(self, file_path: str, work_id: str) -> None:
        with open(file_path, encoding="utf-8") as cve_file:
            cve_data = json.load(cve_file)

        metadata = cve_data.get("cveMetadata") or {}
        cve_id = metadata.get("cveId")
        if not cve_id:
            self.helper.connector_logger.warning(
                "Skipping CVE record without an identifier.", {"file": file_path}
            )
            return

        state = metadata.get("state")
        if state in SKIPPED_STATES:
            self.helper.connector_logger.debug(
                "Skipping CVE record in non-public state.",
                {"cve_id": cve_id, "state": state},
            )
            return

        stix_objects = self._cve_record_to_stix(cve_data)
        if not stix_objects:
            return

        bundle = self.helper.stix2_create_bundle(stix_objects)
        self.helper.send_stix2_bundle(bundle, work_id=work_id, update=True)
        self.helper.connector_logger.info(
            "CVE record sent to OpenCTI.", {"cve_id": cve_id}
        )

    def _cve_record_to_stix(self, cve_data: dict[str, Any]) -> list[Any]:
        metadata = cve_data.get("cveMetadata") or {}
        containers = cve_data.get("containers") or {}
        cna = containers.get("cna") or {}
        adp_containers = containers.get("adp") or []

        cve_id = metadata["cveId"]
        published_date = self._normalize_date(metadata.get("datePublished"))
        modified_date = self._normalize_date(
            metadata.get("dateUpdated") or metadata.get("dateReserved")
        )
        description = self._extract_description(cna)
        if description is None:
            self.helper.connector_logger.debug(
                "CVE record has no English description, skipping.",
                {"cve_id": cve_id},
            )
            return []

        external_references = self._extract_external_references(cna)
        labels = self._extract_labels(cna)
        custom_properties = self._extract_cvss_properties(cna, adp_containers)

        vulnerability = stix2.Vulnerability(
            id=Vulnerability.generate_id(cve_id),
            name=cve_id,
            description=description,
            created=published_date,
            modified=modified_date,
            external_references=external_references or None,
            created_by_ref=self.author["id"],
            custom_properties=custom_properties,
            labels=labels or None,
            allow_custom=True,
        )
        stix_objects: list[Any] = [self.author, vulnerability]

        for product in cna.get("affected") or []:
            stix_objects.extend(self._build_affected_objects(product, vulnerability))

        for section, label in SECTIONS_TO_NOTES.items():
            entries = cna.get(section)
            if not entries:
                continue
            stix_objects.extend(
                self._create_related_notes(label, entries, vulnerability)
            )

        return stix_objects

    def _build_affected_objects(
        self, product: dict[str, Any], vulnerability: stix2.Vulnerability
    ) -> list[Any]:
        product_name = product.get("product") or product.get("packageName")
        if not product_name:
            return []

        vendor_name = product.get("vendor") or "Unknown"
        software_vendor = stix2.Identity(
            id=Identity.generate_id(vendor_name, "organization"),
            name=vendor_name,
            identity_class="organization",
            description="Software Vendor",
            created_by_ref=self.author["id"],
            custom_properties={"x_opencti_organization_type": "vendor"},
            allow_custom=True,
        )

        stix_objects: list[Any] = [software_vendor]

        cpes = product.get("cpes") or []
        if cpes:
            for cpe in cpes:
                version_value = self._extract_cpe_version(cpe)
                stix_objects.extend(
                    self._create_affected_software(
                        product_name,
                        version_value,
                        software_vendor,
                        vulnerability,
                        cpe=cpe,
                    )
                )
            return stix_objects

        for version in product.get("versions") or []:
            if version.get("status") != "affected":
                continue
            version_value = self._format_version(version)
            stix_objects.extend(
                self._create_affected_software(
                    f"{product_name} {version.get('version', '')}".strip(),
                    version_value,
                    software_vendor,
                    vulnerability,
                )
            )
        return stix_objects

    def _create_affected_software(
        self,
        name: str,
        version: str,
        vendor: stix2.Identity,
        vulnerability: stix2.Vulnerability,
        cpe: str = "",
    ) -> list[Any]:
        software = stix2.Software(
            name=name,
            version=version or "unspecified",
            vendor=vendor.name,
            cpe=cpe or None,
            custom_properties={"x_opencti_created_by_ref": self.author["id"]},
            allow_custom=True,
        )

        vulnerability_relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id("has", software.id, vulnerability.id),
            relationship_type="has",
            source_ref=software.id,
            target_ref=vulnerability.id,
            created_by_ref=self.author["id"],
            allow_custom=True,
        )

        software_vendor_relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id("related-to", software.id, vendor.id),
            relationship_type="related-to",
            description="This software is maintained by",
            source_ref=software.id,
            target_ref=vendor.id,
            created_by_ref=self.author["id"],
            allow_custom=True,
        )

        return [software, vulnerability_relationship, software_vendor_relationship]

    def _create_related_notes(
        self,
        section_label: str,
        entries: Iterable[dict[str, Any]],
        vulnerability: stix2.Vulnerability,
    ) -> list[Any]:
        stix_objects: list[Any] = []
        for entry in entries:
            content = entry.get("value")
            if not content:
                continue
            note = stix2.Note(
                id=Note.generate_id(created=None, content=content),
                abstract=f"{vulnerability.name} - {section_label}",
                content=content,
                object_refs=[vulnerability.id],
                labels=[section_label],
                created_by_ref=self.author["id"],
                allow_custom=True,
            )
            stix_objects.append(note)
        return stix_objects

    @staticmethod
    def _normalize_date(value: str | None) -> str | None:
        if not value:
            return None
        if value.endswith("Z"):
            return value
        # CVE feeds occasionally publish ``+00:00`` and bare datetimes. STIX 2.1
        # expects a ``Z`` suffix, so normalize accordingly.
        if value.endswith("+00:00"):
            return f"{value[:-6]}Z"
        return f"{value}Z"

    @staticmethod
    def _extract_description(cna: dict[str, Any]) -> str | None:
        descriptions = cna.get("descriptions") or []
        for description in descriptions:
            if description.get("lang", "").lower().startswith("en"):
                value = description.get("value")
                if value:
                    return value
        if descriptions:
            return descriptions[0].get("value")
        return None

    @staticmethod
    def _extract_external_references(
        cna: dict[str, Any],
    ) -> list[stix2.ExternalReference]:
        references: list[stix2.ExternalReference] = []
        for reference in cna.get("references") or []:
            url = reference.get("url")
            if not url:
                continue
            source_name = reference.get("name")
            if not source_name:
                tags = reference.get("tags") or []
                source_name = tags[0] if tags else url
            references.append(stix2.ExternalReference(source_name=source_name, url=url))
        return references

    @staticmethod
    def _extract_labels(cna: dict[str, Any]) -> list[str]:
        labels: list[str] = []
        seen: set[str] = set()
        for problem_type in cna.get("problemTypes") or []:
            for entry in problem_type.get("descriptions") or []:
                cwe_id = entry.get("cweId")
                description = entry.get("description") or ""
                if not cwe_id:
                    match = CWE_PATTERN.search(description)
                    if match:
                        cwe_id = match.group(0)
                if cwe_id and cwe_id not in seen:
                    seen.add(cwe_id)
                    labels.append(cwe_id)
                if description:
                    clean = CWE_PATTERN.sub("", description).strip(" :-")
                    if clean and clean not in seen:
                        seen.add(clean)
                        labels.append(clean)
        return labels

    @classmethod
    def _extract_cvss_properties(
        cls,
        cna: dict[str, Any],
        adp_containers: list[dict[str, Any]],
    ) -> dict[str, Any]:
        all_metrics = cna.get("metrics") or []
        if not cls._has_supported_cvss_metric(all_metrics):
            all_metrics = []
            for adp in adp_containers:
                candidate_metrics = adp.get("metrics") or []
                if cls._has_supported_cvss_metric(candidate_metrics):
                    all_metrics = candidate_metrics
                    break

        if not all_metrics:
            return {}

        props: dict[str, Any] = {}

        v3_metric = cls._find_cvss_metric(all_metrics, CVSS_V3_VERSIONS)
        if v3_metric:
            props.update(
                {
                    "x_opencti_cvss_base_score": v3_metric.get("baseScore", ""),
                    "x_opencti_cvss_base_severity": v3_metric.get("baseSeverity", ""),
                    "x_opencti_cvss_attack_vector": v3_metric.get("attackVector", ""),
                    "x_opencti_cvss_attack_complexity": v3_metric.get(
                        "attackComplexity", ""
                    ),
                    "x_opencti_cvss_privileges_required": v3_metric.get(
                        "privilegesRequired", ""
                    ),
                    "x_opencti_cvss_user_interaction": v3_metric.get(
                        "userInteraction", ""
                    ),
                    "x_opencti_cvss_scope": v3_metric.get("scope", ""),
                    "x_opencti_cvss_integrity_impact": v3_metric.get(
                        "integrityImpact", ""
                    ),
                    "x_opencti_cvss_availability_impact": v3_metric.get(
                        "availabilityImpact", ""
                    ),
                    "x_opencti_cvss_confidentiality_impact": v3_metric.get(
                        "confidentialityImpact", ""
                    ),
                    "x_opencti_cvss_vector_string": v3_metric.get("vectorString", ""),
                }
            )

        v4_metric = cls._find_cvss_metric(all_metrics, CVSS_V4_VERSIONS)
        if v4_metric:
            props.update(
                {
                    "x_opencti_cvss_v4_base_score": v4_metric.get("baseScore", ""),
                    "x_opencti_cvss_v4_base_severity": v4_metric.get(
                        "baseSeverity", ""
                    ),
                    "x_opencti_cvss_v4_attack_vector": v4_metric.get(
                        "attackVector", ""
                    ),
                    "x_opencti_cvss_v4_attack_complexity": v4_metric.get(
                        "attackComplexity", ""
                    ),
                    "x_opencti_cvss_v4_attack_requirements": v4_metric.get(
                        "attackRequirements", ""
                    ),
                    "x_opencti_cvss_v4_privileges_required": v4_metric.get(
                        "privilegesRequired", ""
                    ),
                    "x_opencti_cvss_v4_user_interaction": v4_metric.get(
                        "userInteraction", ""
                    ),
                    "x_opencti_cvss_v4_confidentiality_impact_v": v4_metric.get(
                        "vulnConfidentialityImpact", ""
                    ),
                    "x_opencti_cvss_v4_confidentiality_impact_s": v4_metric.get(
                        "subConfidentialityImpact", ""
                    ),
                    "x_opencti_cvss_v4_integrity_impact_v": v4_metric.get(
                        "vulnIntegrityImpact", ""
                    ),
                    "x_opencti_cvss_v4_integrity_impact_s": v4_metric.get(
                        "subIntegrityImpact", ""
                    ),
                    "x_opencti_cvss_v4_availability_impact_v": v4_metric.get(
                        "vulnAvailabilityImpact", ""
                    ),
                    "x_opencti_cvss_v4_availability_impact_s": v4_metric.get(
                        "subAvailabilityImpact", ""
                    ),
                    "x_opencti_cvss_v4_vector_string": v4_metric.get(
                        "vectorString", ""
                    ),
                }
            )

        return props

    @classmethod
    def _has_supported_cvss_metric(cls, metrics: list[dict[str, Any]]) -> bool:
        return bool(
            cls._find_cvss_metric(metrics, CVSS_V3_VERSIONS)
            or cls._find_cvss_metric(metrics, CVSS_V4_VERSIONS)
        )

    @staticmethod
    def _find_cvss_metric(
        metrics: list[dict[str, Any]], versions: tuple[str, ...]
    ) -> dict[str, Any] | None:
        for version in versions:
            for metric in metrics:
                if version in metric and isinstance(metric[version], dict):
                    return metric[version]
        return None

    @staticmethod
    def _extract_cpe_version(cpe: str) -> str:
        parts = cpe.split(":")
        if len(parts) >= 7:
            update = parts[6]
            if update not in ("-", "*", ""):
                return f"{parts[5]}-{update}"
            return parts[5]
        if len(parts) >= 6:
            return parts[5]
        if len(parts) >= 5:
            return parts[4]
        return ""

    @staticmethod
    def _format_version(version: dict[str, Any]) -> str:
        if "lessThan" in version:
            return f"<{version['lessThan']}"
        if "lessThanOrEqual" in version:
            return f"<={version['lessThanOrEqual']}"
        return version.get("version", "")

    @staticmethod
    def _create_author() -> stix2.Identity:
        return stix2.Identity(
            id=Identity.generate_id("The CVE Program", "organization"),
            name="The CVE Program",
            identity_class="organization",
        )
