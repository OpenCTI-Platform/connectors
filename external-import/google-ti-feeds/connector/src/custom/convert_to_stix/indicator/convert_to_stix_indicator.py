"""Convert IOC delta entries to STIX objects."""

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from connector.src.custom.convert_to_stix.convert_to_stix_base import BaseConvertToSTIX
from connector.src.custom.mappers.gti_iocs.gti_domain_to_stix_domain import (
    GTIDomainToSTIXDomain,
)
from connector.src.custom.mappers.gti_iocs.gti_file_to_stix_file import (
    GTIFileToSTIXFile,
)
from connector.src.custom.mappers.gti_iocs.gti_ip_to_stix_ip import GTIIPToSTIXIP
from connector.src.custom.mappers.gti_iocs.gti_url_to_stix_url import GTIUrlToSTIXUrl
from connector.src.custom.models.gti import gti_domain_model as domain_models
from connector.src.custom.models.gti import gti_file_model as file_models
from connector.src.custom.models.gti import gti_ip_addresses_model as ip_models
from connector.src.custom.models.gti import gti_url_model as url_models
from connector.src.custom.models.gti.gti_domain_model import GTIDomainData
from connector.src.custom.models.gti.gti_file_model import GTIFileData
from connector.src.custom.models.gti.gti_ioc_delta_model import (
    IOCDeltaEntry,
    IOCDeltaGTIAssessment,
)
from connector.src.custom.models.gti.gti_ip_addresses_model import GTIIPData
from connector.src.custom.models.gti.gti_url_model import GTIURLData
from connector.src.stix.octi.models.relationship_model import OctiRelationshipModel

if TYPE_CHECKING:
    import logging

    from connector.src.custom.configs import GTIConfig

LOG_PREFIX = "[ConvertToSTIXIndicator]"

# Fixed namespace for deterministic UUIDv5 conversion of GTI entity IDs
_GTI_STIX_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

REL_MAPPINGS = {
    "malware_families": "indicates",
    "campaigns": "indicates",
    "threat_actors": "indicates",
    "software_toolkits": "indicates",
    "vulnerabilities": "related-to",
    "reports": "related-to",
}


def _normalize_gti_stix_id(gti_id: str) -> str | None:
    """Convert a GTI entity ID to a valid STIX identifier.

    GTI IDs use the correct STIX type prefix but a non-UUID suffix
    (e.g. ``report--22-00000647``). A UUIDv5 is derived deterministically
    from the full GTI ID so the mapping is stable and reversible.

    IDs that already carry a valid UUIDv4 or UUIDv5 suffix are returned
    unchanged. Returns ``None`` when the input has no ``--`` separator.
    """
    if "--" not in gti_id:
        return None

    obj_type, suffix = gti_id.split("--", 1)

    try:
        parsed = uuid.UUID(suffix)
        if parsed.version in (4, 5):
            return gti_id  # already a valid STIX identifier
    except ValueError:
        pass

    return f"{obj_type}--{uuid.uuid5(_GTI_STIX_NAMESPACE, gti_id)}"


class ConvertToSTIXIndicator(BaseConvertToSTIX):
    """Convert IOC delta entries to STIX objects."""

    def __init__(self, config: "GTIConfig", logger: "logging.Logger", tlp_level: str):
        super().__init__(config, logger, tlp_level)

        self._converter = {
            "domain": self._convert_domain,
            "file": self._convert_file,
            "ip_address": self._convert_ip,
            "url": self._convert_url,
        }

    def convert(self, ioc_data: dict[str, Any]) -> list[Any]:
        """Convert a single IOC delta entry to STIX objects."""
        try:
            entry = IOCDeltaEntry.model_validate(ioc_data)
        except Exception as e:
            self.logger.warning(
                "Failed to parse IOC delta entry",
                {"prefix": LOG_PREFIX, "error": str(e), "data": str(ioc_data)[:200]},
            )
            return []

        try:
            self.logger.info(
                "Converting IOC delta entry to STIX",
                {"prefix": LOG_PREFIX, "type": entry.type, "id": entry.id},
            )
            if converter := self._converter.get(entry.type):
                stix_objects = converter(entry)
            else:
                self.logger.debug(
                    "Unknown IOC type, skipping",
                    {"prefix": LOG_PREFIX, "type": entry.type, "id": entry.id},
                )
                return []
        except Exception as e:
            self.logger.warning(
                "Failed to convert IOC entry to STIX",
                {
                    "prefix": LOG_PREFIX,
                    "type": entry.type,
                    "id": entry.id,
                    "error": str(e),
                },
            )
            return []

        rel_objects = self._build_relationships(entry, stix_objects)
        stix_objects.extend(rel_objects)

        return stix_objects

    @staticmethod
    def _map_assessment(delta: IOCDeltaGTIAssessment, models: Any) -> Any:
        """Map a delta GTI assessment to a target model's GTIAssessment.

        Args:
            delta: The IOC delta assessment to map.
            models: The target model module (file_models, ip_models, etc.)
                    which must expose GTIAssessment, Verdict, Severity,
                    and ThreatScore classes.
        """
        return models.GTIAssessment(
            verdict=(
                models.Verdict(value=delta.verdict.value) if delta.verdict else None
            ),
            severity=(
                models.Severity(value=delta.severity.value) if delta.severity else None
            ),
            threat_score=(
                models.ThreatScore(value=delta.threat_score.value)
                if delta.threat_score
                else None
            ),
        )

    def _convert_file(self, entry: IOCDeltaEntry) -> list[Any]:
        attrs = entry.attributes
        file_attrs = None
        if attrs:
            gti_assessment = (
                self._map_assessment(attrs.gti_assessment, file_models)
                if attrs.gti_assessment
                else None
            )
            file_attrs = file_models.FileModel(
                sha256=attrs.sha256,
                md5=attrs.md5,
                sha1=attrs.sha1,
                meaningful_name=attrs.meaningful_name,
                names=attrs.names,
                size=attrs.size,
                last_modification_date=attrs.last_modification_date,
                gti_assessment=gti_assessment,
            )
        file_data = GTIFileData(id=entry.id, type="file", attributes=file_attrs)
        mapper = GTIFileToSTIXFile(
            file=file_data,
            organization=self.organization,
            tlp_marking=self.tlp_marking,
        )
        return mapper.to_stix()

    def _convert_ip(self, entry: IOCDeltaEntry) -> list[Any]:
        attrs = entry.attributes
        ip_attrs = None
        if attrs:
            gti_assessment = (
                self._map_assessment(attrs.gti_assessment, ip_models)
                if attrs.gti_assessment
                else None
            )
            ip_attrs = ip_models.IPModel(
                last_modification_date=attrs.last_modification_date,
                gti_assessment=gti_assessment,
            )
        ip_data = GTIIPData(id=entry.id, type="ip_address", attributes=ip_attrs)
        mapper = GTIIPToSTIXIP(
            ip=ip_data,
            organization=self.organization,
            tlp_marking=self.tlp_marking,
        )
        return mapper.to_stix()

    def _convert_url(self, entry: IOCDeltaEntry) -> list[Any]:
        attrs = entry.attributes
        url_attrs = None
        if attrs:
            gti_assessment = (
                self._map_assessment(attrs.gti_assessment, url_models)
                if attrs.gti_assessment
                else None
            )
            url_attrs = url_models.URLModel(
                url=attrs.url,
                last_modification_date=attrs.last_modification_date,
                gti_assessment=gti_assessment,
            )
        url_data = GTIURLData(id=entry.id, type="url", attributes=url_attrs)
        mapper = GTIUrlToSTIXUrl(
            url=url_data,
            organization=self.organization,
            tlp_marking=self.tlp_marking,
        )
        return mapper.to_stix()

    def _convert_domain(self, entry: IOCDeltaEntry) -> list[Any]:
        attrs = entry.attributes
        domain_attrs = None
        if attrs:
            gti_assessment = (
                self._map_assessment(attrs.gti_assessment, domain_models)
                if attrs.gti_assessment
                else None
            )
            domain_attrs = domain_models.DomainModel(
                last_modification_date=attrs.last_modification_date,
                gti_assessment=gti_assessment,
            )
        domain_data = GTIDomainData(id=entry.id, type="domain", attributes=domain_attrs)
        mapper = GTIDomainToSTIXDomain(
            domain=domain_data,
            organization=self.organization,
            tlp_marking=self.tlp_marking,
        )
        return mapper.to_stix()

    def _build_relationships(
        self, entry: IOCDeltaEntry, stix_objects: list[Any]
    ) -> list[Any]:
        if not entry.relationships or not stix_objects:
            return []

        indicator_obj = next(
            (obj for obj in stix_objects if getattr(obj, "type", None) == "indicator"),
            None,
        )
        if not indicator_obj:
            return []

        rels = []
        now = datetime.now(timezone.utc)

        for rel_field, rel_type in REL_MAPPINGS.items():
            rel_data = getattr(entry.relationships, rel_field, None)
            if not rel_data:
                continue
            for item in rel_data.data:
                if not item.id:
                    continue
                target_ref = _normalize_gti_stix_id(item.id)
                if not target_ref:
                    self.logger.debug(
                        "Skipping relationship: cannot normalise GTI ID to STIX",
                        {
                            "prefix": LOG_PREFIX,
                            "gti_id": item.id,
                        },
                    )
                    continue
                try:
                    rel = OctiRelationshipModel.create(
                        relationship_type=rel_type,
                        source_ref=indicator_obj.id,
                        target_ref=target_ref,
                        organization_id=self.organization.id,
                        marking_ids=[self.tlp_marking.id],
                        created=now,
                        modified=now,
                    )
                    rels.append(rel)
                except Exception as e:
                    self.logger.debug(
                        "Failed to create relationship",
                        {
                            "prefix": LOG_PREFIX,
                            "rel_type": rel_type,
                            "target_id": target_ref,
                            "error": str(e),
                        },
                    )

        return rels
