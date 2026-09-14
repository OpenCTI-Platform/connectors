"""Converts a GTI file to a STIX file object and indicator."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import pycti  # type: ignore
from connector.src.custom.models.gti_reports.gti_file_model import (
    GTIFileData,
)
from ...indicator_utils import (
    build_enhanced_description,
    build_vt_gui_url,
    compute_indicator_score,
    derive_verdict_from_stats,
    gti_score_and_verdict,
    is_indicator_allowed,
)
from connector.src.stix.octi.models.file_model import OctiFileModel
from connector.src.stix.octi.models.indicator_model import OctiIndicatorModel
from connector.src.stix.octi.observable_type_ov_enum import ObservableTypeOV
from connector.src.stix.octi.pattern_type_ov_enum import PatternTypeOV
from connector.src.stix.v21.models.ovs.indicator_type_ov_enums import IndicatorTypeOV
from connector.src.stix.v21.models.scos.file_model import FileModel
from connector.src.stix.v21.models.sdos.indicator_model import IndicatorModel
from connector.src.stix.v21.models.sros.relationship_model import RelationshipModel
from connector.src.utils.converters.generic_converter_config import BaseMapper
from stix2.v21 import Identity, MarkingDefinition  # type: ignore


class GTIFileToSTIXFile(BaseMapper):
    """Converts a GTI file to a STIX file object and indicator."""

    def __init__(
        self,
        file: GTIFileData,
        organization: Identity,
        tlp_marking: MarkingDefinition,
        indicator_scoring: str = "gti_derived",
        threat_actor_ids: Optional[List[str]] = None,
        malware_ids: Optional[List[str]] = None,
    ) -> None:
        """Initialize the GTIFileToSTIXFile object.

        Args:
        file (GTIFileData): The GTI file data to convert.
        organization (Identity): The organization identity object.
        tlp_marking (MarkingDefinition): The TLP marking definition.
        indicator_scoring (str): The scoring mode to use ('gti_derived' or 'average_detection').
        threat_actor_ids (Optional[List[str]]): List of threat actor names associated with this file.
        malware_ids (Optional[List[str]]): List of malware family names associated with this file.

        """
        self.file = file
        self.organization = organization
        self.tlp_marking = tlp_marking
        self.indicator_scoring = indicator_scoring
        self.threat_actor_ids = threat_actor_ids or []
        
        # Start with malware names from report context
        all_malware_names = list(malware_ids or [])
        
        # Extract additional malware names from popular_threat_name in file attributes
        if self.file.attributes and self.file.attributes.popular_threat_name:
            for threat_name in self.file.attributes.popular_threat_name:
                if threat_name.value:
                    # Capitalize the malware name for consistency
                    name = threat_name.value.strip()
                    if name and name.capitalize() not in [m.capitalize() for m in all_malware_names]:
                        all_malware_names.append(name.capitalize())
        
        self.malware_ids = all_malware_names

    def _create_stix_file(self) -> FileModel:
        """Create the STIX file observable object.

        Returns:
        FileModel: The STIX file observable model object.

        """
        score = self._get_score()

        hashes = self._build_hashes()

        additional_names = None
        if self.file.attributes and self.file.attributes.names:
            additional_names = self.file.attributes.names

        file_name = None
        if self.file.attributes and self.file.attributes.meaningful_name:
            file_name = self.file.attributes.meaningful_name

        file_size = None
        if self.file.attributes and self.file.attributes.size:
            file_size = self.file.attributes.size

        ctime = None
        if self.file.attributes:
            if self.file.attributes.creation_date:
                ctime = datetime.fromtimestamp(
                    self.file.attributes.creation_date, tz=timezone.utc
                )

        file_model = OctiFileModel.create(
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
            hashes=hashes,
            name=file_name,
            additional_names=additional_names,
            size=file_size,
            score=score,
            description=self._get_description(),
            external_references=self._get_external_references(),
            labels=self._get_labels(),
            ctime=ctime,
        )

        return file_model

    def _create_stix_indicator(self) -> IndicatorModel:
        """Create the STIX indicator object.

        Returns:
        IndicatorModel: The STIX indicator model object.

        """
        timestamps = self._get_timestamps()
        created = timestamps["created"]
        modified = timestamps["modified"]
        score = compute_indicator_score(
            self.indicator_scoring,
            self._get_verdict(),
            self._get_severity(),
            self._get_analysis_stats(),
        )

        pattern = self._build_stix_pattern()

        indicator_types = self._determine_indicator_types()

        indicator_model = OctiIndicatorModel.create(
            name=self.file.id,
            pattern=pattern,
            pattern_type=PatternTypeOV.STIX,
            observable_type=ObservableTypeOV.FILE,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
            indicator_types=indicator_types,
            score=score,
            created=created,
            modified=modified,
        )

        return indicator_model

    def _create_relationship_indicator_file(
        self, indicator: IndicatorModel, file_observable: FileModel
    ) -> RelationshipModel:
        """Create a based-on relationship from indicator to file observable.

        Args:
            indicator (IndicatorModel): The source indicator object.
            file_observable (FileModel): The target file observable object.

        Returns:
            RelationshipModel: The relationship model object.

        """
        timestamps = self._get_timestamps()

        relationship = RelationshipModel(
            relationship_type="based-on",
            source_ref=indicator.id,
            target_ref=file_observable.id,
            created=timestamps["created"],
            modified=timestamps["modified"],
            created_by_ref=self.organization.id,
            object_marking_refs=[self.tlp_marking.id],
        )

        return relationship

    def _create_threat_actor_relationships(
        self, file_observable: FileModel
    ) -> List[RelationshipModel]:
        """Create relationships from threat actors (intrusion-sets) to file observable.

        Args:
            file_observable (FileModel): The target file observable object.

        Returns:
            List[RelationshipModel]: List of relationship model objects.

        """
        relationships = []
        timestamps = self._get_timestamps()

        for threat_actor_name in self.threat_actor_ids:
            # Generate deterministic STIX ID using pycti (same as when intrusion-set was created)
            intrusion_set_id = pycti.IntrusionSet.generate_id(name=threat_actor_name)

            relationship = RelationshipModel(
                relationship_type="related-to",
                source_ref=intrusion_set_id,
                target_ref=file_observable.id,
                created=timestamps["created"],
                modified=timestamps["modified"],
                created_by_ref=self.organization.id,
                object_marking_refs=[self.tlp_marking.id],
            )
            relationships.append(relationship)

        return relationships

    def _create_malware_relationships(
        self, file_observable: FileModel
    ) -> List[RelationshipModel]:
        """Create relationships from malware families to file observable.

        Args:
            file_observable (FileModel): The target file observable object.

        Returns:
            List[RelationshipModel]: List of relationship model objects.

        """
        relationships = []
        timestamps = self._get_timestamps()

        for malware_name in self.malware_ids:
            # Generate deterministic STIX ID using pycti (same as when malware was created)
            stix_malware_id = pycti.Malware.generate_id(name=malware_name)

            relationship = RelationshipModel(
                relationship_type="related-to",
                source_ref=stix_malware_id,
                target_ref=file_observable.id,
                created=timestamps["created"],
                modified=timestamps["modified"],
                created_by_ref=self.organization.id,
                object_marking_refs=[self.tlp_marking.id],
            )
            relationships.append(relationship)

        return relationships

    def to_stix(self) -> List[Any]:
        """Convert the GTI file to STIX file and indicator objects.

        Returns:
        List[Any]: List containing the STIX file observable, indicator model objects, and their relationship.

        """
        score = self._get_score()
        verdict = self._get_verdict()

        # Looks counter-intuitive but if the observable is not allowed to be an indicator based on score/verdict
        # we still want to create the URL observable to capture the data - just not the indicator or relationship
        if not is_indicator_allowed(score, verdict):
            file_observable = self._create_stix_file()
            result = [file_observable]
            result.extend(self._create_threat_actor_relationships(file_observable))
            result.extend(self._create_malware_relationships(file_observable))
            return result

        file_observable = self._create_stix_file()
        indicator = self._create_stix_indicator()
        relationship = self._create_relationship_indicator_file(
            indicator, file_observable
        )

        result = [file_observable, indicator, relationship]
        result.extend(self._create_threat_actor_relationships(file_observable))
        result.extend(self._create_malware_relationships(file_observable))
        return result

    def _get_timestamps(self) -> Dict[str, datetime]:
        """Extract creation and modification timestamps from file attributes.

        Returns:
            Dict[str, datetime]: Dictionary with 'created' and 'modified' timestamps

        """
        created = datetime.now(timezone.utc)
        modified = datetime.now(timezone.utc)

        if self.file.attributes:
            if self.file.attributes.first_submission_date:
                created = datetime.fromtimestamp(
                    self.file.attributes.first_submission_date, tz=timezone.utc
                )
            if self.file.attributes.last_submission_date:
                modified = datetime.fromtimestamp(
                    self.file.attributes.last_submission_date, tz=timezone.utc
                )

        return {"created": created, "modified": modified}

    def _get_score(self) -> Optional[int]:
        """Get score from file attributes using configured scoring mode.

        Returns:
            Optional[int]: The score if available, None otherwise

        """
        return compute_indicator_score(
            self.indicator_scoring,
            self._get_verdict(),
            self._get_severity(),
            self._get_analysis_stats(),
        )

    def _get_description(self) -> str:
        """Generate enhanced description with GTI assessment details.

        Returns:
            str: Rich description with narrative, reasons, and assessment

        """
        attrs = {}
        if self.file.attributes:
            attrs = self.file.attributes.model_dump()

        score, verdict, severity = gti_score_and_verdict(
            attrs.get("gti_assessment")
        )

        return build_enhanced_description(attrs, score, verdict, severity)

    def _get_external_references(self) -> List[Dict[str, Any]]:
        """Build external references including VirusTotal link.

        Returns:
            List of external reference dicts

        """
        # Use SHA256 hash for file URL
        file_hash = self.file.id
        vt_url = build_vt_gui_url("file", file_hash)
        return [
            {
                "source_name": "VirusTotal",
                "url": vt_url,
                "description": f"VirusTotal link for file: {file_hash}",
            }
        ]

    def _get_labels(self) -> Optional[List[str]]:
        """Get labels/tags from file attributes.

        Returns:
            Optional[List[str]]: List of labels if available

        """
        if self.file.attributes and self.file.attributes.tags:
            return self.file.attributes.tags
        return None

    def _get_analysis_stats(self) -> Optional[Dict[str, int]]:
        """Get analysis stats from file attributes.

        Returns:
            Optional[Dict[str, int]]: Dictionary with malicious, suspicious, harmless, undetected counts

        """
        if not (self.file.attributes and self.file.attributes.last_analysis_stats):
            return None

        stats = self.file.attributes.last_analysis_stats
        return {
            "malicious": stats.malicious,
            "suspicious": stats.suspicious,
            "harmless": stats.harmless,
            "undetected": stats.undetected,
        }

    def _build_hashes(self) -> Optional[Dict[str, str]]:
        """Build hashes dictionary from file attributes.

        Returns:
            Optional[Dict[str, str]]: Dictionary of hashes if available, None otherwise

        """
        if not self.file.attributes:
            return None

        hashes = {}
        if self.file.attributes.sha256:
            hashes["SHA-256"] = self.file.attributes.sha256
        if self.file.attributes.sha1:
            hashes["SHA-1"] = self.file.attributes.sha1
        if self.file.attributes.md5:
            hashes["MD5"] = self.file.attributes.md5

        return hashes if hashes else None

    def _build_stix_pattern(self) -> str:
        """Build STIX pattern for the file indicator.

        Returns:
            str: STIX pattern string

        """
        patterns = []

        if self.file.attributes:
            if self.file.attributes.sha256:
                patterns.append(
                    f"file:hashes.'SHA-256' = '{self.file.attributes.sha256}'"
                )
            if self.file.attributes.md5:
                patterns.append(f"file:hashes.MD5 = '{self.file.attributes.md5}'")
            if self.file.attributes.sha1:
                patterns.append(f"file:hashes.'SHA-1' = '{self.file.attributes.sha1}'")

        if patterns:
            return f"[{' OR '.join(patterns)}]"
        else:
            return f"[file:hashes.'SHA-256' = '{self.file.id}']"

    def _determine_indicator_types(self) -> List[IndicatorTypeOV]:
        """Determine indicator types based on file attributes.

        Returns:
            List[IndicatorTypeOV]: List of indicator types

        """
        indicator_types = []

        gti_types = self._get_types_from_gti_assessment()
        if gti_types:
            indicator_types.extend(gti_types)

        if not indicator_types:
            indicator_types.append(IndicatorTypeOV.UNKNOWN)

        return indicator_types

    def _get_types_from_gti_assessment(self) -> List[IndicatorTypeOV]:
        """Extract indicator types from GTI assessment verdict.

        Returns:
            List[IndicatorTypeOV]: List of indicator types from GTI assessment

        """
        if not (self.file.attributes and self.file.attributes.gti_assessment):
            return []

        gti_assessment = self.file.attributes.gti_assessment
        if not (gti_assessment.verdict and gti_assessment.verdict.value):
            return []

        verdict = gti_assessment.verdict.value.upper()

        return [IndicatorTypeOV(verdict)]

    def _get_verdict(self) -> Optional[str]:
        """Get verdict from file attributes.

        Priority order:
        1. gti_assessment.verdict.value
        2. Derived from last_analysis_stats

        Returns:
            Optional[str]: The verdict if available, None otherwise

        """
        if (
            self.file.attributes
            and self.file.attributes.gti_assessment
            and self.file.attributes.gti_assessment.verdict
        ):
            return self.file.attributes.gti_assessment.verdict.value

        # Fallback: derive from last_analysis_stats
        stats = self._get_analysis_stats()
        if stats:
            return derive_verdict_from_stats(
                stats.get("malicious"),
                stats.get("suspicious"),
            )

        return None

    def _get_severity(self) -> Optional[str]:
        """Get severity from file attributes.

        Returns:
            Optional[str]: The severity if available, None otherwise

        """
        if (
            self.file.attributes
            and self.file.attributes.gti_assessment
            and self.file.attributes.gti_assessment.severity
        ):
            return self.file.attributes.gti_assessment.severity.value
        return None
