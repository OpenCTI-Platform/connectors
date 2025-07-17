"""Converts a GTI file to a STIX file object and indicator."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from connector.src.custom.models.gti_reports.gti_file_model import (
    GTIFileData,
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
    ) -> None:
        """Initialize the GTIFileToSTIXFile object.

        Args:
        file (GTIFileData): The GTI file data to convert.
        organization (Identity): The organization identity object.
        tlp_marking (MarkingDefinition): The TLP marking definition.

        """
        self.file = file
        self.organization = organization
        self.tlp_marking = tlp_marking

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
        score = self._get_score()

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

    def to_stix(self) -> List[Any]:
        """Convert the GTI file to STIX file and indicator objects.

        Returns:
        List[Any]: List containing the STIX file observable, indicator model objects, and their relationship.

        """
        file_observable = self._create_stix_file()
        indicator = self._create_stix_indicator()
        relationship = self._create_relationship_indicator_file(
            indicator, file_observable
        )

        return [file_observable, indicator, relationship]

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
        """Get score from file attributes.

        Priority order:
        1. contributing_factors.mandiant_confidence_score
        2. threat_score.value

        Returns:
            Optional[int]: The score if available, None otherwise

        """
        if (
            self.file.attributes
            and self.file.attributes.gti_assessment
            and self.file.attributes.gti_assessment.contributing_factors
            and hasattr(
                self.file.attributes.gti_assessment.contributing_factors,
                "mandiant_confidence_score",
            )
            and self.file.attributes.gti_assessment.contributing_factors.mandiant_confidence_score
            is not None
        ):
            return (
                self.file.attributes.gti_assessment.contributing_factors.mandiant_confidence_score
            )

        if (
            self.file.attributes
            and self.file.attributes.gti_assessment
            and self.file.attributes.gti_assessment.threat_score
        ):
            return self.file.attributes.gti_assessment.threat_score.value

        return None

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
