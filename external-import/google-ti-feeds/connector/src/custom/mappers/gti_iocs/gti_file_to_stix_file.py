"""Converts a GTI file to a STIX file object and indicator."""

from datetime import datetime, timezone
from typing import Any

from connector.src.custom.models.gti.gti_file_model import (
    GTIFileData,
)
from connector.src.stix.octi.models.file_model import OctiFileModel
from connector.src.stix.octi.models.indicator_model import OctiIndicatorModel
from connector.src.stix.octi.models.relationship_model import OctiRelationshipModel
from connector.src.stix.octi.observable_type_ov_enum import ObservableTypeOV
from connector.src.stix.octi.pattern_type_ov_enum import PatternTypeOV
from connector.src.stix.v21.models.ovs.indicator_type_ov_enums import IndicatorTypeOV
from connector.src.stix.v21.models.sdos.indicator_model import IndicatorModel
from connector.src.stix.v21.models.sros.relationship_model import RelationshipModel
from connector.src.utils.converters.generic_converter_config import BaseMapper
from connectors_sdk.models.octi import (  # type: ignore[import-untyped]
    OrganizationAuthor,
    TLPMarking,
)
from stix2 import File  # type: ignore[import-untyped]


class GTIFileToSTIXFile(BaseMapper):
    """Converts a GTI file to a STIX file object and indicator."""

    @staticmethod
    def create_relationship(
        src_entity: Any, relation_type: str, target_entity: Any
    ) -> Any:
        """Create a relationship between entities.

        For indicators: creates 'indicates' relationship from indicator to target
        For observables: creates the specified relationship type from source to target

        Args:
            src_entity: The source entity (intrusion set or indicator/observable)
            relation_type: The relationship type (e.g., "related-to")
            target_entity: The target entity (file or intrusion set)

        Returns:
            OctiRelationshipModel: The relationship object

        """
        if isinstance(target_entity, IndicatorModel):
            return OctiRelationshipModel.create(
                relationship_type="indicates",
                source_ref=target_entity.id,
                target_ref=src_entity.id,
                organization_id=src_entity.created_by_ref,
                marking_ids=src_entity.object_marking_refs,
                created=datetime.now(tz=timezone.utc),
                modified=datetime.now(tz=timezone.utc),
                description=f"Indicator indicates {src_entity.__class__.__name__}",
            )
        else:
            return OctiRelationshipModel.create(
                relationship_type=relation_type,
                source_ref=src_entity.id,
                target_ref=target_entity.id,
                organization_id=src_entity.created_by_ref,
                marking_ids=src_entity.object_marking_refs,
                created=datetime.now(tz=timezone.utc),
                modified=datetime.now(tz=timezone.utc),
                description=f"{src_entity.__class__.__name__} {relation_type} {target_entity.__class__.__name__}",
            )

    def __init__(
        self,
        file: GTIFileData,
        organization: OrganizationAuthor,
        tlp_marking: TLPMarking,
    ) -> None:
        """Initialize the GTIFileToSTIXFile object.

        Args:
        file (GTIFileData): The GTI file data to convert.
        organization (OrganizationAuthor): The organization identity object.
        tlp_marking (TLPMarking): The TLP marking definition.

        """
        self.file = file
        self.organization = organization
        self.tlp_marking = tlp_marking

    def _create_stix_file(self) -> File:
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

        return file_model.to_stix2_object()

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
        self, indicator: IndicatorModel, file_observable: File
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

    def to_stix(self) -> list[Any]:
        """Convert the GTI file to STIX file and indicator objects.

        Returns:
        list[Any]: list containing the STIX file observable, indicator model objects, and their relationship.

        """
        file_observable = self._create_stix_file()
        indicator = self._create_stix_indicator()
        relationship = self._create_relationship_indicator_file(
            indicator, file_observable
        )

        return [file_observable, indicator, relationship]

    def _get_timestamps(self) -> dict[str, datetime]:
        """Extract creation and modification timestamps from file attributes.

        Returns:
            dict[str, datetime]: dictionary with 'created' and 'modified' timestamps

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

    def _get_score(self) -> int | None:
        """Get score from file attributes.

        Priority order:
        1. contributing_factors.mandiant_confidence_score
        2. threat_score.value

        Returns:
            int | None: The score if available, None otherwise

        """
        if (
            self.file.attributes
            and self.file.attributes.gti_assessment
            and self.file.attributes.gti_assessment.threat_score
        ):
            return self.file.attributes.gti_assessment.threat_score.value

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

        return None

    def _build_hashes(self) -> dict[str, str] | None:
        """Build hashes dictionary from file attributes.

        Returns:
            dict[str, str] | None: dictionary of hashes if available, None otherwise

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

    def _determine_indicator_types(self) -> list[IndicatorTypeOV]:
        """Determine indicator types based on file attributes.

        Returns:
            list[IndicatorTypeOV]: list of indicator types

        """
        indicator_types = []

        gti_types = self._get_types_from_gti_assessment()
        if gti_types:
            indicator_types.extend(gti_types)

        if not indicator_types:
            indicator_types.append(IndicatorTypeOV.UNKNOWN)

        return indicator_types

    def _get_types_from_gti_assessment(self) -> list[IndicatorTypeOV]:
        """Extract indicator types from GTI assessment verdict.

        Returns:
            list[IndicatorTypeOV]: list of indicator types from GTI assessment

        """
        if not (self.file.attributes and self.file.attributes.gti_assessment):
            return []

        gti_assessment = self.file.attributes.gti_assessment
        if not (gti_assessment.verdict and gti_assessment.verdict.value):
            return []

        verdict = gti_assessment.verdict.value.upper()

        return [IndicatorTypeOV(verdict)]
