"""Converts a GTI domain to a STIX domain object and indicator."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from connector.src.custom.models.gti_reports.gti_domain_model import (
    GTIDomainData,
)
from connector.src.stix.octi.models.domain_model import OctiDomainModel
from connector.src.stix.octi.models.indicator_model import OctiIndicatorModel
from connector.src.stix.octi.observable_type_ov_enum import ObservableTypeOV
from connector.src.stix.octi.pattern_type_ov_enum import PatternTypeOV
from connector.src.stix.v21.models.ovs.indicator_type_ov_enums import IndicatorTypeOV
from connector.src.stix.v21.models.scos.domain_name_model import DomainNameModel
from connector.src.stix.v21.models.sdos.indicator_model import IndicatorModel
from connector.src.stix.v21.models.sros.relationship_model import RelationshipModel
from connector.src.utils.converters.generic_converter_config import BaseMapper
from stix2.v21 import Identity, MarkingDefinition  # type: ignore


class GTIDomainToSTIXDomain(BaseMapper):
    """Converts a GTI domain to a STIX domain object and indicator."""

    def __init__(
        self,
        domain: GTIDomainData,
        organization: Identity,
        tlp_marking: MarkingDefinition,
    ) -> None:
        """Initialize the GTIDomainToSTIXDomain object.

        Args:
        domain (GTIDomainData): The GTI domain data to convert.
        organization (Identity): The organization identity object.
        tlp_marking (MarkingDefinition): The TLP marking definition.

        """
        self.domain = domain
        self.organization = organization
        self.tlp_marking = tlp_marking

    def _create_stix_domain(self) -> DomainNameModel:
        """Create the STIX domain observable object.

        Returns:
        DomainNameModel: The STIX domain observable model object.

        """
        score = self._get_score()

        domain_model = OctiDomainModel.create(
            value=self.domain.id,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
            score=score,
        )

        return domain_model

    def _create_stix_indicator(self) -> IndicatorModel:
        """Create the STIX indicator object.

        Returns:
        IndicatorModel: The STIX indicator model object.

        """
        timestamps = self._get_timestamps()
        created = timestamps["created"]
        score = self._get_score()

        indicator_types = self._determine_indicator_types()

        indicator_model = OctiIndicatorModel.create(
            name=self.domain.id,
            pattern=f"[domain-name:value='{self.domain.id}']",
            pattern_type=PatternTypeOV.STIX,
            observable_type=ObservableTypeOV.DOMAIN_NAME,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
            indicator_types=indicator_types,
            score=score,
            created=created,
            modified=created,
        )

        return indicator_model

    def _create_relationship_indicator_domain(
        self, indicator: IndicatorModel, domain_observable: DomainNameModel
    ) -> RelationshipModel:
        """Create a based-on relationship from indicator to domain observable.

        Args:
            indicator (IndicatorModel): The source indicator object.
            domain_observable (DomainNameModel): The target domain observable object.

        Returns:
            RelationshipModel: The relationship model object.

        """
        timestamps = self._get_timestamps()

        relationship = RelationshipModel(
            relationship_type="based-on",
            source_ref=indicator.id,
            target_ref=domain_observable.id,
            created=timestamps["created"],
            modified=timestamps["modified"],
            created_by_ref=self.organization.id,
            object_marking_refs=[self.tlp_marking.id],
        )

        return relationship

    def to_stix(self) -> List[Any]:
        """Convert the GTI domain to STIX domain and indicator objects.

        Returns:
        List[Any]: List containing the STIX domain observable, indicator model objects, and their relationship.

        """
        domain_observable = self._create_stix_domain()
        indicator = self._create_stix_indicator()
        relationship = self._create_relationship_indicator_domain(
            indicator, domain_observable
        )

        return [domain_observable, indicator, relationship]

    def _get_timestamps(self) -> Dict[str, datetime]:
        """Extract creation and modification timestamps from domain attributes.

        Returns:
            Dict[str, datetime]: Dictionary with 'created' and 'modified' timestamps

        """
        created = datetime.now(timezone.utc)
        modified = datetime.now(timezone.utc)

        if self.domain.attributes:
            if self.domain.attributes.creation_date:
                created = datetime.fromtimestamp(
                    self.domain.attributes.creation_date, tz=timezone.utc
                )
            if self.domain.attributes.last_modification_date:
                modified = datetime.fromtimestamp(
                    self.domain.attributes.last_modification_date, tz=timezone.utc
                )

        return {"created": created, "modified": modified}

    def _get_score(self) -> Optional[int]:
        """Get score from domain attributes.

        Priority order:
        1. contributing_factors.mandiant_confidence_score
        2. threat_score.value

        Returns:
            Optional[int]: The score if available, None otherwise

        """
        if (
            self.domain.attributes
            and self.domain.attributes.gti_assessment
            and self.domain.attributes.gti_assessment.contributing_factors
            and hasattr(
                self.domain.attributes.gti_assessment.contributing_factors,
                "mandiant_confidence_score",
            )
            and self.domain.attributes.gti_assessment.contributing_factors.mandiant_confidence_score
            is not None
        ):
            return (
                self.domain.attributes.gti_assessment.contributing_factors.mandiant_confidence_score
            )

        if (
            self.domain.attributes
            and self.domain.attributes.gti_assessment
            and self.domain.attributes.gti_assessment.threat_score
        ):
            return self.domain.attributes.gti_assessment.threat_score.value

        return None

    def _determine_indicator_types(self) -> List[IndicatorTypeOV]:
        """Determine indicator types based on domain attributes.

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
        if not (self.domain.attributes and self.domain.attributes.gti_assessment):
            return []

        gti_assessment = self.domain.attributes.gti_assessment
        if not (gti_assessment.verdict and gti_assessment.verdict.value):
            return []

        verdict = gti_assessment.verdict.value.upper()

        return [IndicatorTypeOV(verdict)]
