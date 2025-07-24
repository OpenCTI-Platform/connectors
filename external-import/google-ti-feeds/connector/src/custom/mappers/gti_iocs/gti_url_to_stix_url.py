"""Converts a GTI URL to a STIX URL object and indicator."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from connector.src.custom.models.gti.gti_url_model import (
    GTIURLData,
)
from connector.src.stix.octi.models.indicator_model import OctiIndicatorModel
from connector.src.stix.octi.models.relationship_model import OctiRelationshipModel
from connector.src.stix.octi.models.url_model import OctiUrlModel
from connector.src.stix.octi.observable_type_ov_enum import ObservableTypeOV
from connector.src.stix.octi.pattern_type_ov_enum import PatternTypeOV
from connector.src.stix.v21.models.ovs.indicator_type_ov_enums import IndicatorTypeOV
from connector.src.stix.v21.models.scos.url_model import URLModel
from connector.src.stix.v21.models.sdos.indicator_model import IndicatorModel
from connector.src.stix.v21.models.sros.relationship_model import RelationshipModel
from connector.src.utils.converters.generic_converter_config import BaseMapper
from connectors_sdk.models.octi import (  # type: ignore[import-untyped]
    OrganizationAuthor,
    TLPMarking,
)


class GTIUrlToSTIXUrl(BaseMapper):
    """Converts a GTI URL to a STIX URL object and indicator."""

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
            target_entity: The target entity (URL or intrusion set)

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
                created=datetime.now(),
                modified=datetime.now(),
                description=f"Indicator indicates {src_entity.__class__.__name__}",
            )
        else:
            return OctiRelationshipModel.create(
                relationship_type=relation_type,
                source_ref=src_entity.id,
                target_ref=target_entity.id,
                organization_id=src_entity.created_by_ref,
                marking_ids=src_entity.object_marking_refs,
                created=datetime.now(),
                modified=datetime.now(),
                description=f"{src_entity.__class__.__name__} {relation_type} {target_entity.__class__.__name__}",
            )

    def __init__(
        self,
        url: GTIURLData,
        organization: OrganizationAuthor,
        tlp_marking: TLPMarking,
    ) -> None:
        """Initialize the GTIUrlToSTIXUrl object.

        Args:
        url (GTIURLData): The GTI URL data to convert.
        organization (OrganizationAuthor): The organization identity object.
        tlp_marking (TLPMarking): The TLP marking definition.

        """
        self.url = url
        self.organization = organization
        self.tlp_marking = tlp_marking

    def _create_stix_url(self) -> URLModel:
        """Create the STIX URL observable object.

        Returns:
        OctiUrlModel: The STIX URL observable model object.

        """
        score = self._get_score()

        url_value = self._get_url_value()

        url_model = OctiUrlModel.create(
            value=url_value,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
            score=score,
        )

        return url_model

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

        url_value = self._get_url_value()

        indicator_model = OctiIndicatorModel.create(
            name=url_value,
            pattern=pattern,
            pattern_type=PatternTypeOV.STIX,
            observable_type=ObservableTypeOV.URL,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
            indicator_types=indicator_types,
            score=score,
            created=created,
            modified=modified,
        )

        return indicator_model

    def _create_relationship_indicator_url(
        self, indicator: IndicatorModel, url_observable: URLModel
    ) -> RelationshipModel:
        """Create a based-on relationship from indicator to URL observable.

        Args:
            indicator (IndicatorModel): The source indicator object.
            url_observable (URLModel): The target URL observable object.

        Returns:
            RelationshipModel: The relationship model object.

        """
        timestamps = self._get_timestamps()

        relationship = RelationshipModel(
            relationship_type="based-on",
            source_ref=indicator.id,
            target_ref=url_observable.id,
            created=timestamps["created"],
            modified=timestamps["modified"],
            created_by_ref=self.organization.id,
            object_marking_refs=[self.tlp_marking.id],
        )

        return relationship

    def to_stix(self) -> List[Any]:
        """Convert the GTI URL to STIX URL and indicator objects.

        Returns:
        List[Any]: List containing the STIX URL observable, indicator model objects, and their relationship.

        """
        url_observable = self._create_stix_url()
        indicator = self._create_stix_indicator()
        relationship = self._create_relationship_indicator_url(
            indicator, url_observable
        )

        return [url_observable, indicator, relationship]

    def _get_timestamps(self) -> Dict[str, datetime]:
        """Extract creation and modification timestamps from URL attributes.

        Returns:
            Dict[str, datetime]: Dictionary with 'created' and 'modified' timestamps

        """
        created = datetime.now(timezone.utc)
        modified = datetime.now(timezone.utc)

        if self.url.attributes:
            if self.url.attributes.first_submission_date:
                created = datetime.fromtimestamp(
                    self.url.attributes.first_submission_date, tz=timezone.utc
                )
            if self.url.attributes.last_modification_date:
                modified = datetime.fromtimestamp(
                    self.url.attributes.last_modification_date, tz=timezone.utc
                )

        return {"created": created, "modified": modified}

    def _get_score(self) -> Optional[int]:
        """Get score from URL attributes.

        Priority order:
        1. contributing_factors.mandiant_confidence_score
        2. threat_score.value

        Returns:
            Optional[int]: The score if available, None otherwise

        """
        if (
            self.url.attributes
            and self.url.attributes.gti_assessment
            and self.url.attributes.gti_assessment.contributing_factors
            and hasattr(
                self.url.attributes.gti_assessment.contributing_factors,
                "mandiant_confidence_score",
            )
            and self.url.attributes.gti_assessment.contributing_factors.mandiant_confidence_score
            is not None
        ):
            return (
                self.url.attributes.gti_assessment.contributing_factors.mandiant_confidence_score
            )

        if (
            self.url.attributes
            and self.url.attributes.gti_assessment
            and self.url.attributes.gti_assessment.threat_score
        ):
            return self.url.attributes.gti_assessment.threat_score.value

        return None

    def _get_url_value(self) -> str:
        """Get the URL value with priority order.

        Priority order:
        1. attributes.url (original URL)
        2. attributes.last_final_url (final URL after redirects)
        3. id (fallback)

        Returns:
            str: The URL value

        """
        if self.url.attributes and self.url.attributes.url:
            return self.url.attributes.url
        elif self.url.attributes and self.url.attributes.last_final_url:
            return self.url.attributes.last_final_url
        else:
            return self.url.id

    def _build_stix_pattern(self) -> str:
        """Build STIX pattern for the URL indicator.

        Returns:
            str: STIX pattern string

        """
        url_value = self._get_url_value()
        return f"[url:value = '{url_value}']"

    def _determine_indicator_types(self) -> List[IndicatorTypeOV]:
        """Determine indicator types based on URL attributes.

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
        if not (self.url.attributes and self.url.attributes.gti_assessment):
            return []

        gti_assessment = self.url.attributes.gti_assessment
        if not (gti_assessment.verdict and gti_assessment.verdict.value):
            return []

        verdict = gti_assessment.verdict.value.upper()

        return [IndicatorTypeOV(verdict)]
