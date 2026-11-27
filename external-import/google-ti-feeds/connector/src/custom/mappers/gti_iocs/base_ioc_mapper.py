"""Shared mapping of a GTI IOC to an observable, an indicator and their 'based-on' link."""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, ClassVar, Generic, Protocol, TypeVar

from connector.src.custom.mappers.gti_iocs.gti_links import gti_external_reference
from connector.src.custom.mappers.gti_iocs.indicator_type_helpers import (
    indicator_types_from_verdict,
)
from connector.src.custom.mappers.gti_iocs.ioc_assessment import (
    build_ioc_description,
    ioc_tag_labels,
    observable_description_properties,
    threat_category,
)
from connector.src.custom.mappers.gti_iocs.ioc_scoring import (
    compute_ioc_score,
    meets_min_verdict,
)
from connector.src.custom.mappers.relationship_reasons import (
    gti_collection_id,
    ioc_threat_evidence,
)
from connector.src.stix.octi.models.indicator_model import OctiIndicatorModel
from connector.src.stix.octi.models.relationship_model import OctiRelationshipModel
from connector.src.stix.octi.observable_type_ov_enum import ObservableTypeOV
from connector.src.stix.octi.pattern_type_ov_enum import PatternTypeOV
from connector.src.stix.v21.models.ovs.indicator_type_ov_enums import IndicatorTypeOV
from connector.src.stix.v21.models.sdos.indicator_model import IndicatorModel
from connector.src.stix.v21.models.sros.relationship_model import RelationshipModel
from connector.src.utils.converters.generic_converter_config import BaseMapper
from connectors_sdk.models import (  # type: ignore[import-untyped]
    OrganizationAuthor,
    TLPMarking,
)


class GTIIOCData(Protocol):
    """GTI IOC data: domain, file, IP address or URL."""

    id: str
    attributes: Any


IOCData = TypeVar("IOCData", bound=GTIIOCData)

# Objects describing the IOC itself, not linked to the report, campaign or threat it comes from.
IOC_CONTEXT_ONLY_TYPES = ("autonomous-system", "location")


class BaseIOCMapper(BaseMapper, ABC, Generic[IOCData]):
    """Convert a GTI IOC to an observable, an indicator and a 'based-on' relationship.

    Subclasses build the observable, the pattern and the timestamps.
    """

    # GTI IOC type, for the GTI page link: file, domain, ip_address or url.
    ioc_type: ClassVar[str]

    @staticmethod
    def create_relationship(
        src_entity: Any, relation_type: str, target_entity: Any
    ) -> Any:
        """Create a relationship between a context entity and a converted IOC object.

        Indicators get 'indicates' from the indicator to the context entity, other
        objects get ``relation_type`` from the context entity to the object.

        Args:
            src_entity: The context entity (e.g. intrusion set, campaign)
            relation_type: The relationship type (e.g. "related-to")
            target_entity: The converted IOC object

        Returns:
            RelationshipModel | None: The relationship object, None for objects
                describing the IOC itself, such as its autonomous system.

        """
        if getattr(target_entity, "type", None) in IOC_CONTEXT_ONLY_TYPES:
            return None
        if isinstance(target_entity, IndicatorModel):
            source_ref, target_ref = target_entity.id, src_entity.id
            relation_type = "indicates"
        else:
            source_ref, target_ref = src_entity.id, target_entity.id
        return OctiRelationshipModel.create(
            relationship_type=relation_type,
            source_ref=source_ref,
            target_ref=target_ref,
            organization_id=src_entity.created_by_ref,
            marking_ids=src_entity.object_marking_refs,
            created=datetime.now(tz=timezone.utc),
            modified=datetime.now(tz=timezone.utc),
        )

    def __init__(
        self,
        ioc: IOCData,
        organization: OrganizationAuthor,
        tlp_marking: TLPMarking,
        indicator_scoring: str = "threat_score",
        extended_descriptions: bool = False,
        indicator_min_verdict: str = "any",
        ioc_tags_as_labels: bool = False,
    ) -> None:
        """Initialize the mapper.

        Args:
            ioc: The GTI IOC data to convert.
            organization: The author of the objects.
            tlp_marking: The TLP marking of the objects.
            indicator_scoring: Score strategy, see `compute_ioc_score`.
            extended_descriptions: Whether to describe the GTI assessment.
            indicator_min_verdict: Lowest verdict creating an indicator, see `meets_min_verdict`.
            ioc_tags_as_labels: Whether to label the objects with the GTI tags.

        """
        self.ioc = ioc
        self.organization = organization
        self.tlp_marking = tlp_marking
        self.indicator_scoring = indicator_scoring
        self.extended_descriptions = extended_descriptions
        self.indicator_min_verdict = indicator_min_verdict
        self.ioc_tags_as_labels = ioc_tags_as_labels

    @abstractmethod
    def _create_stix_observable(self) -> Any:
        """Create the STIX observable."""

    @abstractmethod
    def _build_stix_pattern(self) -> str:
        """Build the STIX pattern of the indicator."""

    @abstractmethod
    def _observable_type(self) -> ObservableTypeOV:
        """Return the main observable type of the indicator."""

    @abstractmethod
    def _get_timestamps(self) -> dict[str, datetime]:
        """Return the 'created' and 'modified' timestamps of the objects."""

    def _indicator_name(self) -> str:
        """Return the indicator name, the GTI ID by default."""
        return self.ioc.id

    def to_stix(self) -> list[Any]:
        """Convert the GTI IOC to STIX objects.

        Returns:
            list[Any]: The observable, the indicator and their relationship, or
                the observable alone when the verdict is below `indicator_min_verdict`.

        """
        observable = self._create_stix_observable()
        if not meets_min_verdict(self.ioc.attributes, self.indicator_min_verdict):
            return [observable]
        indicator = self._create_stix_indicator()
        return [observable, indicator, self._create_based_on(indicator, observable)]

    def _create_stix_indicator(self) -> IndicatorModel:
        """Create the STIX indicator.

        Returns:
            IndicatorModel: The STIX indicator model object.

        """
        timestamps = self._get_timestamps()
        return OctiIndicatorModel.create(
            name=self._indicator_name(),
            pattern=self._build_stix_pattern(),
            pattern_type=PatternTypeOV.STIX,
            observable_type=self._observable_type(),
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
            indicator_types=self._determine_indicator_types(),
            score=self._get_score(),
            description=self._get_description(),
            labels=self._get_labels(),
            external_references=[
                gti_external_reference(
                    self.ioc_type, self.ioc.id, self._indicator_name()
                )
            ],
            created=timestamps["created"],
            modified=timestamps["modified"],
        )

    def _create_based_on(
        self, indicator: IndicatorModel, observable: Any
    ) -> RelationshipModel:
        """Create the 'based-on' relationship from the indicator to the observable."""
        return self._create_ioc_relationship("based-on", indicator, observable)

    def _create_ioc_relationship(
        self,
        relationship_type: str,
        source: Any,
        target: Any,
        description: str | None = None,
    ) -> RelationshipModel:
        """Create a relationship between two objects of the IOC, with its timestamps."""
        timestamps = self._get_timestamps()
        return RelationshipModel(
            relationship_type=relationship_type,
            source_ref=source.id,
            target_ref=target.id,
            description=description,
            created=timestamps["created"],
            modified=timestamps["modified"],
            created_by_ref=self.organization.id,
            object_marking_refs=[self.tlp_marking.id],
        )

    def _observable_custom_properties(self) -> dict[str, Any]:
        """Return the custom properties shared by the observables."""
        properties = observable_description_properties(self._get_description())
        if labels := self._get_labels():
            properties["x_opencti_labels"] = labels
        return properties

    def relationship_evidence(self, context_entity: Any) -> str | None:
        """Return the GTI evidence of this IOC supporting its link to the context entity."""
        if not self.ioc.attributes:
            return None
        return ioc_threat_evidence(
            getattr(self.ioc.attributes, "gti_assessment", None),
            getattr(context_entity, "type", None),
            getattr(context_entity, "name", None),
            gti_collection_id(context_entity),
            getattr(self.ioc.attributes, "sandbox_verdicts", None),
        )

    def _get_labels(self) -> list[str] | None:
        """Return the GTI tags and file threat category when enabled, or None."""
        if not self.ioc_tags_as_labels or not self.ioc.attributes:
            return None
        return ioc_tag_labels(
            getattr(self.ioc.attributes, "tags", None),
            threat_category(self.ioc.attributes),
        )

    def _get_description(self) -> str | None:
        """Get the GTI assessment summary when enabled.

        Returns:
            str | None: The description, None when disabled or empty

        """
        if not self.extended_descriptions:
            return None
        return build_ioc_description(
            self.ioc.attributes, self._natively_linked_fields()
        )

    def _natively_linked_fields(self) -> frozenset[str]:
        """Return the fields imported as linked objects, left out of the description."""
        return frozenset()

    def _get_score(self) -> int | None:
        """Get the score computed with the configured scoring strategy.

        Returns:
            int | None: The score if available, None otherwise

        """
        return compute_ioc_score(self.ioc.attributes, self.indicator_scoring)

    def _determine_indicator_types(self) -> list[IndicatorTypeOV]:
        """Determine indicator types from the GTI assessment verdict.

        Returns:
            list[IndicatorTypeOV]: list of indicator types, empty when no
            classification is available (field should be omitted downstream).

        """
        if not self.ioc.attributes:
            return []
        return indicator_types_from_verdict(self.ioc.attributes.gti_assessment)
