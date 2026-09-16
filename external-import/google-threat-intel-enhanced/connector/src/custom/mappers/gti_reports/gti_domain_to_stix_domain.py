"""Converts a GTI domain to a STIX domain object and indicator."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import pycti  # type: ignore
from connector.src.custom.models.gti_reports.gti_domain_model import (
    GTIDomainData,
)
from ...indicator_utils import (
    build_enhanced_description,
    build_vt_gui_url,
    compute_indicator_score,
    derive_verdict_from_stats,
    escape_stix_pattern_value,
    gti_score_and_verdict,
    is_indicator_allowed,
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
        indicator_scoring: str = "gti_derived",
        threat_actor_ids: Optional[List[str]] = None,
        malware_ids: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> None:
        """Initialize the GTIDomainToSTIXDomain object.

        Args:
        domain (GTIDomainData): The GTI domain data to convert.
        organization (Identity): The organization identity object.
        tlp_marking (MarkingDefinition): The TLP marking definition.
        indicator_scoring (str): The scoring mode to use ('gti_derived' or 'average_detection').
        threat_actor_ids (Optional[List[str]]): List of threat actor IDs associated with this domain.
        malware_ids (Optional[List[str]]): List of malware family IDs associated with this domain.

        """
        self.domain = domain
        self.organization = organization
        self.tlp_marking = tlp_marking
        self.indicator_scoring = indicator_scoring
        self.threat_actor_ids = threat_actor_ids or []
        self.malware_ids = malware_ids or []

    def _create_stix_domain(self) -> DomainNameModel:
        """Create the STIX domain observable object.

        Returns:
        DomainNameModel: The STIX domain observable model object.

        """
        score = self._get_score()
        description = self._get_description()
        external_references = self._get_external_references()
        labels = self._get_labels()

        domain_model = OctiDomainModel.create(
            value=self.domain.id,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
            score=score,
            description=description,
            external_references=external_references,
            labels=labels,
        )

        return domain_model

    def _create_stix_indicator(self) -> IndicatorModel:
        """Create the STIX indicator object.

        Returns:
        IndicatorModel: The STIX indicator model object.

        """
        timestamps = self._get_timestamps()
        created = timestamps["created"]
        score = compute_indicator_score(
            self.indicator_scoring,
            self._get_verdict(),
            self._get_severity(),
            self._get_analysis_stats(),
        )

        indicator_types = self._determine_indicator_types()

        indicator_model = OctiIndicatorModel.create(
            name=self.domain.id,
            pattern=f"[domain-name:value='{escape_stix_pattern_value(self.domain.id)}']",
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

    def _create_threat_actor_relationships(
        self, domain_observable: DomainNameModel
    ) -> List[RelationshipModel]:
        """Create relationships from threat actors (intrusion-sets) to domain observable.

        Args:
            domain_observable (DomainNameModel): The target domain observable object.

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
                target_ref=domain_observable.id,
                created=timestamps["created"],
                modified=timestamps["modified"],
                created_by_ref=self.organization.id,
                object_marking_refs=[self.tlp_marking.id],
            )
            relationships.append(relationship)

        return relationships

    def _create_malware_relationships(
        self, domain_observable: DomainNameModel
    ) -> List[RelationshipModel]:
        """Create relationships from malware families to domain observable.

        Args:
            domain_observable (DomainNameModel): The target domain observable object.

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
                target_ref=domain_observable.id,
                created=timestamps["created"],
                modified=timestamps["modified"],
                created_by_ref=self.organization.id,
                object_marking_refs=[self.tlp_marking.id],
            )
            relationships.append(relationship)

        return relationships

    def to_stix(self) -> List[Any]:
        """Convert the GTI domain to STIX domain and indicator objects.

        Returns:
        List[Any]: List containing the STIX domain observable, indicator model objects, and their relationship.

        """
        score = self._get_score()
        verdict = self._get_verdict()

        # Looks counter-intuitive but if the observable is not allowed to be an indicator based on score/verdict
        # we still want to create the URL observable to capture the data - just not the indicator or relationship
        if not is_indicator_allowed(score, verdict):
            domain_observable = self._create_stix_domain()
            result = [domain_observable]
            # Still add threat actor and malware relationships even without indicator
            result.extend(self._create_threat_actor_relationships(domain_observable))
            result.extend(self._create_malware_relationships(domain_observable))
            return result

        domain_observable = self._create_stix_domain()
        indicator = self._create_stix_indicator()
        relationship = self._create_relationship_indicator_domain(
            indicator, domain_observable
        )

        result = [domain_observable, indicator, relationship]
        # Add threat actor and malware relationships
        result.extend(self._create_threat_actor_relationships(domain_observable))
        result.extend(self._create_malware_relationships(domain_observable))
        return result

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
        """Get score from domain attributes using configured scoring mode.

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
        if self.domain.attributes:
            attrs = self.domain.attributes.model_dump()

        score, verdict, severity = gti_score_and_verdict(
            attrs.get("gti_assessment")
        )

        return build_enhanced_description(attrs, score, verdict, severity)

    def _get_external_references(self) -> List[Dict[str, Any]]:
        """Build external references including VirusTotal link.

        Returns:
            List of external reference dicts

        """
        vt_url = build_vt_gui_url("domain", self.domain.id)
        return [
            {
                "source_name": "VirusTotal",
                "url": vt_url,
                "description": f"VirusTotal link for domain: {self.domain.id}",
            }
        ]

    def _get_labels(self) -> Optional[List[str]]:
        """Get labels/tags from domain attributes.

        Returns:
            Optional[List[str]]: List of labels if available

        """
        if self.domain.attributes and self.domain.attributes.tags:
            return self.domain.attributes.tags
        return None

    def _get_analysis_stats(self) -> Optional[Dict[str, int]]:
        """Get analysis stats from domain attributes.

        Returns:
            Optional[Dict[str, int]]: Dictionary with malicious, suspicious, harmless, undetected counts

        """
        if not (self.domain.attributes and self.domain.attributes.last_analysis_stats):
            return None

        stats = self.domain.attributes.last_analysis_stats
        return {
            "malicious": stats.malicious,
            "suspicious": stats.suspicious,
            "harmless": stats.harmless,
            "undetected": stats.undetected,
        }

    def _get_verdict(self) -> Optional[str]:
        """Get verdict from domain attributes.

        Priority order:
        1. gti_assessment.verdict.value
        2. Derived from last_analysis_stats

        Returns:
            Optional[str]: The verdict if available, None otherwise

        """
        if (
            self.domain.attributes
            and self.domain.attributes.gti_assessment
            and self.domain.attributes.gti_assessment.verdict
        ):
            return self.domain.attributes.gti_assessment.verdict.value

        # Fallback: derive from last_analysis_stats
        stats = self._get_analysis_stats()
        if stats:
            return derive_verdict_from_stats(
                stats.get("malicious"),
                stats.get("suspicious"),
            )

        return None

    def _get_severity(self) -> Optional[str]:
        """Get severity from domain attributes.

        Returns:
            Optional[str]: The severity if available, None otherwise

        """
        if (
            self.domain.attributes
            and self.domain.attributes.gti_assessment
            and self.domain.attributes.gti_assessment.severity
        ):
            return self.domain.attributes.gti_assessment.severity.value
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
