"""Converts a GTI IP address to a STIX IP object and indicator."""

import ipaddress
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

import pycti  # type: ignore
from connector.src.custom.models.gti_reports.gti_ip_addresses_model import (
    GTIIPData,
)
from ...indicator_utils import (
    build_enhanced_description,
    build_vt_gui_url,
    compute_indicator_score,
    derive_verdict_from_stats,
    gti_score_and_verdict,
    is_indicator_allowed,
)
from connector.src.stix.octi.models.indicator_model import OctiIndicatorModel
from connector.src.stix.octi.models.ipv4_address_model import OctiIPv4AddressModel
from connector.src.stix.octi.models.ipv6_address_model import OctiIPv6AddressModel
from connector.src.stix.octi.observable_type_ov_enum import ObservableTypeOV
from connector.src.stix.octi.pattern_type_ov_enum import PatternTypeOV
from connector.src.stix.v21.models.ovs.indicator_type_ov_enums import IndicatorTypeOV
from connector.src.stix.v21.models.scos.ipv4_address_model import IPv4AddressModel
from connector.src.stix.v21.models.scos.ipv6_address_model import IPv6AddressModel
from connector.src.stix.v21.models.sdos.indicator_model import IndicatorModel
from connector.src.stix.v21.models.sros.relationship_model import RelationshipModel
from connector.src.utils.converters.generic_converter_config import BaseMapper
from stix2.v21 import Identity, MarkingDefinition  # type: ignore


class GTIIPToSTIXIP(BaseMapper):
    """Converts a GTI IP address to a STIX IP object and indicator."""

    def __init__(
        self,
        ip: GTIIPData,
        organization: Identity,
        tlp_marking: MarkingDefinition,
        indicator_scoring: str = "gti_derived",
        threat_actor_ids: Optional[List[str]] = None,
        malware_ids: Optional[List[str]] = None,
    ) -> None:
        """Initialize the GTIIPToSTIXIP object.

        Args:
        ip (GTIIPData): The GTI IP data to convert.
        organization (Identity): The organization identity object.
        tlp_marking (MarkingDefinition): The TLP marking definition.
        indicator_scoring (str): The scoring mode to use ('gti_derived' or 'average_detection').
        threat_actor_ids (Optional[List[str]]): List of threat actor IDs associated with this IP.
        malware_ids (Optional[List[str]]): List of malware family IDs associated with this IP.

        """
        self.ip = ip
        self.organization = organization
        self.tlp_marking = tlp_marking
        self.indicator_scoring = indicator_scoring
        self.threat_actor_ids = threat_actor_ids or []
        self.malware_ids = malware_ids or []

    def _detect_ip_version(self) -> str:
        """Detect if IP is IPv4 or IPv6.

        Returns:
            str: "ipv4" or "ipv6"

        Raises:
            ValueError: If IP format is invalid

        """
        try:
            ip_obj = ipaddress.ip_address(self.ip.id)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                return "ipv4"
            elif isinstance(ip_obj, ipaddress.IPv6Address):
                return "ipv6"
            else:
                raise ValueError(f"Unknown IP address type: {type(ip_obj)}")
        except ValueError as e:
            raise ValueError(f"Invalid IP address format '{self.ip.id}': {e}") from e

    def _create_stix_ip(self) -> Union[IPv4AddressModel, IPv6AddressModel]:
        """Create the STIX IP observable object (IPv4 or IPv6).

        Returns:
        Union[IPv4AddressModel, IPv6AddressModel]: The STIX IP observable model object.

        """
        score = self._get_score()

        ip_version = self._detect_ip_version()

        timestamps = self._get_timestamps()
        external_references = self._get_external_references()
        labels = self._get_labels()

        ip_model: Union[IPv4AddressModel, IPv6AddressModel]
        if ip_version == "ipv4":
            ip_model = OctiIPv4AddressModel.create(
                value=self.ip.id,
                organization_id=self.organization.id,
                marking_ids=[self.tlp_marking.id],
                score=score,
                description=self._get_description(),
                external_references=external_references,
                labels=labels,
                created=timestamps["created"],
                modified=timestamps["modified"],
            )
        else:
            ip_model = OctiIPv6AddressModel.create(
                value=self.ip.id,
                organization_id=self.organization.id,
                marking_ids=[self.tlp_marking.id],
                score=score,
                description=self._get_description(),
                external_references=external_references,
                labels=labels,
                created=timestamps["created"],
                modified=timestamps["modified"],
            )

        return ip_model

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

        ip_version = self._detect_ip_version()
        observable_type = (
            ObservableTypeOV.IPV4_ADDR
            if ip_version == "ipv4"
            else ObservableTypeOV.IPV6_ADDR
        )
        indicator_types = self._determine_indicator_types()

        indicator_model = OctiIndicatorModel.create(
            name=self.ip.id,
            pattern=pattern,
            pattern_type=PatternTypeOV.STIX,
            observable_type=observable_type,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
            indicator_types=indicator_types,
            score=score,
            created=created,
            modified=modified,
        )

        return indicator_model

    def _create_relationship_indicator_ip(
        self,
        indicator: IndicatorModel,
        ip_observable: Union[IPv4AddressModel, IPv6AddressModel],
    ) -> RelationshipModel:
        """Create a based-on relationship from indicator to IP observable.

        Args:
            indicator (IndicatorModel): The source indicator object.
            ip_observable (Union[IPv4AddressModel, IPv6AddressModel]): The target IP observable object.

        Returns:
            RelationshipModel: The relationship model object.

        """
        timestamps = self._get_timestamps()

        relationship = RelationshipModel(
            type="relationship",
            spec_version="2.1",
            source_ref=indicator.id,
            target_ref=ip_observable.id,
            relationship_type="based-on",
            created=timestamps["created"],
            modified=timestamps["modified"],
            created_by_ref=self.organization.id,
            object_marking_refs=[self.tlp_marking.id],
        )

        return relationship

    def _create_threat_actor_relationships(
        self, ip_observable: Union[IPv4AddressModel, IPv6AddressModel]
    ) -> List[RelationshipModel]:
        """Create relationships from threat actors (intrusion-sets) to IP observable.

        Args:
            ip_observable (Union[IPv4AddressModel, IPv6AddressModel]): The target IP observable object.

        Returns:
            List[RelationshipModel]: List of relationship model objects.

        """
        relationships = []
        timestamps = self._get_timestamps()

        for threat_actor_name in self.threat_actor_ids:
            # Generate deterministic STIX ID using pycti (same as when intrusion-set was created)
            intrusion_set_id = pycti.IntrusionSet.generate_id(name=threat_actor_name)

            relationship = RelationshipModel(
                type="relationship",
                spec_version="2.1",
                relationship_type="related-to",
                source_ref=intrusion_set_id,
                target_ref=ip_observable.id,
                created=timestamps["created"],
                modified=timestamps["modified"],
                created_by_ref=self.organization.id,
                object_marking_refs=[self.tlp_marking.id],
            )
            relationships.append(relationship)

        return relationships

    def _create_malware_relationships(
        self, ip_observable: Union[IPv4AddressModel, IPv6AddressModel]
    ) -> List[RelationshipModel]:
        """Create relationships from malware families to IP observable.

        Args:
            ip_observable (Union[IPv4AddressModel, IPv6AddressModel]): The target IP observable object.

        Returns:
            List[RelationshipModel]: List of relationship model objects.

        """
        relationships = []
        timestamps = self._get_timestamps()

        for malware_name in self.malware_ids:
            # Generate deterministic STIX ID using pycti (same as when malware was created)
            stix_malware_id = pycti.Malware.generate_id(name=malware_name)

            relationship = RelationshipModel(
                type="relationship",
                spec_version="2.1",
                relationship_type="related-to",
                source_ref=stix_malware_id,
                target_ref=ip_observable.id,
                created=timestamps["created"],
                modified=timestamps["modified"],
                created_by_ref=self.organization.id,
                object_marking_refs=[self.tlp_marking.id],
            )
            relationships.append(relationship)

        return relationships

    def to_stix(self) -> List[Any]:
        """Convert the GTI IP to STIX IP and indicator objects.

        Returns:
        List[Any]: List containing the STIX IP observable, indicator model objects, and their relationship.

        """
        score = self._get_score()
        verdict = self._get_verdict()

        # Looks counter-intuitive but if the observable is not allowed to be an indicator based on score/verdict
        # we still want to create the URL observable to capture the data - just not the indicator or relationship
        if not is_indicator_allowed(score, verdict):
            ip_observable = self._create_stix_ip()
            result = [ip_observable]
            result.extend(self._create_threat_actor_relationships(ip_observable))
            result.extend(self._create_malware_relationships(ip_observable))
            return result

        ip_observable = self._create_stix_ip()
        indicator = self._create_stix_indicator()
        relationship = self._create_relationship_indicator_ip(indicator, ip_observable)

        result = [ip_observable, indicator, relationship]
        result.extend(self._create_threat_actor_relationships(ip_observable))
        result.extend(self._create_malware_relationships(ip_observable))
        return result

    def _get_timestamps(self) -> Dict[str, datetime]:
        """Extract creation and modification timestamps from IP attributes.

        Returns:
            Dict[str, datetime]: Dictionary with 'created' and 'modified' timestamps

        """
        created = datetime.now(timezone.utc)
        modified = datetime.now(timezone.utc)

        if self.ip.attributes:
            if self.ip.attributes.last_analysis_date:
                created = datetime.fromtimestamp(
                    self.ip.attributes.last_analysis_date, tz=timezone.utc
                )
            if self.ip.attributes.last_modification_date:
                modified = datetime.fromtimestamp(
                    self.ip.attributes.last_modification_date, tz=timezone.utc
                )

        return {"created": created, "modified": modified}

    def _get_score(self) -> Optional[int]:
        """Get score from IP attributes using configured scoring mode.

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
        if self.ip.attributes:
            attrs = self.ip.attributes.model_dump()

        score, verdict, severity = gti_score_and_verdict(
            attrs.get("gti_assessment")
        )

        return build_enhanced_description(attrs, score, verdict, severity)

    def _get_external_references(self) -> List[Dict[str, Any]]:
        """Build external references including VirusTotal link.

        Returns:
            List of external reference dicts

        """
        vt_url = build_vt_gui_url("ip", self.ip.id)
        return [
            {
                "source_name": "VirusTotal",
                "url": vt_url,
                "description": f"VirusTotal link for IP: {self.ip.id}",
            }
        ]

    def _get_labels(self) -> Optional[List[str]]:
        """Get labels/tags from IP attributes.

        Returns:
            Optional[List[str]]: List of labels if available

        """
        if self.ip.attributes and self.ip.attributes.tags:
            return self.ip.attributes.tags
        return None

    def _get_analysis_stats(self) -> Optional[Dict[str, int]]:
        """Get analysis stats from IP attributes.

        Returns:
            Optional[Dict[str, int]]: Dictionary with malicious, suspicious, harmless, undetected counts

        """
        if not (self.ip.attributes and self.ip.attributes.last_analysis_stats):
            return None

        stats = self.ip.attributes.last_analysis_stats
        return {
            "malicious": stats.malicious,
            "suspicious": stats.suspicious,
            "harmless": stats.harmless,
            "undetected": stats.undetected,
        }

    def _build_stix_pattern(self) -> str:
        """Build STIX pattern for the IP indicator.

        Returns:
            str: STIX pattern string

        """
        ip_version = self._detect_ip_version()

        if ip_version == "ipv4":
            return f"[ipv4-addr:value = '{self.ip.id}']"
        else:
            return f"[ipv6-addr:value = '{self.ip.id}']"

    def _determine_indicator_types(self) -> List[IndicatorTypeOV]:
        """Determine indicator types based on IP attributes.

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
        if not (self.ip.attributes and self.ip.attributes.gti_assessment):
            return []

        gti_assessment = self.ip.attributes.gti_assessment
        if not (gti_assessment.verdict and gti_assessment.verdict.value):
            return []

        verdict = gti_assessment.verdict.value.upper()

        return [IndicatorTypeOV(verdict)]

    def _get_verdict(self) -> Optional[str]:
        """Get verdict from IP attributes.

        Priority order:
        1. gti_assessment.verdict.value
        2. Derived from last_analysis_stats

        Returns:
            Optional[str]: The verdict if available, None otherwise

        """
        if (
            self.ip.attributes
            and self.ip.attributes.gti_assessment
            and self.ip.attributes.gti_assessment.verdict
        ):
            return self.ip.attributes.gti_assessment.verdict.value

        # Fallback: derive from last_analysis_stats
        stats = self._get_analysis_stats()
        if stats:
            return derive_verdict_from_stats(
                stats.get("malicious"),
                stats.get("suspicious"),
            )

        return None

    def _get_severity(self) -> Optional[str]:
        """Get severity from IP attributes.

        Returns:
            Optional[str]: The severity if available, None otherwise

        """
        if (
            self.ip.attributes
            and self.ip.attributes.gti_assessment
            and self.ip.attributes.gti_assessment.severity
        ):
            return self.ip.attributes.gti_assessment.severity.value
        return None
