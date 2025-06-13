"""Converts a GTI IP address to a STIX IP object and indicator."""

import ipaddress
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from connector.src.custom.models.gti_reports.gti_ip_addresses_model import (
    GTIIPData,
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
    ) -> None:
        """Initialize the GTIIPToSTIXIP object.

        Args:
        ip (GTIIPData): The GTI IP data to convert.
        organization (Identity): The organization identity object.
        tlp_marking (MarkingDefinition): The TLP marking definition.

        """
        self.ip = ip
        self.organization = organization
        self.tlp_marking = tlp_marking

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

        ip_model: Union[IPv4AddressModel, IPv6AddressModel]
        if ip_version == "ipv4":
            ip_model = OctiIPv4AddressModel.create(
                value=self.ip.id,
                organization_id=self.organization.id,
                marking_ids=[self.tlp_marking.id],
                score=score,
                created=timestamps["created"],
                modified=timestamps["modified"],
            )
        else:
            ip_model = OctiIPv6AddressModel.create(
                value=self.ip.id,
                organization_id=self.organization.id,
                marking_ids=[self.tlp_marking.id],
                score=score,
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
        score = self._get_score()

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

    def to_stix(self) -> List[Any]:
        """Convert the GTI IP to STIX IP and indicator objects.

        Returns:
        List[Any]: List containing the STIX IP observable, indicator model objects, and their relationship.

        """
        ip_observable = self._create_stix_ip()
        indicator = self._create_stix_indicator()
        relationship = self._create_relationship_indicator_ip(indicator, ip_observable)

        return [ip_observable, indicator, relationship]

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
        """Get score from IP attributes.

        Priority order:
        1. contributing_factors.mandiant_confidence_score
        2. threat_score.value

        Returns:
            Optional[int]: The score if available, None otherwise

        """
        if (
            self.ip.attributes
            and self.ip.attributes.gti_assessment
            and self.ip.attributes.gti_assessment.contributing_factors
            and hasattr(
                self.ip.attributes.gti_assessment.contributing_factors,
                "mandiant_confidence_score",
            )
            and self.ip.attributes.gti_assessment.contributing_factors.mandiant_confidence_score
            is not None
        ):
            return (
                self.ip.attributes.gti_assessment.contributing_factors.mandiant_confidence_score
            )

        if (
            self.ip.attributes
            and self.ip.attributes.gti_assessment
            and self.ip.attributes.gti_assessment.threat_score
        ):
            return self.ip.attributes.gti_assessment.threat_score.value

        return None

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
