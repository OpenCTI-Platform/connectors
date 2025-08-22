"""Converts a GTI threat actor's country regions to STIX Location objects."""

from typing import List, Optional

from connector.src.custom.models.gti.gti_threat_actor_model import (
    GTIThreatActorData,
    SourceRegion,
    TargetedRegion,
)
from connector.src.stix.octi.models.location_model import OctiLocationModel
from connector.src.utils.converters.generic_converter_config import BaseMapper
from connectors_sdk.models.octi import (  # type: ignore[import-untyped]
    OrganizationAuthor,
    TLPMarking,
)
from stix2.v21 import Location  # type: ignore


class GTIThreatActorToSTIXLocation(BaseMapper):
    """Converts a GTI Threat Actor's country regions to STIX Location objects."""

    def __init__(
        self,
        threat_actor: GTIThreatActorData,
        organization: OrganizationAuthor,
        tlp_marking: TLPMarking,
    ):
        """Initialize the GTIThreatActorToSTIXLocation object.

        Args:
            threat_actor (GTIThreatActorData): The GTI threat actor data to convert.
            organization (OrganizationAuthor): The organization identity object.
            tlp_marking (TLPMarking): The TLP marking definition.

        """
        self.threat_actor = threat_actor
        self.organization = organization
        self.tlp_marking = tlp_marking

    def to_stix(self) -> List[Location]:
        """Convert the GTI threat actor country regions to STIX Location objects.

        Returns:
            List[Location]: The list of STIX Location objects (countries only).

        """
        result: List[Location] = []

        if (
            not hasattr(self.threat_actor, "attributes")
            or not self.threat_actor.attributes
        ):
            raise ValueError("Invalid threat actor attributes")

        targeted_regions = self.threat_actor.attributes.targeted_regions_hierarchy
        if targeted_regions:
            for target_region_data in targeted_regions:
                location = self._create_country_from_targeted(target_region_data)
                if location:
                    result.append(location)

        source_regions = self.threat_actor.attributes.source_regions_hierarchy
        if source_regions:
            for source_region_data in source_regions:
                location = self._create_country_from_source(source_region_data)
                if location:
                    result.append(location)

        return result

    def _create_country_from_targeted(
        self, region_data: TargetedRegion
    ) -> Optional[Location]:
        """Create a LocationCountry object from targeted region data (countries only).

        Args:
            region_data (TargetedRegion): The targeted region data containing country information.

        Returns:
            Optional[Location]: The STIX LocationCountry object, or None if invalid.

        """
        if not region_data.country or not region_data.country_iso2:
            return None

        country = OctiLocationModel.create_country(
            name=region_data.country,
            country_code=region_data.country_iso2,
            description=region_data.description,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
        )

        return country.to_stix2_object()

    def _create_country_from_source(
        self, region_data: SourceRegion
    ) -> Optional[Location]:
        """Create a LocationCountry object from source region data (countries only).

        Args:
            region_data (SourceRegion): The source region data containing country information.

        Returns:
            Optional[Location]: The STIX LocationCountry object, or None if invalid.

        """
        if not region_data.country or not region_data.country_iso2:
            return None

        country = OctiLocationModel.create_country(
            name=region_data.country,
            country_code=region_data.country_iso2,
            description=region_data.description,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
        )

        return country.to_stix2_object()
