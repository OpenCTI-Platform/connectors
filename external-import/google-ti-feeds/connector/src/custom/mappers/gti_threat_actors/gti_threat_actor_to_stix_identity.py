"""Converts a GTI threat actor's targeted industries to STIX Identity objects as sectors."""

from typing import List, Optional

from connector.src.custom.models.gti.gti_threat_actor_model import (
    GTIThreatActorData,
    TargetedIndustry,
)
from connector.src.stix.octi.models.identity_sector_model import OctiIdentitySectorModel
from connector.src.utils.converters.generic_converter_config import BaseMapper
from connectors_sdk.models.octi import (  # type: ignore[import-untyped]
    OrganizationAuthor,
    TLPMarking,
)
from stix2.v21 import Identity  # type: ignore


class GTIThreatActorToSTIXIdentity(BaseMapper):
    """Converts a GTI Threat Actor's targeted industries to STIX Identity objects as sectors."""

    def __init__(
        self,
        threat_actor: GTIThreatActorData,
        organization: OrganizationAuthor,
        tlp_marking: TLPMarking,
    ):
        """Initialize the GTIThreatActorToSTIXIdentity object.

        Args:
            threat_actor (GTIThreatActorData): The GTI threat actor data to convert.
            organization (OrganizationAuthor): The organization identity object.
            tlp_marking (TLPMarking): The TLP marking definition.

        """
        self.threat_actor = threat_actor
        self.organization = organization
        self.tlp_marking = tlp_marking

    def to_stix(self) -> List[Identity]:
        """Convert the GTI threat actor targeted industries to STIX Identity objects.

        Returns:
            List[Identity]: The list of STIX Identity objects representing sectors.

        """
        result: List[Identity] = []

        if (
            not hasattr(self.threat_actor, "attributes")
            or not self.threat_actor.attributes
        ):
            raise ValueError("Invalid threat actor attributes")

        targeted_industries = self.threat_actor.attributes.targeted_industries_tree
        if not targeted_industries:
            return result

        for industry_data in targeted_industries:
            sector = self._process_industry(industry_data)
            if sector:
                result.append(sector)

        return result

    def _process_industry(self, industry_data: TargetedIndustry) -> Optional[Identity]:
        """Process a targeted industry entry and convert to a sector Identity.

        Args:
            industry_data (TargetedIndustry): The targeted industry data to process.

        Returns:
            Optional[Identity]: The STIX Identity object, or None if no valid industry group found.

        """
        if not industry_data.industry_group or not industry_data.industry_group.strip():
            return None

        return self._create_sector(industry_data)

    def _create_sector(self, industry_data: TargetedIndustry) -> Identity:
        """Create a Sector Identity object.

        Args:
            industry_data (TargetedIndustry): The targeted industry data containing industry group information.

        Returns:
            Identity: The STIX Identity object representing a sector.

        """
        sector_name = industry_data.industry_group

        sector = OctiIdentitySectorModel.create(
            name=sector_name,
            description=industry_data.description,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
        )

        return sector
