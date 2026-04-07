"""Converts a GTI threat actor's targeted industries to STIX Identity objects as sectors."""

from datetime import datetime, timezone

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
from pydantic import BaseModel
from stix2.v21 import Identity  # type: ignore


class IdentityWithTiming(BaseModel):
    """Container for a STIX Identity object with timing metadata."""

    model_config = {"arbitrary_types_allowed": True}

    identity: Identity
    first_seen: datetime | None = None
    last_seen: datetime | None = None


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

    def to_stix(self) -> list[Identity]:
        """Convert the GTI threat actor targeted industries to STIX Identity objects.

        Returns:
            list[Identity]: The list of STIX Identity objects representing sectors.

        """
        return [item.identity for item in self.to_stix_with_timing()]

    def to_stix_with_timing(self) -> list[IdentityWithTiming]:
        """Convert the GTI threat actor targeted industries to IdentityWithTiming objects.

        Returns:
            list[IdentityWithTiming]: The list of IdentityWithTiming objects containing STIX Identity objects and timing metadata.

        """
        result: list[IdentityWithTiming] = []

        if (
            not hasattr(self.threat_actor, "attributes")
            or not self.threat_actor.attributes
        ):
            raise ValueError("Invalid threat actor attributes")

        targeted_industries = self.threat_actor.attributes.targeted_industries_tree
        if not targeted_industries:
            return result

        for industry_data in targeted_industries:
            identity_with_timing = self._process_industry_with_timing(industry_data)
            if identity_with_timing:
                result.append(identity_with_timing)

        return result

    def _create_sector_with_timing(
        self, industry_data: TargetedIndustry
    ) -> IdentityWithTiming:
        """Create an IdentityWithTiming object from targeted industry data.

        Args:
            industry_data (TargetedIndustry): The targeted industry data containing industry group information.

        Returns:
            IdentityWithTiming: The IdentityWithTiming object with timing metadata.

        """
        sector_name = industry_data.industry_group

        sector = OctiIdentitySectorModel.create(
            name=sector_name,
            description=industry_data.description,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
        )

        first_seen = None
        if industry_data.first_seen:
            first_seen = datetime.fromtimestamp(
                industry_data.first_seen, tz=timezone.utc
            )

        last_seen = None
        if industry_data.last_seen:
            last_seen = datetime.fromtimestamp(industry_data.last_seen, tz=timezone.utc)

        # Validate timing: if both are present, stop_time must be later than start_time
        if first_seen and last_seen and last_seen <= first_seen:
            # If stop_time is not later than start_time, only keep start_time
            last_seen = None

        return IdentityWithTiming(
            identity=sector.to_stix2_object(),
            first_seen=first_seen,
            last_seen=last_seen,
        )

    def _process_industry(self, industry_data: TargetedIndustry) -> Identity | None:
        """Process a targeted industry entry and convert to a sector Identity.

        Args:
            industry_data (TargetedIndustry): The targeted industry data to process.

        Returns:
                Identity | None: The STIX Identity object, or None if no valid industry group found.

        """
        if not industry_data.industry_group or not industry_data.industry_group.strip():
            return None

        return self._create_sector_with_timing(industry_data).identity

    def _process_industry_with_timing(
        self, industry_data: TargetedIndustry
    ) -> IdentityWithTiming | None:
        """Process a targeted industry entry and convert to IdentityWithTiming.

        Args:
            industry_data (TargetedIndustry): The targeted industry data to process.

        Returns:
            IdentityWithTiming | None: The IdentityWithTiming object, or None if no valid industry group found.

        """
        if not industry_data.industry_group or not industry_data.industry_group.strip():
            return None

        return self._create_sector_with_timing(industry_data)

    def _create_sector(self, industry_data: TargetedIndustry) -> Identity:
        """Create a Sector Identity object.

        Args:
            industry_data (TargetedIndustry): The targeted industry data containing industry group information.

        Returns:
            Identity: The STIX Identity object representing a sector.

        """
        return self._create_sector_with_timing(industry_data).identity
