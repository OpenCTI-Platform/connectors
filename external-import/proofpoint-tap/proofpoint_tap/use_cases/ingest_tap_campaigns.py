# isort: skip_file
"""Offer tools to create entities from TAP Campaigns."""

from typing import TYPE_CHECKING

from proofpoint_tap.models.octi import (
    AttackPattern,
    Campaign,
    IntrusionSet,
    Malware,
    TargetedOrganization,
    CampaignAttributedToIntrusionSet,
    CampaignTargetsOrganization,
    CampaignUsesMalware,
    CampaignUsesAttackPattern,
)

if TYPE_CHECKING:
    from stix2 import TLPMarking  # type: ignore[import-untyped] # stix2 is not typed

    # for now we use V2 API compiled response directly into the use case and no interface injection.
    from proofpoint_tap.client_api.v2 import CampaignCompiledInfo
    from proofpoint_tap.client_api.v2.campaign import Actor, Brand, Technique
    from proofpoint_tap.client_api.v2.campaign import Malware as TAPMalware
    from proofpoint_tap.models.octi import BaseEntity, OrganizationAuthor


class TAPCampaignProcessor:
    """Process ProofPoint TAP Compiled Campaign data."""

    def __init__(self, author: "OrganizationAuthor", tlp_marking: "TLPMarking"):
        """Initialize the TAPCampaignProcessor with author and TLP marking."""
        self.author = author
        self.tlp_marking = tlp_marking

    def make_intrusion_set(self, tap_actor: "Actor") -> IntrusionSet:
        """Make an OCTI IntrusionSet from a ProofPoint TAP campaign.

        Args:
            tap_actor (Actor): The actor to ingest.
            author (OrganizationAuthor): The author of the intrusion set.
            tlp_marking (TLPMarking): default marking for ingested objects.

        """
        return IntrusionSet(
            name=tap_actor.name,
            description="",
            labels=None,
            markings=[self.tlp_marking],
            author=self.author,
            external_references=None,
        )

    def make_malware(self, tap_malware: "TAPMalware") -> Malware:
        """Make an OCTI Malware from a ProofPoint TAP malware.

        Args:
            tap_malware (TAPMalware): The malware to ingest.
            author (OrganizationAuthor): The author of the malware.
            tlp_marking (TLPMarking): default marking for ingested objects.

        """
        return Malware(
            name=tap_malware.name,
            types=None,
            is_family=False,
            description=None,
            architecture_execution_env=None,
            implementation_languages=None,
            kill_chain_phases=None,
            author=self.author,
            labels=None,
            markings=[self.tlp_marking],
            external_references=None,
        )

    def make_attack_pattern(self, tap_technique: "Technique") -> AttackPattern:
        """Make an OCTI AttackPattern from a ProofPoint TAP technique.

        Args:
            tap_technique (Technique): The technique to ingest.
            author (OrganizationAuthor): The author of the attack pattern.
            tlp_marking (TLPMarking): default marking for ingested objects.

        """
        return AttackPattern(
            name=tap_technique.name,
            external_id=None,
            description=None,
            kill_chain_phases=None,
            author=self.author,
            labels=None,
            markings=[self.tlp_marking],
            external_references=None,
        )

    def make_targeted_organization(
        self,
        tap_brand: "Brand",
    ) -> TargetedOrganization:
        """Make an OCTI TargetedOrganization from a ProofPoint TAP brand.

        Args:
            tap_brand (Brand): The brand to ingest.
            author (OrganizationAuthor): The author of the targeted organization.
            tlp_marking (TLPMarking): default marking for ingested objects.

        """
        return TargetedOrganization(
            name=tap_brand.name,
            description=None,
            labels=None,
            markings=[self.tlp_marking],
            author=self.author,
            contact_information=None,
            organization_type=None,
            external_references=None,
            confidence=None,
            reliability=None,
            aliases=None,
        )

    def make_campaign(self, tap_campaign: "CampaignCompiledInfo") -> Campaign:
        """Make an OCTI Campaign from a ProofPoint TAP campaign.

        Args:
            tap_campaign (CampaignCompiledInfo): The campaign to ingest.
            author (OrganizationAuthor): The author of the campaign.
            tlp_marking (TLPMarking): default marking for ingested objects.

        """
        return Campaign(
            name=tap_campaign.name,
            description=tap_campaign.description,
            first_seen=tap_campaign.start_date,
            last_seen=None,
            external_references=None,
            markings=[self.tlp_marking],
            labels=[family.name for family in tap_campaign.families or []],
            author=self.author,
        )

    def make_campaign_attributed_to_intrusion_set(
        self, campaign: Campaign, intrusion_set: IntrusionSet
    ) -> CampaignAttributedToIntrusionSet:
        """Make an OCTI CampaignAttributedToIntrusionSet relationship from a ProofPoint TAP campaign and an IntrusionSet."""
        return CampaignAttributedToIntrusionSet(
            author=self.author,
            created=None,
            modified=None,
            description=None,
            source=campaign,
            target=intrusion_set,
            start_time=None,
            stop_time=None,
            confidence=None,
            markings=[self.tlp_marking],
            external_references=None,
        )

    def make_campaign_targets_organization(
        self, campaign: Campaign, targeted_org: TargetedOrganization
    ) -> CampaignTargetsOrganization:
        """Make an OCTI CampaignTargetsOrganization relationship from a ProofPoint TAP campaign and a TargetedOrganization."""
        return CampaignTargetsOrganization(
            author=self.author,
            created=None,
            modified=None,
            description=None,
            source=campaign,
            target=targeted_org,
            start_time=None,
            stop_time=None,
            confidence=None,
            markings=[self.tlp_marking],
            external_references=None,
        )

    def make_campaign_uses_malware(
        self, campaign: Campaign, malware: Malware
    ) -> CampaignUsesMalware:
        """Make an OCTI CampaignUsesMalware relationship from a ProofPoint TAP campaign and a Malware."""
        return CampaignUsesMalware(
            author=self.author,
            created=None,
            modified=None,
            description=None,
            source=campaign,
            target=malware,
            start_time=None,
            stop_time=None,
            confidence=None,
            markings=[self.tlp_marking],
            external_references=None,
        )

    def make_campaign_uses_attack_pattern(
        self, campaign: Campaign, attack_pattern: AttackPattern
    ) -> CampaignUsesAttackPattern:
        """Make an OCTI CampaignUsesAttackPattern relationship from a ProofPoint TAP campaign and an AttackPattern."""
        return CampaignUsesAttackPattern(
            author=self.author,
            created=None,
            modified=None,
            description=None,
            source=campaign,
            target=attack_pattern,
            start_time=None,
            stop_time=None,
            confidence=None,
            markings=[self.tlp_marking],
            external_references=None,
        )

    def run_on(self, tap_campaign: "CampaignCompiledInfo") -> list["BaseEntity"]:
        """Run the process of entities creation thanks to a TAP Compiled Campaign."""
        # TODO add relationships creation

        entities: list["BaseEntity"] = []  # result holder

        # Process the campaign itself
        campaign = self.make_campaign(tap_campaign)
        entities.append(campaign)

        # Process associated actors
        for actor in tap_campaign.actors or []:
            intrusion_set = self.make_intrusion_set(actor)
            entities.append(intrusion_set)
            # Relationships
            entities.append(
                self.make_campaign_attributed_to_intrusion_set(campaign, intrusion_set)
            )

        # Process associated malware
        for malware in tap_campaign.malware or []:
            malware_entity = self.make_malware(malware)
            entities.append(malware_entity)
            # Relationships
            entities.append(self.make_campaign_uses_malware(campaign, malware_entity))

        # Process associated techniques
        for technique in tap_campaign.techniques or []:
            attack_pattern = self.make_attack_pattern(technique)
            entities.append(attack_pattern)
            # Relationships
            entities.append(
                self.make_campaign_uses_attack_pattern(campaign, attack_pattern)
            )

        # Process associated brands
        for brand in tap_campaign.brands or []:
            targeted_org = self.make_targeted_organization(brand)
            entities.append(targeted_org)
            # Relationships
            entities.append(
                self.make_campaign_targets_organization(campaign, targeted_org)
            )

        # Only append Author if at least one entity is present
        if entities:
            entities.append(self.author)
        return entities
