"""STIX 2.1 objects describing deployed detection rules."""

from datetime import datetime, timezone
from typing import Any, Literal

import stix2
from connector.deployment import DEPLOYED_ON, RELATED_TO
from connector.detection_rule import DetectionRule
from connectors_sdk.models import OrganizationAuthor, TLPMarking
from pycti import Identity, Indicator, StixCoreRelationship

SecurityPlatformType = Literal["SIEM", "EDR", "XDR", "SOAR", "NDR", "ISPM"]


def stix_timestamp(value: datetime) -> str:
    """Format ``value`` as a STIX timestamp (UTC, millisecond precision)."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    utc = value.astimezone(timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


class RuleStixBuilder:
    """Build the objects of one Security Platform and its deployed rules."""

    def __init__(
        self,
        author: OrganizationAuthor,
        marking: TLPMarking,
        platform_name: str,
        platform_type: SecurityPlatformType,
        platform_description: str,
        source_name: str,
    ) -> None:
        """Prepare the author, marking and Security Platform objects.

        Args:
            author: Organization the imported objects are attributed to.
            marking: TLP marking applied to every imported object.
            platform_name: Name of the Security Platform identity.
            platform_type: ``security_platform_type`` of that identity.
            platform_description: Description of that identity.
            source_name: ``source_name`` of the rule external references.
        """
        self.author = author.to_stix2_object()
        self.marking = marking.to_stix2_object()
        self.source_name = source_name
        self.platform = stix2.Identity(
            id=Identity.generate_id(platform_name, "securityplatform"),
            name=platform_name,
            identity_class="securityplatform",
            description=platform_description,
            created_by_ref=self.author.id,
            object_marking_refs=[self.marking.id],
            custom_properties={"security_platform_type": platform_type},
        )

    @property
    def common_objects(self) -> list[Any]:
        """Objects every bundle carries: author, marking, Security Platform."""
        return [self.author, self.marking, self.platform]

    def indicator(self, rule: DetectionRule, run_time: datetime) -> stix2.Indicator:
        """Build the rule Indicator."""
        properties: dict[str, Any] = {}
        if rule.level:
            properties["x_opencti_rule_level"] = rule.level
        if rule.logsource:
            properties["x_opencti_rule_logsource"] = rule.logsource
        if rule.platforms:
            properties["x_mitre_platforms"] = rule.platforms
        reference: dict[str, str] = {
            "source_name": self.source_name,
            "external_id": rule.external_id,
        }
        if rule.url:
            reference["url"] = rule.url
        return stix2.Indicator(
            id=Indicator.generate_id(rule.pattern),
            name=rule.name,
            description=rule.description,
            pattern=rule.pattern,
            pattern_type=rule.pattern_type,
            valid_from=rule.created_at or rule.modified_at or run_time,
            created_by_ref=self.author.id,
            object_marking_refs=[self.marking.id],
            external_references=[reference],
            custom_properties=properties,
        )

    def indicates(
        self, indicator_id: str, attack_pattern_id: str
    ) -> stix2.Relationship:
        """Build the ``indicates`` relationship to a technique."""
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "indicates", indicator_id, attack_pattern_id
            ),
            relationship_type="indicates",
            source_ref=indicator_id,
            target_ref=attack_pattern_id,
            created_by_ref=self.author.id,
            object_marking_refs=[self.marking.id],
        )

    def deployment(
        self,
        indicator_id: str,
        external_id: str,
        status: str,
        last_sync_at: datetime,
        deployed_on_supported: bool,
        deployed_at: datetime | None = None,
        removed_at: datetime | None = None,
    ) -> stix2.Relationship:
        """Build the deployment of a rule Indicator on the Security Platform.

        ``deployed-on`` with the deployment properties when the platform
        defines it, otherwise ``related-to`` describing the deployment.
        """
        if not deployed_on_supported:
            return stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    RELATED_TO, indicator_id, self.platform.id
                ),
                relationship_type=RELATED_TO,
                source_ref=indicator_id,
                target_ref=self.platform.id,
                description=(
                    f"Deployed on {self.platform.name} "
                    f"(status: {status}, rule id: {external_id})"
                ),
                created_by_ref=self.author.id,
                object_marking_refs=[self.marking.id],
            )
        properties: dict[str, str] = {
            "deployment_status": status,
            "external_id": external_id,
            "last_sync_at": stix_timestamp(last_sync_at),
        }
        if deployed_at is not None:
            properties["deployed_at"] = stix_timestamp(deployed_at)
        if removed_at is not None:
            properties["removed_at"] = stix_timestamp(removed_at)
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                DEPLOYED_ON, indicator_id, self.platform.id
            ),
            relationship_type=DEPLOYED_ON,
            source_ref=indicator_id,
            target_ref=self.platform.id,
            created_by_ref=self.author.id,
            object_marking_refs=[self.marking.id],
            custom_properties=properties,
        )
