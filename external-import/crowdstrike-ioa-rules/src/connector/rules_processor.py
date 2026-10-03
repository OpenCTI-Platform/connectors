"""Processor of the CrowdStrike Falcon custom IOA rules."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from connector.deployed_rules_processor import DeployedRulesProcessor
from connector.detection_rule import DetectionRule, RuleSkippedError
from connector.rule_mapper import instance_id_from_key, iter_rules, map_rule
from connector.stix_builder import RuleStixBuilder
from connectors_sdk import ApiForbiddenError
from connectors_sdk.models import OrganizationAuthor, TLPMarking
from crowdstrike_client import CrowdStrikeIoaClient

if TYPE_CHECKING:
    from connector.settings import ConnectorSettings

RawRule = tuple[dict[str, Any], dict[str, Any], bool]


class CrowdStrikeRulesProcessor(DeployedRulesProcessor):
    """Import the custom IOA rules of a CrowdStrike Falcon CID."""

    settings: ConnectorSettings
    work_name = "CrowdStrike Falcon custom IOA rules"
    platform_label = "CrowdStrike Falcon"

    def setup(self) -> None:
        """Create the CrowdStrike API client and the STIX builder."""
        config = self.settings.crowdstrike_ioa_rules
        self.client = CrowdStrikeIoaClient(
            str(config.base_url),
            config.client_id,
            config.client_secret.get_secret_value(),
            logger=self.logger,
            member_cid=config.member_cid,
            page_size=config.page_size,
            timeout=config.request_timeout,
            max_retries=config.max_retries,
        )
        self.builder = RuleStixBuilder(
            author=OrganizationAuthor(
                name="CrowdStrike",
                description="CrowdStrike, maker of the CrowdStrike Falcon platform "
                "(EDR and XDR).",
            ),
            marking=TLPMarking(level=config.tlp_level),
            platform_name=config.platform_name,
            platform_type=config.platform_type,
            platform_description="CrowdStrike Falcon tenant whose custom IOA rules "
            "are imported by the CrowdStrike Falcon Custom IOA Rules connector.",
            source_name="CrowdStrike Falcon",
        )

    def collect(self) -> list[RawRule]:
        """Read every custom IOA rule group and flatten its rules."""
        config = self.settings.crowdstrike_ioa_rules
        groups = list(self.client.iter_rule_groups(config.rule_group_filter))
        enforced = (
            self._enforced_group_ids() if config.check_prevention_policies else None
        )
        rules = iter_rules(groups, enforced)
        self.logger.info(
            "CrowdStrike custom IOA rules fetched",
            {
                "rule_groups": len(groups),
                "rules": len(rules),
                "rule_groups_in_prevention_policies": (
                    None
                    if enforced is None
                    else sum(1 for group in groups if str(group.get("id")) in enforced)
                ),
            },
        )
        return rules

    def _enforced_group_ids(self) -> set[str] | None:
        """Rule groups assigned to an enabled prevention policy, ``None`` if unknown."""
        try:
            return self.client.enforced_rule_group_ids()
        except ApiForbiddenError:
            self.logger.warning(
                "The API client cannot read prevention policies (missing the "
                "'Prevention policies: Read' scope): the deployment status only "
                "reflects whether rules and rule groups are enabled",
                {"platform": self.platform_label},
            )
            return None

    def to_detection_rule(self, raw_rule: RawRule) -> DetectionRule:
        """Map a rule of its group, leaving disabled ones out when configured so."""
        group, rule, enforced = raw_rule
        detection_rule = map_rule(group, rule, enforced)
        if (
            not detection_rule.enabled
            and not self.settings.crowdstrike_ioa_rules.import_disabled_rules
        ):
            raise RuleSkippedError("disabled")
        return detection_rule

    def external_id_for_key(self, key: str) -> str:
        """Rules are keyed by ``<rule group id>/<instance id>``."""
        return instance_id_from_key(key)
