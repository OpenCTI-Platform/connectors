"""Processor of the Microsoft Sentinel analytics rules."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from connector.deployed_rules_processor import DeployedRulesProcessor
from connector.detection_rule import DetectionRule, RuleSkippedError
from connector.rule_mapper import map_rule
from connector.stix_builder import RuleStixBuilder
from connectors_sdk.models import OrganizationAuthor, TLPMarking
from sentinel_client import SentinelAlertRulesClient

if TYPE_CHECKING:
    from connector.settings import ConnectorSettings


class SentinelRulesProcessor(DeployedRulesProcessor):
    """Import the analytics rules of a Microsoft Sentinel workspace."""

    settings: ConnectorSettings
    work_name = "Microsoft Sentinel analytics rules"
    platform_label = "Microsoft Sentinel"

    def setup(self) -> None:
        """Create the Azure Resource Manager client and the STIX builder."""
        config = self.settings.sentinel_analytics_rules
        self.client = SentinelAlertRulesClient(
            tenant_id=config.tenant_id,
            client_id=config.client_id,
            client_secret=config.client_secret.get_secret_value(),
            subscription_id=config.subscription_id,
            resource_group=config.resource_group,
            workspace_name=config.workspace_name,
            api_version=config.api_version,
            logger=self.logger,
            management_url=str(config.management_url),
            login_url=str(config.login_url),
            timeout=config.request_timeout,
            max_retries=config.max_retries,
        )
        self.builder = RuleStixBuilder(
            author=OrganizationAuthor(
                name="Microsoft",
                description="Microsoft, maker of Microsoft Sentinel (cloud SIEM).",
            ),
            marking=TLPMarking(level=config.tlp_level),
            platform_name=config.platform_name,
            platform_type=config.platform_type,
            platform_description="Microsoft Sentinel workspace "
            f"{config.workspace_name} whose analytics rules are imported by the "
            "Microsoft Sentinel Analytics Rules connector.",
            source_name="Microsoft Sentinel",
        )
        self.configured_platform_id = config.platform_id

    def collect(self) -> list[dict[str, Any]]:
        """Read every alert rule of the workspace."""
        rules = list(self.client.iter_alert_rules())
        self.logger.info(
            "Microsoft Sentinel alert rules fetched",
            {
                "rules": len(rules),
                "workspace": self.settings.sentinel_analytics_rules.workspace_name,
            },
        )
        return rules

    def to_detection_rule(self, raw_rule: dict[str, Any]) -> DetectionRule:
        """Map an alert rule, leaving disabled ones out when configured so."""
        rule = map_rule(raw_rule)
        if (
            not rule.enabled
            and not self.settings.sentinel_analytics_rules.import_disabled_rules
        ):
            raise RuleSkippedError("disabled")
        return rule
