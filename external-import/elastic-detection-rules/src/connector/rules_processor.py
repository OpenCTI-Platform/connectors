"""Processor of the Elastic Security detection rules."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from connector.deployed_rules_processor import DeployedRulesProcessor
from connector.detection_rule import DetectionRule, RuleSkippedError
from connector.rule_mapper import map_rule
from connector.stix_builder import RuleStixBuilder
from connectors_sdk.models import OrganizationAuthor, TLPMarking
from elastic_client import ElasticDetectionRulesClient

if TYPE_CHECKING:
    from connector.settings import ConnectorSettings


class ElasticRulesProcessor(DeployedRulesProcessor):
    """Import the detection rules of a Kibana space."""

    settings: ConnectorSettings
    work_name = "Elastic Security detection rules"
    platform_label = "Elastic Security"

    def setup(self) -> None:
        """Create the Kibana client and the STIX builder."""
        config = self.settings.elastic_detection_rules
        self.client = ElasticDetectionRulesClient(
            str(config.kibana_url),
            config.api_key.get_secret_value(),
            logger=self.logger,
            space_id=config.space_id,
            page_size=config.page_size,
            timeout=config.request_timeout,
            ssl_verify=config.verify_ssl,
            max_retries=config.max_retries,
        )
        self.builder = RuleStixBuilder(
            author=OrganizationAuthor(
                name="Elastic",
                description="Elastic, maker of Elastic Security (SIEM and XDR).",
            ),
            marking=TLPMarking(level=config.tlp_level),
            platform_name=config.platform_name,
            platform_type=config.platform_type,
            platform_description="Elastic Security deployment whose detection rules "
            "are imported by the Elastic Security Detection Rules connector.",
            source_name="Elastic Security",
        )
        self.configured_platform_id = config.platform_id

    def collect(self) -> list[dict[str, Any]]:
        """Read every detection rule of the space."""
        config = self.settings.elastic_detection_rules
        rules = list(self.client.iter_rules(config.rule_filter))
        self.logger.info(
            "Elastic Security detection rules fetched",
            {"rules": len(rules), "space": config.space_id or "default"},
        )
        return rules

    def to_detection_rule(self, raw_rule: dict[str, Any]) -> DetectionRule:
        """Map a Kibana rule, leaving disabled ones out when configured so."""
        rule = map_rule(raw_rule, self.client.rule_url)
        if (
            not rule.enabled
            and not self.settings.elastic_detection_rules.import_disabled_rules
        ):
            raise RuleSkippedError("disabled")
        return rule
