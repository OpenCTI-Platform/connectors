"""Processor of the Google SecOps detection rules."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from connector.deployed_rules_processor import DeployedRulesProcessor
from connector.detection_rule import DetectionRule, RuleSkippedError
from connector.rule_mapper import map_rule
from connector.stix_builder import RuleStixBuilder
from connectors_sdk.models import OrganizationAuthor, TLPMarking
from secops_client import (
    GoogleSecOpsRulesClient,
    rule_id_from_name,
    service_account_credentials,
)

if TYPE_CHECKING:
    from connector.settings import ConnectorSettings

RawRule = tuple[dict[str, Any], dict[str, Any] | None]


class GoogleSecOpsRulesProcessor(DeployedRulesProcessor):
    """Import the YARA-L detection rules of a Google SecOps instance."""

    settings: ConnectorSettings
    work_name = "Google SecOps detection rules"
    platform_label = "Google SecOps"

    def setup(self) -> None:
        """Create the Chronicle API client and the STIX builder."""
        config = self.settings.google_secops_rules
        try:
            credentials = service_account_credentials(
                client_email=config.client_email,
                private_key=config.private_key.get_secret_value(),
                private_key_id=config.private_key_id,
                token_uri=str(config.token_uri),
                project_id=config.project_id,
            )
        except ValueError as err:
            raise ValueError(
                f"Invalid Google service account private key: {err}"
            ) from err
        self.client = GoogleSecOpsRulesClient(
            base_url=str(config.base_url),
            region=config.project_region,
            project_id=config.project_id,
            instance_id=config.project_instance,
            api_version=config.api_version,
            credentials=credentials,
            logger=self.logger,
            page_size=config.page_size,
            timeout=config.request_timeout,
            max_retries=config.max_retries,
        )
        self.builder = RuleStixBuilder(
            author=OrganizationAuthor(
                name="Google",
                description="Google, maker of Google Security Operations "
                "(Google SecOps, formerly Chronicle).",
            ),
            marking=TLPMarking(level=config.tlp_level),
            platform_name=config.platform_name,
            platform_type=config.platform_type,
            platform_description=f"Google SecOps instance {config.project_instance} "
            "whose detection rules are imported by the Google SecOps Detection Rules "
            "connector.",
            source_name="Google SecOps",
        )

    def collect(self) -> list[RawRule]:
        """Read every rule of the instance with its deployment."""
        rules = list(self.client.iter_rules())
        deployments = self.client.rule_deployments()
        self.logger.info(
            "Google SecOps rules fetched",
            {
                "rules": len(rules),
                "live": sum(1 for d in deployments.values() if d.get("enabled")),
                "alerting": sum(1 for d in deployments.values() if d.get("alerting")),
                "archived": sum(1 for d in deployments.values() if d.get("archived")),
                "instance": self.settings.google_secops_rules.project_instance,
            },
        )
        return [
            (rule, deployments.get(rule_id_from_name(rule.get("name")) or ""))
            for rule in rules
        ]

    def to_detection_rule(self, raw_rule: RawRule) -> DetectionRule:
        """Map a rule, leaving the rules that are not live out when configured so."""
        rule, deployment = raw_rule
        detection_rule = map_rule(rule, deployment)
        if (
            not detection_rule.enabled
            and not self.settings.google_secops_rules.import_disabled_rules
        ):
            raise RuleSkippedError("disabled")
        return detection_rule
