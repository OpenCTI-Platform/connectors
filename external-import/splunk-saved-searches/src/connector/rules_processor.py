"""Processor of the Splunk saved searches."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from connector.deployed_rules_processor import DeployedRulesProcessor
from connector.detection_rule import DetectionRule, RuleSkippedError
from connector.rule_mapper import map_saved_search, name_from_key
from connector.stix_builder import RuleStixBuilder
from connectors_sdk.models import OrganizationAuthor, TLPMarking
from splunk_client import SplunkSavedSearchesClient

if TYPE_CHECKING:
    from connector.settings import ConnectorSettings


class SplunkRulesProcessor(DeployedRulesProcessor):
    """Import the saved searches (detections) of a Splunk namespace."""

    settings: ConnectorSettings
    work_name = "Splunk saved searches"
    platform_label = "Splunk"

    def setup(self) -> None:
        """Create the Splunk REST client and the STIX builder."""
        config = self.settings.splunk_saved_searches
        self.client = SplunkSavedSearchesClient(
            str(config.api_url),
            config.token.get_secret_value(),
            logger=self.logger,
            app=config.app,
            owner=config.owner,
            web_url=str(config.web_url) if config.web_url else None,
            page_size=config.page_size,
            timeout=config.request_timeout,
            ssl_verify=config.verify_ssl,
            max_retries=config.max_retries,
        )
        self.builder = RuleStixBuilder(
            author=OrganizationAuthor(
                name="Splunk",
                description="Splunk, maker of Splunk Enterprise and Splunk "
                "Enterprise Security (SIEM).",
            ),
            marking=TLPMarking(level=config.tlp_level),
            platform_name=config.platform_name,
            platform_type=config.platform_type,
            platform_description="Splunk deployment whose saved searches are "
            "imported by the Splunk Saved Searches connector.",
            source_name="Splunk",
        )

    def collect(self) -> list[dict[str, Any]]:
        """Read every saved search of the namespace."""
        config = self.settings.splunk_saved_searches
        entries = list(self.client.iter_saved_searches())
        self.logger.info(
            "Splunk saved searches fetched",
            {"saved_searches": len(entries), "app": config.app, "owner": config.owner},
        )
        return entries

    def to_detection_rule(self, raw_rule: dict[str, Any]) -> DetectionRule:
        """Map a saved search of the configured scope."""
        config = self.settings.splunk_saved_searches
        rule = map_saved_search(
            raw_rule, config.search_scope, self.client.saved_search_url
        )
        if not rule.enabled and not config.import_disabled_rules:
            raise RuleSkippedError("disabled")
        return rule

    def external_id_for_key(self, key: str) -> str:
        """Saved searches are keyed by ``<app>/<owner>/<name>``."""
        return name_from_key(key)
