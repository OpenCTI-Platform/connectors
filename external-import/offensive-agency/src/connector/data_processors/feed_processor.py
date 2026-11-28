"""Processor importing the offensive.agency feed.

The feed lists Internet-exposed consoles of offensive AI agents seen by ONYPHE:
one STIX indicator per IPv4 address, linked by `indicates` relationships to the
agents (STIX tools) it runs. It covers a sliding window of 7 days and is dated
by day.
"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from collections.abc import Generator
from datetime import datetime
from itertools import batched

from connector.settings import ConnectorSettings
from connector.state import ConnectorState
from connectors_sdk import BaseDataProcessor, DataConversionError, DataError
from connectors_sdk.models import (
    BaseIdentifiedObject,
    ExternalReference,
    Indicator,
    IPV4Address,
    OrganizationAuthor,
    Relationship,
    TLPMarking,
    Tool,
)
from connectors_sdk.models.enums import RelationshipType
from offensive_agency_client import (
    Feed,
    FeedIndicator,
    FeedRelationship,
    FeedTool,
    OffensiveAgencyClient,
)
from offensive_agency_client.models import FeedExternalReference

# Indicators per bundle. Each one produces up to 1 indicator, 1 observable,
# 1 `based-on` and a few `indicates` relationships, so a bundle stays under
# about 10,000 objects.
INDICATORS_PER_BUNDLE = 2000

AUTHOR_NAME = "offensive.agency"
AUTHOR_DESCRIPTION = (
    "Data by ONYPHE (https://www.onyphe.io), published by offensive.agency "
    "(https://www.offensive.agency). Free to use, please credit both."
)

IPV4_PATTERN = re.compile(r"\[ipv4-addr:value\s*=\s*'([^']+)'\]")


class FeedProcessor(BaseDataProcessor[ConnectorSettings, ConnectorState]):
    """Fetch the feed and send the indicators that changed since the last run."""

    work_name = "Offensive Agency feed import"

    def post_init(self) -> None:
        """Build the API client and the objects shared by every bundle."""
        config = self.settings.offensive_agency
        self.client = OffensiveAgencyClient(
            base_url=str(config.api_base_url), logger=self.logger
        )
        self.author = OrganizationAuthor(
            name=AUTHOR_NAME, description=AUTHOR_DESCRIPTION
        )
        self.tlp_marking = TLPMarking(level=config.tlp_level)

    def collect(self) -> Feed:
        """Download the feed.

        Returns:
            Feed: The validated tools, indicators and relationships.
        """
        return self.client.get_feed()

    def transform(
        self, feed: Feed
    ) -> Generator[list[BaseIdentifiedObject], None, None]:
        """Convert the indicators modified since the checkpoint, bundle by bundle.

        Args:
            feed: The feed returned by `collect`.

        Yields:
            list[BaseIdentifiedObject]: One bundle: the author, the marking, the
            tools and up to `INDICATORS_PER_BUNDLE` converted indicators with
            their observables and relationships.
        """
        checkpoint = self.state.last_modified
        indicators = sorted(
            (
                indicator
                for indicator in feed.indicators
                # The feed is dated by day: entries of the checkpoint day are
                # sent again, since some may have been added after the last run.
                if checkpoint is None or indicator.modified >= checkpoint
            ),
            key=lambda indicator: indicator.modified,
        )
        self.logger.info(
            "Indicators to send",
            meta={
                "checkpoint": checkpoint.isoformat() if checkpoint else None,
                "to_send": len(indicators),
                "in_feed": len(feed.indicators),
            },
        )
        if not indicators:
            return

        tools = self._convert_tools(feed.tools)
        relationships_by_indicator: dict[str, list[FeedRelationship]] = defaultdict(
            list
        )
        for relationship in feed.relationships:
            if relationship.relationship_type == RelationshipType.INDICATES:
                relationships_by_indicator[relationship.source_ref].append(relationship)

        for batch in batched(indicators, INDICATORS_PER_BUNDLE):
            stix_objects: list[BaseIdentifiedObject] = []
            newest: datetime | None = None
            for feed_indicator in batch:
                try:
                    stix_objects.extend(
                        self._convert_indicator(
                            feed_indicator,
                            relationships_by_indicator[feed_indicator.id],
                            tools,
                        )
                    )
                except DataError as err:
                    self.logger.warning(
                        "Failed to convert indicator, skipping it",
                        meta={
                            "indicator_id": feed_indicator.id,
                            "code": err.code,
                            "error": str(err),
                        },
                    )
                    continue
                newest = feed_indicator.modified

            if not stix_objects:
                continue

            yield [self.author, self.tlp_marking, *tools.values(), *stix_objects]

            # The bundle is sent: move the checkpoint, never backwards.
            if newest and (
                self.state.last_modified is None or newest > self.state.last_modified
            ):
                self.state.last_modified = newest

    def _convert_tools(self, feed_tools: list[FeedTool]) -> dict[str, Tool]:
        """Convert the feed tools, keyed by their feed ID.

        A tool that fails to convert is logged and skipped: the relationships
        pointing to it are then skipped too.
        """
        tools: dict[str, Tool] = {}
        for feed_tool in feed_tools:
            try:
                tools[feed_tool.id] = Tool(
                    name=feed_tool.name,
                    description=feed_tool.description,
                    tool_types=feed_tool.tool_types or None,
                    external_references=self._external_references(
                        feed_tool.external_references
                    ),
                    created=feed_tool.created,
                    author=self.author,
                    markings=[self.tlp_marking],
                )
            except (
                Exception
            ) as err:  # noqa: BLE001 # one bad tool must not stop the run
                self.logger.warning(
                    "Failed to convert tool, skipping it",
                    meta={"tool_id": feed_tool.id, "error": str(err)},
                )
        return tools

    def _convert_indicator(
        self,
        feed_indicator: FeedIndicator,
        feed_relationships: list[FeedRelationship],
        tools: dict[str, Tool],
    ) -> list[BaseIdentifiedObject]:
        """Convert one feed indicator with its observable and relationships.

        Raises:
            DataConversionError: If the indicator cannot be converted.
        """
        match = IPV4_PATTERN.fullmatch(feed_indicator.pattern.strip())
        if not match:
            raise DataConversionError(
                f"Unsupported pattern: {feed_indicator.pattern!r}"
            )
        ip_address = match.group(1)
        try:
            ipaddress.IPv4Address(ip_address)
        except ValueError as err:
            raise DataConversionError(f"Invalid IPv4 address: {ip_address!r}") from err
        labels = feed_indicator.labels or None
        external_references = self._external_references(
            feed_indicator.external_references
        )

        try:
            indicator = Indicator(
                # The feed name only cites one agent, while an IP can run
                # several: use the IP, the agents are in labels and relationships.
                name=ip_address,
                pattern=f"[ipv4-addr:value = '{ip_address}']",
                pattern_type="stix",
                main_observable_type="IPv4-Addr",
                description=feed_indicator.description,
                indicator_types=feed_indicator.indicator_types or None,
                labels=labels,
                valid_from=feed_indicator.valid_from or feed_indicator.created,
                # `modified` is the last day the feed saw the agent on this IP.
                valid_until=feed_indicator.modified
                + self.settings.offensive_agency.indicator_validity,
                created=feed_indicator.created,
                external_references=external_references,
                # The connector creates the observables itself (or not, by setting).
                create_observables=False,
                author=self.author,
                markings=[self.tlp_marking],
            )
            stix_objects: list[BaseIdentifiedObject] = [indicator]

            if self.settings.offensive_agency.create_observables:
                observable = IPV4Address(
                    value=ip_address,
                    description=feed_indicator.description,
                    labels=labels,
                    external_references=external_references,
                    author=self.author,
                    markings=[self.tlp_marking],
                )
                stix_objects += [
                    observable,
                    Relationship(
                        type=RelationshipType.BASED_ON,
                        source=indicator,
                        target=observable,
                        created=feed_indicator.created,
                        author=self.author,
                        markings=[self.tlp_marking],
                    ),
                ]

            for feed_relationship in feed_relationships:
                tool = tools.get(feed_relationship.target_ref)
                if tool is None:
                    self.logger.warning(
                        "Relationship to an unknown tool, skipping it",
                        meta={
                            "relationship_id": feed_relationship.id,
                            "target_ref": feed_relationship.target_ref,
                        },
                    )
                    continue
                stix_objects.append(
                    Relationship(
                        type=RelationshipType.INDICATES,
                        source=indicator,
                        target=tool,
                        created=feed_relationship.created,
                        author=self.author,
                        markings=[self.tlp_marking],
                    )
                )
        # pydantic and stix2 raise different error types (stix2 errors are not
        # ValueError): catch them all, the item is skipped by the caller.
        except Exception as err:  # noqa: BLE001
            raise DataConversionError(
                f"Invalid indicator {feed_indicator.id}: {err}"
            ) from err
        return stix_objects

    @staticmethod
    def _external_references(
        feed_references: list[FeedExternalReference],
    ) -> list[ExternalReference] | None:
        """Convert the feed external references (None when there are none).

        A reference with only a `source_name` is dropped: STIX requires at least
        one of `url`, `description` or `external_id`.
        """
        return [
            ExternalReference(
                source_name=reference.source_name,
                url=reference.url,
                description=reference.description,
                external_id=reference.external_id,
            )
            for reference in feed_references
            if reference.url or reference.description or reference.external_id
        ] or None
