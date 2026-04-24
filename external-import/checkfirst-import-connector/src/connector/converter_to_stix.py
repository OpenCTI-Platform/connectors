"""STIX conversion helpers for the Checkfirst connector.

Converts API rows into STIX 2.1 objects using:
- `OrganizationAuthor` / `TLPMarking` from `connectors_sdk.models`
- `pycti.*.generate_id()` for deterministic IDs on OpenCTI custom entities
"""

import re
from datetime import datetime, timezone
from functools import lru_cache
from typing import Literal
from urllib.parse import urlparse

from checkfirst_client.api_models import AlternateURL, Article
from connector.pravda_network import PRAVDA_DOMAINS, PRAVDA_IP, SUBDOMAIN_TO_DOMAIN
from connectors_sdk.models import (
    URL,
    BaseIdentifiedEntity,
    Campaign,
    Channel,
    DomainName,
    ExternalReference,
    Infrastructure,
    IntrusionSet,
    IPV4Address,
    MediaContent,
    OrganizationAuthor,
    Relationship,
    TLPMarking,
)
from pycti import OpenCTIConnectorHelper


class ConversionError(Exception):
    """Raised when conversion of API data to OpenCTI objects fails."""


_URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)


def parse_alternates(alternates_urls: list[AlternateURL]) -> list[str]:
    """Extract a list of unique alternate URLs from a raw column value."""
    parsed_urls: list[str] = []
    for alternate_url in alternates_urls:
        url = alternate_url.url.strip() if alternate_url.url else ""

        if _URL_RE.search(url):
            parsed_urls.append(url)

    # preserve order but remove duplicates
    seen: set[str] = set()
    out: list[str] = []
    for url in parsed_urls:
        if url in seen:
            continue
        seen.add(url)
        out.append(url)

    return out


class ConverterToStix:
    """Convert API rows into OpenCTI objects (convertible to STIX 2.1 format)."""

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        tlp_level: Literal[
            "clear",
            "white",
            "green",
            "amber",
            "amber+strict",
            "red",
        ] = "clear",
    ):
        self.helper = helper

        self.author = OrganizationAuthor(name="CheckFirst")
        self.tlp_marking = TLPMarking(level=tlp_level.lower())
        self.intrusion_set = self._create_intrusion_set()

        self.required_objects = [
            self.author,
            self.tlp_marking,
            self.intrusion_set,
        ]

    def _create_intrusion_set(self) -> IntrusionSet:
        return IntrusionSet(
            name="Pravda Network",
            description=(
                "Information Manipulation Set (IMS) conducting pro-Russian "
                "influence operations through a network of 190+ websites"
            ),
            aliases=["Portal-Kombat", "Pravda Network IMS"],
            first_seen=datetime(2023, 6, 24, 0, 0, 0, tzinfo=timezone.utc),
            goals=[
                "Undermine Western unity",
                "Promote Russian narratives",
                "Influence public opinion",
            ],
            resource_level="government",
            primary_motivation="ideology",
            author=self.author,
            markings=[self.tlp_marking],
        )

    def _create_campaign(self, year: int) -> Campaign:
        name = f"Pravda Network Campaigns {year}"
        first_seen = (
            "2023-09-01T00:00:00Z" if year == 2023 else f"{year}-01-01T00:00:00Z"
        )
        return Campaign(
            name=name,
            description=(
                "Coordinated FIMI campaign spreading pro-Russian narratives "
                "across multiple countries and languages"
            ),
            aliases=[f"Portal-Kombat Campaign {year}", f"Pravda {year}"],
            first_seen=first_seen,
            objective=(
                "Manipulate public opinion, undermine trust in Western "
                "institutions, justify Russian actions"
            ),
            author=self.author,
            markings=[self.tlp_marking],
        )

    def create_channel(self, name: str, source_url: str | None = None) -> Channel:
        external_refs: list[ExternalReference] = []
        if source_url:
            external_refs.append(
                ExternalReference(source_name="source", url=source_url)
            )

        is_telegram = source_url is not None and source_url.startswith("https://t.me/")
        channel = Channel(
            name=name,
            channel_types=["channel"] if is_telegram else ["website"],
            author=self.author,
            markings=[self.tlp_marking],
            external_references=external_refs,
        )
        return channel

    def create_media_content(
        self,
        title: str | None,
        description: str | None,
        url: str,
        publication_date: datetime,
    ) -> MediaContent:
        media = MediaContent(
            title=title,
            description=description,
            url=url,
            publication_date=publication_date,
            author=self.author,
            markings=[self.tlp_marking],
        )
        return media

    @lru_cache  # same domain name shared by many articles
    def create_domain_name(self, value: str) -> DomainName:
        return DomainName(
            value=value,
            author=self.author,
            markings=[self.tlp_marking],
        )

    def create_ipv4_address(self, value: str) -> IPV4Address:
        return IPV4Address(
            value=value,
            author=self.author,
            markings=[self.tlp_marking],
        )

    def create_infrastructure(
        self, name: str, first_seen: datetime | str | None = None
    ) -> Infrastructure:
        return Infrastructure(
            name=name,
            infrastructure_types=["hosting-infrastructure"],
            first_seen=first_seen,
            author=self.author,
            markings=[self.tlp_marking],
        )

    def create_url(self, value: str) -> URL:
        return URL(
            value=value,
            author=self.author,
            markings=[self.tlp_marking],
        )

    def create_relationship(
        self,
        source: BaseIdentifiedEntity,
        relationship_type: str,
        target: BaseIdentifiedEntity,
        start_time: datetime | None = None,
        stop_time: datetime | None = None,
    ) -> Relationship:
        rel = Relationship(
            type=relationship_type,
            source=source,
            target=target,
            author=self.author,
            markings=[self.tlp_marking],
            start_time=start_time,
            stop_time=stop_time,
        )
        return rel

    @lru_cache  # cache campaigns by year to reuse across articles from the same year
    def get_campaign_for_year(self, year: int) -> tuple[Campaign, Relationship]:
        """Return (Campaign, attributed-to Relationship) for the given year, cached."""
        campaign = self._create_campaign(year=year)
        attributed_to = self.create_relationship(
            source=campaign,
            relationship_type="attributed-to",
            target=self.intrusion_set,
        )

        return campaign, attributed_to

    def convert_pravda_network_infrastructure(
        self, campaign: Campaign
    ) -> list[BaseIdentifiedEntity]:
        """Create a list of OpenCTI objects based on known Pravda network infrastructure.
        Relationships per domain:
        - Campaign 2023 → attributed-to → IntrusionSet
        - Campaign 2023 → uses [first_observed] → Infrastructure
        - Infrastructure → consists-of → DomainName
        - Infrastructure → consists-of → IPv4Address (with stop_time)
        - Subdomain [first_observed] → related-to → Infrastructure

        Call this method only when starting from page 1 (first run or force_reprocess)
        to create the base infrastructure objects and relationships, then rely on get_campaign_for_year()
        for subsequent pages/years to reuse the same Campaign and IntrusionSet objects.
        """
        try:
            octi_objects = []

            ipv4 = self.create_ipv4_address(value=PRAVDA_IP["IP"])
            octi_objects.append(ipv4)

            for entry in PRAVDA_DOMAINS:
                first_observed = entry["first_observed"]

                infrastructure = self.create_infrastructure(
                    name=entry["domain"],
                    first_seen=first_observed,
                )
                octi_objects.append(infrastructure)

                domain_name = self.create_domain_name(value=entry["domain"])
                octi_objects.append(domain_name)

                # Campaign → uses → Infrastructure
                octi_objects.append(
                    self.create_relationship(
                        source=campaign,
                        relationship_type="uses",
                        target=infrastructure,
                        start_time=first_observed,
                    )
                )
                # Infrastructure → consists-of → DomainName
                octi_objects.append(
                    self.create_relationship(
                        source=infrastructure,
                        relationship_type="consists-of",
                        target=domain_name,
                        start_time=first_observed,
                    )
                )
                # Infrastructure → consists-of → IPv4Address (with temporal bounds)
                octi_objects.append(
                    self.create_relationship(
                        source=infrastructure,
                        relationship_type="consists-of",
                        target=ipv4,
                        start_time=first_observed,
                        stop_time=PRAVDA_IP["last_seen"],
                    )
                )
                # Subdomains → related-to → Infrastructure
                for subdomain in entry.get("subdomains", []):
                    sub_domain_name = self.create_domain_name(value=subdomain)
                    octi_objects.append(sub_domain_name)
                    octi_objects.append(
                        self.create_relationship(
                            source=sub_domain_name,
                            relationship_type="related-to",
                            target=infrastructure,
                            start_time=first_observed,
                        )
                    )

            # To limit duplicates, do not return shared entities such as Author, IntrusionSet or Campaign
            return octi_objects
        except Exception as err:
            raise ConversionError(
                f"Error converting Pravda network infrastructure: {err}"
            ) from err

    def convert_article(
        self, article: Article, campaign: Campaign
    ) -> list[BaseIdentifiedEntity]:
        """Convert a Article representing an article into a list of OpenCTI objects."""

        try:
            octi_objects = []

            # --- Domain observable (extracted from article URL) ---
            article_domain = urlparse(article.url).netloc
            domain_name = self.create_domain_name(value=article_domain)
            # --- Infrastructure wrapping the publishing domain ---
            # No first_seen: the connector deduplicates objects via a set (connector.py)
            # using model_dump_json() as hash. Passing article.published_date as first_seen
            # would produce different JSON per article for the same domain, bypassing
            # set dedup and flooding OpenCTI with near-duplicate updates.
            # Known domains already have correct first_seen from the infrastructure bundle.
            infrastructure = self.create_infrastructure(
                name=article_domain,
                first_seen=article.published_date,
            )
            # --- Channel as website (the publishing domain/subdomain) ---
            channel = self.create_channel(
                name=article_domain,
                source_url=article.url,
            )
            # --- Source as Channel (Telegram or website origin) ---
            source_channel = self.create_channel(
                name=article.source_title,
                source_url=article.source_url,
            )
            # --- Content (article) ---
            content = self.create_media_content(
                title=article.title,
                description=article.og_description,
                url=article.url,
                publication_date=article.published_date,
            )

            # --- Relationships ---
            # No start_time/stop_time on relationships shared across articles.
            # Using article.published_date would produce a unique STIX ID per article,
            # flooding OpenCTI's Redis stream with thousands of create/upsert events.
            # Campaign → uses → Infrastructure
            campaign_uses_infra = self.create_relationship(
                source=campaign,
                relationship_type="uses",
                target=infrastructure,
            )
            # Campaign → uses → Channel as website
            campaign_uses_channel = self.create_relationship(
                source=campaign,
                relationship_type="uses",
                target=channel,
            )
            # Infrastructure → consists-of → DomainName
            infra_consists_of_domain = self.create_relationship(
                source=infrastructure,
                relationship_type="consists-of",
                target=domain_name,
            )
            # Channel as website → related-to → Infrastructure
            channel_related_to_infra = self.create_relationship(
                source=channel,
                relationship_type="related-to",
                target=infrastructure,
            )
            # DomainName → related-to → Channel as website
            domain_related_to_channel = self.create_relationship(
                source=domain_name,
                relationship_type="related-to",
                target=channel,
            )
            # Channel as website → publishes → Content
            publishes = self.create_relationship(
                source=channel,
                relationship_type="publishes",
                target=content,
            )
            # Channel as website → related-to → Source as Channel
            channel_uses_source = self.create_relationship(
                source=channel,
                relationship_type="related-to",
                target=source_channel,
            )
            # Content → related-to → Source as Channel
            content_related_to_source = self.create_relationship(
                source=content,
                relationship_type="related-to",
                target=source_channel,
            )

            octi_objects.extend(
                [
                    domain_name,
                    infrastructure,
                    channel,
                    source_channel,
                    content,
                    campaign_uses_infra,
                    campaign_uses_channel,
                    infra_consists_of_domain,
                    channel_related_to_infra,
                    domain_related_to_channel,
                    publishes,
                    channel_uses_source,
                    content_related_to_source,
                ]
            )

            # If the article domain is a known news-pravda.com subdomain,
            # link the Channel as website to its parent pravda-XX.com domain.
            parent_domain_str = SUBDOMAIN_TO_DOMAIN.get(article_domain)
            if parent_domain_str:
                parent_domain_name = self.create_domain_name(value=parent_domain_str)
                octi_objects.append(parent_domain_name)
                octi_objects.append(
                    self.create_relationship(
                        source=channel,
                        relationship_type="related-to",
                        target=parent_domain_name,
                    )
                )

            # Content → related-to → alternate URLs
            for alt in parse_alternates(article.alternates_urls):
                alt_url = self.create_url(value=alt)
                alt_rel = self.create_relationship(
                    source=content,
                    relationship_type="related-to",
                    target=alt_url,
                )
                octi_objects.extend([alt_url, alt_rel])

            # To limit duplicates, do not return shared entities such as Author, IntrusionSet or Campaign
            return octi_objects
        except Exception as err:
            raise ConversionError(
                f"Error converting article to OpenCTI objects: {err}"
            ) from err
