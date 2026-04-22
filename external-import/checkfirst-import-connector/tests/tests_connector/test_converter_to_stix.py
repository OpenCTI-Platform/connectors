"""Tests for ConverterToStix — validates that structural relationships
produce stable STIX IDs across articles and that Infrastructure objects are cached."""

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from checkfirst_client.api_models import Article
from connector.converter_to_stix import ConverterToStix


@pytest.fixture
def converter():
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    return ConverterToStix(helper=helper, tlp_level="clear")


def _make_article(
    url: str = "https://france.news-pravda.com/article-1",
    source_title: str = "Telegram Source",
    source_url: str = "https://t.me/source",
    published_date: datetime | None = None,
    row_number: int = 1,
    article_id: str = "abc123",
) -> Article:
    return Article(
        _id=article_id,
        row_number=row_number,
        url=url,
        source_title=source_title,
        source_url=source_url,
        published_date=published_date or datetime(2025, 3, 15, tzinfo=timezone.utc),
        title="Test Article",
    )


class TestStructuralRelationshipsAreStable:
    """Structural relationships (Campaign→Channel, Channel→Infra, etc.) should produce
    the same STIX ID regardless of which article triggers them, because they must NOT
    include article-specific start_time in their ID hash."""

    def test_campaign_uses_channel_same_stix_id_across_articles(self, converter):
        """Two articles from the same domain should produce identical
        Campaign→uses→Channel relationships."""
        campaign, _ = converter.get_campaign_for_year(2025)

        article_1 = _make_article(
            published_date=datetime(2025, 1, 10, tzinfo=timezone.utc),
            article_id="a1",
        )
        article_2 = _make_article(
            published_date=datetime(2025, 6, 20, tzinfo=timezone.utc),
            article_id="a2",
        )

        objects_1 = converter.convert_article(article_1, campaign)
        objects_2 = converter.convert_article(article_2, campaign)

        # Find campaign→uses→channel relationships
        rels_1 = [
            o
            for o in objects_1
            if hasattr(o, "type")
            and o.type == "uses"
            and o.source.id == campaign.id
            and o.target.id.startswith("channel--")
        ]
        rels_2 = [
            o
            for o in objects_2
            if hasattr(o, "type")
            and o.type == "uses"
            and o.source.id == campaign.id
            and o.target.id.startswith("channel--")
        ]

        assert len(rels_1) == 1
        assert len(rels_2) == 1
        assert (
            rels_1[0].id == rels_2[0].id
        ), "Campaign→uses→Channel should have identical STIX IDs across articles"

    def test_structural_relationships_have_no_start_time(self, converter):
        """Structural relationships should not carry article-specific start_time."""
        campaign, _ = converter.get_campaign_for_year(2025)
        article = _make_article()

        objects = converter.convert_article(article, campaign)

        for obj in objects:
            if not hasattr(obj, "type") or not hasattr(obj, "source"):
                continue

            is_campaign_source = obj.source.id.startswith("campaign--")
            is_content_involved = obj.source.id.startswith(
                "media-content--"
            ) or obj.target.id.startswith("media-content--")

            # Per-article relationships (involving MediaContent) may have start_time
            if is_content_involved:
                continue

            # Structural relationships should NOT have start_time
            if is_campaign_source or obj.type in ("consists-of",):
                assert obj.start_time is None, (
                    f"Structural relationship {obj.type} from {obj.source.id[:20]}... "
                    f"should not have start_time, got {obj.start_time}"
                )


class TestInfrastructureCaching:
    """Infrastructure objects should be cached by name to ensure identical
    Python objects across articles from the same domain."""

    def test_same_domain_returns_same_infrastructure_object(self, converter):
        """create_infrastructure() with same name should return the same cached object."""
        infra_1 = converter.create_infrastructure(name="example.com")
        infra_2 = converter.create_infrastructure(name="example.com")

        assert (
            infra_1 is infra_2
        ), "create_infrastructure should return cached instance for same domain"

    def test_article_infrastructure_has_no_first_seen(self, converter):
        """Infrastructure created in the article path should not have first_seen."""
        campaign, _ = converter.get_campaign_for_year(2025)
        article = _make_article()

        objects = converter.convert_article(article, campaign)

        infra_objects = [o for o in objects if o.id.startswith("infrastructure--")]
        assert len(infra_objects) == 1
        assert infra_objects[0].first_seen is None

    def test_infrastructure_bundle_preserves_first_seen(self, converter):
        """Infrastructure created by the pravda bundle should keep its first_seen."""
        campaign, _ = converter.get_campaign_for_year(2023)
        objects = converter.convert_pravda_network_infrastructure(campaign)

        infra_objects = [o for o in objects if o.id.startswith("infrastructure--")]
        assert len(infra_objects) > 0
        for infra in infra_objects:
            assert (
                infra.first_seen is not None
            ), f"Pravda infrastructure {infra.name} should have first_seen"


class TestDeduplicationEfficiency:
    """The connector's set-based deduplication should work correctly after the fix.
    Objects that are structurally identical across articles should deduplicate in a set.
    """

    def test_structural_objects_deduplicate_in_set(self, converter):
        """Two articles from the same domain should produce mostly identical structural
        objects that deduplicate when added to a set."""
        campaign, attributed_to = converter.get_campaign_for_year(2025)

        article_1 = _make_article(
            url="https://france.news-pravda.com/article-1",
            published_date=datetime(2025, 1, 10, tzinfo=timezone.utc),
            article_id="a1",
        )
        article_2 = _make_article(
            url="https://france.news-pravda.com/article-2",
            published_date=datetime(2025, 6, 20, tzinfo=timezone.utc),
            article_id="a2",
        )

        objects_1 = converter.convert_article(article_1, campaign)
        objects_2 = converter.convert_article(article_2, campaign)

        # Simulate the connector's dedup
        octi_set: set = set()
        for obj in [campaign, attributed_to] + objects_1:
            octi_set.add(obj)
        for obj in [campaign, attributed_to] + objects_2:
            octi_set.add(obj)

        # The set should be significantly smaller than the raw sum
        raw_count = (
            len(objects_1) + len(objects_2) + 4
        )  # +4 for campaign+attributed_to twice
        assert len(octi_set) < raw_count, (
            f"Set ({len(octi_set)}) should be smaller than raw count ({raw_count}) "
            "due to deduplication of structural objects"
        )

    def test_per_article_objects_remain_unique(self, converter):
        """MediaContent and its relationships should remain unique per article."""
        campaign, _ = converter.get_campaign_for_year(2025)

        article_1 = _make_article(
            url="https://france.news-pravda.com/article-1",
            published_date=datetime(2025, 1, 10, tzinfo=timezone.utc),
            article_id="a1",
        )
        article_2 = _make_article(
            url="https://france.news-pravda.com/article-2",
            published_date=datetime(2025, 6, 20, tzinfo=timezone.utc),
            article_id="a2",
        )

        objects_1 = converter.convert_article(article_1, campaign)
        objects_2 = converter.convert_article(article_2, campaign)

        content_1 = [o for o in objects_1 if o.id.startswith("media-content--")]
        content_2 = [o for o in objects_2 if o.id.startswith("media-content--")]

        assert len(content_1) == 1
        assert len(content_2) == 1
        assert (
            content_1[0].id != content_2[0].id
        ), "Different articles should produce different MediaContent STIX IDs"
