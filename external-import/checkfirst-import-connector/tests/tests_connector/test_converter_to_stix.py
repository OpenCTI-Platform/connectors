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


class TestConverterCache:
    """DomainName, Infrastructure and Campaign should be cached for performance issues
    (many objects are shared across different articles)."""

    def test_same_domain_returns_same_domain_name_object(self, converter):
        """create_domain_name() with same value should return the same cached object."""
        domain_1 = converter.create_domain_name(value="example.com")
        domain_2 = converter.create_domain_name(value="example.com")

        assert (
            domain_1 is domain_2
        ), "create_domain_name should return cached instance for same domain"

    def test_same_year_returns_same_campaign_object(self, converter):
        """get_campaign_for_year() with same year should return the same cached object."""
        campaign_1, _ = converter.get_campaign_for_year(2025)
        campaign_2, _ = converter.get_campaign_for_year(2025)

        assert (
            campaign_1 is campaign_2
        ), "get_campaign_for_year should return cached instance for same year"


class TestPravdaInfrastructure:
    """Test Infrastructure objects created for the Pravda bundle (created on connector's first run)."""

    def test_infrastructure_bundle_contains_first_seen(self, converter):
        """Infrastructure objects created for the Pravda bundle should contain first_seen attribute."""
        campaign, _ = converter.get_campaign_for_year(2023)
        objects = converter.convert_pravda_network_infrastructure(campaign)

        infra_objects = [o for o in objects if o.id.startswith("infrastructure--")]
        assert len(infra_objects) > 0
        for infra in infra_objects:
            assert (
                infra.first_seen is not None
            ), f"Pravda infrastructure {infra.name} should have first_seen"


class TestArticleConversion:
    """Articles conversion should produce a structural subset of STIX objects that is identical for same-domain articles,
    while allowing per-article objects (MediaContent and its relationships) to differ.
    """

    def test_article_shared_objects_are_identical(self, converter):
        """Two same-domain articles should have an identical structural subset."""
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

        all_ids_1 = {obj.id for obj in [campaign, attributed_to] + objects_1}
        all_ids_2 = {obj.id for obj in [campaign, attributed_to] + objects_2}

        def _is_per_article_object(obj) -> bool:
            # Only MediaContent and its relationships should be considered per-article objects.
            if obj.id.startswith("media-content--"):
                return True
            if obj.id.startswith("relationship--") and (
                obj.source.id.startswith("media-content--")
                or obj.target.id.startswith("media-content--")
            ):
                return True

            return False

        per_article_ids_1 = {
            obj.id
            for obj in [campaign, attributed_to] + objects_1
            if _is_per_article_object(obj)
        }
        per_article_ids_2 = {
            obj.id
            for obj in [campaign, attributed_to] + objects_2
            if _is_per_article_object(obj)
        }

        structural_ids_1 = all_ids_1 - per_article_ids_1
        structural_ids_2 = all_ids_2 - per_article_ids_2

        # Structural subset should be identical for same-domain articles.
        assert len(structural_ids_1) > 0
        assert structural_ids_1 == structural_ids_2

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

    def test_structural_relationships_have_no_start_time(self, converter):
        """Structural relationships should not carry article-specific start_time."""
        campaign, _ = converter.get_campaign_for_year(2025)
        article = _make_article()

        objects = converter.convert_article(article, campaign)

        for obj in objects:
            if not obj.id.startswith("relationship--"):
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
