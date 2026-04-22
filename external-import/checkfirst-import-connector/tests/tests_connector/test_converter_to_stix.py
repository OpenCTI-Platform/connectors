"""Unit tests for import_* filter flags in ConverterToStix.convert_article."""

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from checkfirst_client.api_models import Article
from connector.converter_to_stix import ConverterToStix
from connectors_sdk.models import (
    Channel,
    DomainName,
    Infrastructure,
    MediaContent,
    Relationship,
)

ARTICLE_PUBLISHED_DATE = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def fake_article(url: str = "https://test.com/some-article") -> Article:
    return Article(
        **{
            "_id": "article-id-1",
            "row_number": 1,
            "url": url,
            "source_title": "Telegram Source",
            "source_url": "https://t.me/some_channel",
            "published_date": ARTICLE_PUBLISHED_DATE,
        }
    )


@pytest.fixture
def mock_opencti_connector_helper() -> MagicMock:
    return MagicMock()


def _has_type(objects, cls) -> bool:
    return any(isinstance(o, cls) for o in objects)


class TestAllFlags:
    def test_all_enabled_returns_all_entity_types(self, mock_opencti_connector_helper):
        converter = ConverterToStix(
            helper=mock_opencti_connector_helper,
            tlp_level="clear",
        )
        article = fake_article()
        campaign, _ = converter.get_campaign_for_year(ARTICLE_PUBLISHED_DATE.year)

        result = converter.convert_article(article=article, campaign=campaign)

        assert _has_type(result, DomainName)
        assert _has_type(result, Infrastructure)
        assert _has_type(result, Channel)
        assert _has_type(result, MediaContent)

    def test_all_disabled_returns_empty_list(self, mock_opencti_connector_helper):
        converter = ConverterToStix(
            helper=mock_opencti_connector_helper,
            tlp_level="clear",
            import_domain_name=False,
            import_infrastructure=False,
            import_channel=False,
            import_source_channel=False,
            import_media_content=False,
        )
        article = fake_article()
        campaign, _ = converter.get_campaign_for_year(ARTICLE_PUBLISHED_DATE.year)

        result = converter.convert_article(article=article, campaign=campaign)

        assert result == []


class TestImportDomainName:
    def test_disabled_excludes_domain_name(self, mock_opencti_connector_helper):
        converter = ConverterToStix(
            helper=mock_opencti_connector_helper,
            tlp_level="clear",
            import_domain_name=False,
        )
        article = fake_article()
        campaign, _ = converter.get_campaign_for_year(ARTICLE_PUBLISHED_DATE.year)

        result = converter.convert_article(article=article, campaign=campaign)

        assert not _has_type(result, DomainName)

    def test_disabled_keeps_other_entities(self, mock_opencti_connector_helper):
        converter = ConverterToStix(
            helper=mock_opencti_connector_helper,
            tlp_level="clear",
            import_domain_name=False,
        )
        article = fake_article()
        campaign, _ = converter.get_campaign_for_year(ARTICLE_PUBLISHED_DATE.year)

        result = converter.convert_article(article=article, campaign=campaign)

        assert _has_type(result, Infrastructure)
        assert _has_type(result, Channel)
        assert _has_type(result, MediaContent)

    def test_disabled_removes_consists_of_relationship(
        self, mock_opencti_connector_helper
    ):
        article = fake_article()

        converter = ConverterToStix(
            helper=mock_opencti_connector_helper,
            tlp_level="clear",
            import_domain_name=False,
            import_infrastructure=True,
        )
        campaign, _ = converter.get_campaign_for_year(ARTICLE_PUBLISHED_DATE.year)
        result = converter.convert_article(article=article, campaign=campaign)

        consists_of_relationships = [
            o for o in result if isinstance(o, Relationship) and o.type == "consists-of"
        ]

        assert len(consists_of_relationships) == 0

    def test_disabled_parent_structural_domain_still_created(
        self,
        mock_opencti_connector_helper,
    ):
        """The parent pravda-XX.com DomainName is always created for Channel topology,
        even when import_domain_name=False (which only suppresses article-derived domains).
        """
        converter = ConverterToStix(
            helper=mock_opencti_connector_helper,
            tlp_level="clear",
            import_domain_name=False,
        )
        # deutsch.news-pravda.com maps to pravda-de.com in SUBDOMAIN_TO_DOMAIN
        article = fake_article(url="https://deutsch.news-pravda.com/some-article")
        campaign, _ = converter.get_campaign_for_year(ARTICLE_PUBLISHED_DATE.year)

        result = converter.convert_article(article=article, campaign=campaign)

        domain_values = {o.value for o in result if isinstance(o, DomainName)}
        assert "deutsch.news-pravda.com" not in domain_values
        assert "pravda-de.com" in domain_values

    def test_enabled_parent_domain_created(self, mock_opencti_connector_helper):
        converter = ConverterToStix(
            helper=mock_opencti_connector_helper,
            tlp_level="clear",
            import_domain_name=True,
        )
        article = fake_article(url="https://deutsch.news-pravda.com/some-article")
        campaign, _ = converter.get_campaign_for_year(ARTICLE_PUBLISHED_DATE.year)

        result = converter.convert_article(article=article, campaign=campaign)

        domain_values = {o.value for o in result if isinstance(o, DomainName)}
        assert "pravda-de.com" in domain_values


class TestImportInfrastructure:
    def test_disabled_excludes_infrastructure(self, mock_opencti_connector_helper):
        converter = ConverterToStix(
            helper=mock_opencti_connector_helper,
            tlp_level="clear",
            import_infrastructure=False,
        )
        article = fake_article()
        campaign, _ = converter.get_campaign_for_year(ARTICLE_PUBLISHED_DATE.year)

        result = converter.convert_article(article=article, campaign=campaign)

        assert not _has_type(result, Infrastructure)

    def test_disabled_keeps_other_entities(self, mock_opencti_connector_helper):
        converter = ConverterToStix(
            helper=mock_opencti_connector_helper,
            tlp_level="clear",
            import_infrastructure=False,
        )
        article = fake_article()
        campaign, _ = converter.get_campaign_for_year(ARTICLE_PUBLISHED_DATE.year)

        result = converter.convert_article(article=article, campaign=campaign)

        assert _has_type(result, DomainName)
        assert _has_type(result, Channel)
        assert _has_type(result, MediaContent)


class TestImportChannel:
    def test_disabled_excludes_website_channel(self, mock_opencti_connector_helper):
        converter = ConverterToStix(
            helper=mock_opencti_connector_helper,
            tlp_level="clear",
            import_channel=False,
        )
        article = fake_article()
        campaign, _ = converter.get_campaign_for_year(ARTICLE_PUBLISHED_DATE.year)

        result = converter.convert_article(article=article, campaign=campaign)

        # Only the Telegram source_channel should remain
        channels = [o for o in result if isinstance(o, Channel)]
        assert all(o.channel_types == ["channel"] for o in channels)

    def test_disabled_keeps_other_entities(self, mock_opencti_connector_helper):
        converter = ConverterToStix(
            helper=mock_opencti_connector_helper,
            tlp_level="clear",
            import_channel=False,
        )
        article = fake_article()
        campaign, _ = converter.get_campaign_for_year(ARTICLE_PUBLISHED_DATE.year)

        result = converter.convert_article(article=article, campaign=campaign)

        assert _has_type(result, DomainName)
        assert _has_type(result, Infrastructure)
        assert _has_type(result, MediaContent)


class TestImportSourceChannel:
    def test_disabled_only_website_channel_remains(self, mock_opencti_connector_helper):
        converter = ConverterToStix(
            helper=mock_opencti_connector_helper,
            tlp_level="clear",
            import_source_channel=False,
        )
        article = fake_article()
        campaign, _ = converter.get_campaign_for_year(ARTICLE_PUBLISHED_DATE.year)

        result = converter.convert_article(article=article, campaign=campaign)

        channels = [o for o in result if isinstance(o, Channel)]
        assert all(o.channel_types == ["website"] for o in channels)


class TestImportMediaContent:
    def test_disabled_excludes_media_content(self, mock_opencti_connector_helper):
        converter = ConverterToStix(
            helper=mock_opencti_connector_helper,
            tlp_level="clear",
            import_media_content=False,
        )
        article = fake_article()
        campaign, _ = converter.get_campaign_for_year(ARTICLE_PUBLISHED_DATE.year)

        result = converter.convert_article(article=article, campaign=campaign)

        assert not _has_type(result, MediaContent)

    def test_disabled_keeps_other_entities(self, mock_opencti_connector_helper):
        converter = ConverterToStix(
            helper=mock_opencti_connector_helper,
            tlp_level="clear",
            import_media_content=False,
        )
        article = fake_article()
        campaign, _ = converter.get_campaign_for_year(ARTICLE_PUBLISHED_DATE.year)

        result = converter.convert_article(article=article, campaign=campaign)

        assert _has_type(result, DomainName)
        assert _has_type(result, Infrastructure)
        assert _has_type(result, Channel)
