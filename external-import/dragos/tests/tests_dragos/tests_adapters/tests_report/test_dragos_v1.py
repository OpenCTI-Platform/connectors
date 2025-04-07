from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, Mock, patch

import pytest
from client_api.v1 import DragosClientAPIV1
from client_api.v1.indicator import IndicatorResponse
from client_api.v1.product import ProductResponse, TagResponse
from dragos.adapters.report.dragos_v1 import (
    ReportsAPIV1,
    ReportAPIV1,
    IndicatorAPIV1,
    TagAPIV1,
    ExtendedProductResponse,
)
from yarl import URL


def fake_tag_response():
    """Return a fake TagResponse."""

    return TagResponse.model_validate(
        {
            "text": "my_text",
            "tag_type": "my_type",
        }
    )


def fake_product_response():
    """Return a fake ProductResponse."""

    return ProductResponse.model_validate(
        {
            "serial": "12345",
            "tlp_level": "amber",
            "title": "my_title",
            "executive_summary": "my_summary",
            "type": "report",
            "updated_at": "2023-10-01T00:00:00Z",
            "threat_level": 3,
            "ioc_count": 10,
            "release_date": "2023-10-01T00:00:00Z",
            "tags": [fake_tag_response()],
            "report_link": "http://example.com/report",
            "ioc_csv_link": "http://example.com/ioc.csv",
            "ioc_stix2_link": "http://example.com/ioc.stix2",
            "slides_link": "http://example.com/slides",
        }
    )


def fake_indicator_response():
    """Return a fake IndicatorResponse."""

    return IndicatorResponse.model_validate(
        {
            "id": 1,
            "value": "indicator_value",
            "indicator_type": "sha256",
            "category": "category",
            "comment": "comment",
            "first_seen": "2023-10-01T00:00:00Z",
            "last_seen": "2023-10-01T00:00:00Z",
            "updated_at": "2023-10-01T00:00:00Z",
            "confidence": "high",
            "kill_chain": "kill_chain",
            "uuid": "uuid",
            "status": "released",
            "severity": "severity",
            "attack_techniques": ["technique1"],
            "ics_attack_techniques": ["ics_technique1"],
            "kill_chains": ["kill_chain1"],
            "pre_attack_techniques": ["pre_attack_technique1"],
            "threat_groups": ["threat_group1"],
            "products": [{"serial": "serial1"}],
        }
    )


@pytest.fixture
def mock_dragos_client():
    """Fixture to create a mock Dragos client."""

    client = Mock(spec=DragosClientAPIV1)

    client.product = Mock()
    # Mock iter_products async generator
    mock_async_iter_products = AsyncMock()
    mock_async_iter_products.__aiter__.return_value = [fake_product_response()] * 3
    client.product.iter_products.return_value = mock_async_iter_products
    # Mock get_product_pdf async method
    mock_async_get_product_pdf = AsyncMock()
    mock_async_get_product_pdf.return_value = b"PDF content"
    client.product.get_product_pdf.return_value = mock_async_get_product_pdf()

    client.indicator = Mock()
    # Mock iter_indicators async generator
    mock_async_iter_indicators = AsyncMock()
    mock_async_iter_indicators.__aiter__.return_value = [fake_indicator_response()] * 3
    client.indicator.iter_indicators.return_value = mock_async_iter_indicators

    return client


def test_reports_api_v1_lists_all_reports(mock_dragos_client):
    """Test that the ReportsAPIV1 generates reports."""

    # Given an instance of ReportsAPIV1
    reports_api_v1 = ReportsAPIV1(
        base_url=URL("http://example.com"),
        token="<API_TOKEN>",
        secret="<API_SECRET>",
        timeout=timedelta(seconds=10),
        retry=3,
        backoff=timedelta(seconds=1),
    )
    reports_api_v1._client = mock_dragos_client

    # When calling iter() generator
    start_date = datetime(1970, 1, 1, tzinfo=timezone.utc)
    reports = list(reports_api_v1.iter(since=start_date))

    # Then ReportAPIV1 instances should be yielded
    assert len(reports) == 3
    assert all(isinstance(report, ReportAPIV1) for report in reports) is True


def test_report_api_v1_from_product_response_returns_report(
    mock_dragos_client,
):
    """Test ReportAPIV1.from_product_response factory method."""

    # Given a ProductResponse from DragosClientAPIV1
    product_response = ProductResponse.model_validate(fake_product_response())
    extended_product_response = ExtendedProductResponse(
        product=product_response, client=mock_dragos_client
    )

    # When calling from_product_response() factory
    report = ReportAPIV1.from_product_response(extended_product_response)

    # Then a ReportAPIV1 instance should be created
    assert isinstance(report, ReportAPIV1)
    assert report.serial == product_response.serial
    assert report.title == product_response.title
    assert report.created_at == product_response.release_date
    assert report.updated_at == product_response.updated_at
    assert report.summary == product_response.executive_summary
    assert isinstance(report.pdf, bytes)
    assert len(list(report.related_tags)) == 1
    assert all(isinstance(tag, TagAPIV1) for tag in report.related_tags) is True
    assert len(list(report.related_indicators)) == 3
    assert (
        all(
            isinstance(indicator, IndicatorAPIV1)
            for indicator in report.related_indicators
        )
        is True
    )


def test_tag_api_v1_from_tag_response_returns_tag():
    """Test TagAPIV1.from_tag_response factory method."""

    # Given a TagResponse from DragosClientAPIV1
    tag_response = TagResponse.model_validate(fake_tag_response())

    # When calling from_tag_response() factory
    tag = TagAPIV1.from_tag_response(tag_response)

    # Then a TagAPIV1 instance should be created
    assert isinstance(tag, TagAPIV1)
    assert tag.value == tag_response.text
    assert tag.type == tag_response.tag_type


def test_indicator_api_v1_from_indicator_response_returns_indicator():
    """Test IndicatorAPIV1.from_indicator_response factory method."""

    # Given an IndicatorResponse from DragosClientAPIV1
    indicator_response = IndicatorResponse.model_validate(fake_indicator_response())

    # When calling from_indicator_response() factory
    indicator = IndicatorAPIV1.from_indicator_response(indicator_response)

    # Then an IndicatorAPIV1 instance should be created
    assert isinstance(indicator, IndicatorAPIV1)
    assert indicator.type == indicator_response.indicator_type
    assert indicator.value == indicator_response.value
    assert indicator.first_seen == indicator_response.first_seen
    assert indicator.last_seen == indicator_response.last_seen
