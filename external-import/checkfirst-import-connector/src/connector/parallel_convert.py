"""Process-pool helpers for Row → STIX conversion.

Workers own a process-local ``ConverterToStix`` (no OpenCTI helper). The main
process keeps HTTP fetch, bundle send, and the single ``last_cursor`` watermark.
"""

from __future__ import annotations

from checkfirst_client.api_models import Article
from connector.converter_to_stix import ConversionError, ConverterToStix
from connectors_sdk.models import BaseIdentifiedEntity

_worker_converter: ConverterToStix | None = None


def init_convert_worker(tlp_level: str) -> None:
    """Create a process-local converter for pool workers."""
    global _worker_converter
    _worker_converter = ConverterToStix(helper=None, tlp_level=tlp_level)


def convert_row_in_worker(
    article: Article,
) -> tuple[str, int, list[BaseIdentifiedEntity] | None, str | None]:
    """Convert one article in a worker process.

    Returns:
        ``(row_id, row_number, entities_or_none, error_or_none)``.
        On success ``error`` is ``None``; on failure ``entities`` is ``None``.
    """
    if _worker_converter is None:
        return article.id, article.row_number, None, "convert worker not initialized"

    try:
        campaign, attributed_to = _worker_converter.get_campaign_for_year(
            year=article.published_date.year
        )
        article_entities = _worker_converter.convert_article(article, campaign)
        return (
            article.id,
            article.row_number,
            [campaign, attributed_to] + article_entities,
            None,
        )
    except ConversionError as err:
        return article.id, article.row_number, None, str(err)
    except Exception as err:  # noqa: BLE001 — surface any worker failure to the parent
        return article.id, article.row_number, None, str(err)
