"""Tests for process-pool Row → STIX conversion helpers."""

from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone

from checkfirst_client.api_models import Article
from connector.parallel_convert import convert_row_in_worker, init_convert_worker


def _make_article(article_id: str = "abc123", row_number: int = 1) -> Article:
    return Article(
        _id=article_id,
        row_number=row_number,
        url="https://france.news-pravda.com/article-1",
        source_title="Telegram Source",
        source_url="https://t.me/source",
        published_date=datetime(2025, 3, 15, tzinfo=timezone.utc),
        title="Test Article",
    )


def test_convert_row_in_worker_in_process():
    init_convert_worker("clear")
    row_id, row_number, entities, error = convert_row_in_worker(_make_article())

    assert error is None
    assert row_id == "abc123"
    assert row_number == 1
    assert entities is not None
    assert len(entities) > 0


def test_convert_row_in_worker_via_process_pool():
    articles = [_make_article(article_id=f"id-{i}", row_number=i) for i in range(4)]

    with ProcessPoolExecutor(
        max_workers=2,
        initializer=init_convert_worker,
        initargs=("clear",),
    ) as pool:
        results = list(pool.map(convert_row_in_worker, articles))

    assert len(results) == 4
    for article, (row_id, row_number, entities, error) in zip(
        articles, results, strict=True
    ):
        assert error is None
        assert row_id == article.id
        assert row_number == article.row_number
        assert entities is not None
        assert len(entities) > 0
