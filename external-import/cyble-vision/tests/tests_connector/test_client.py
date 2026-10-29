from datetime import datetime, timezone

from cyble_client.api_client import to_vision_timestamp
from cyble_client.engine_client import CybleEngineClient
from cyble_client.engine_dates import iso_date, next_page, parse_engine_datetime


def test_to_vision_timestamp_uses_milliseconds_and_z():
    value = datetime(2026, 10, 1, 3, 7, 31, 859433, tzinfo=timezone.utc)
    assert to_vision_timestamp(value) == "2026-10-01T03:07:31.859Z"


def test_engine_date_formats():
    assert iso_date(datetime(2026, 10, 12, 15, tzinfo=timezone.utc)) == "2026-10-12"
    assert parse_engine_datetime("2026-10-13").day == 13
    assert parse_engine_datetime("2025-07-14 14:50:20").hour == 14
    assert next_page(1, 50, 51) == 2
    assert next_page(2, 50, 51) is None
    assert next_page(2, 50, 50) is None


class _Logger:
    def info(self, *args, **kwargs):
        return None

    def warning(self, *args, **kwargs):
        return None


def test_engine_client_walks_advisory_pages():
    client = CybleEngineClient(
        base_url="https://api.cyble.ai",
        api_token="test",
        page_size=2,
        logger=_Logger(),
    )
    calls = []

    def fake_get(path, params=None):
        calls.append(params["page"])
        page = int(params["page"])
        rows = [{"id": page}, {"id": page + 10}]
        return {
            "success": True,
            "data": {
                "pagination": {"page": str(page), "items_per_page": "2", "total": 6},
                "reports": rows,
            },
        }

    client._get = fake_get
    pages = list(
        client.iter_advisories(
            since=datetime(2026, 10, 12, tzinfo=timezone.utc),
            until=datetime(2026, 10, 13, tzinfo=timezone.utc),
        )
    )
    assert calls == [1, 2, 3]
    assert len(pages) == 3
