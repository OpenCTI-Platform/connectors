import json
from datetime import datetime, timedelta, timezone

from src.cache import HuntCache


def test_cache_miss_on_fresh_file(tmp_path):
    cache = HuntCache(str(tmp_path / "cache.json"), ttl_hours=24)
    assert (
        cache.is_fresh(
            "8e4c1bab-3695-4e5c-a900-934512d05205", "2026-05-13T15:36:15.873627+00:00"
        )
        is False
    )


def test_cache_hit_after_mark(tmp_path):
    path = tmp_path / "cache.json"
    cache = HuntCache(str(path), ttl_hours=24)
    uuid_val = "8e4c1bab-3695-4e5c-a900-934512d05205"
    cache.mark(uuid_val, "2026-05-13T15:36:15.873627+00:00")
    assert cache.is_fresh(uuid_val, "2026-05-13T15:36:15.873627+00:00") is True
    # Different last_updated invalidates.
    assert cache.is_fresh(uuid_val, "2026-05-14T00:00:00+00:00") is False


def test_cache_uuid_case_insensitive(tmp_path):
    cache = HuntCache(str(tmp_path / "cache.json"), ttl_hours=24)
    cache.mark(
        "ABC123DE-0000-0000-0000-000000000000", "2026-05-13T15:36:15.873627+00:00"
    )
    assert cache.is_fresh(
        "abc123de-0000-0000-0000-000000000000", "2026-05-13T15:36:15.873627+00:00"
    )


def test_cache_persists_to_disk(tmp_path):
    path = tmp_path / "cache.json"
    cache = HuntCache(str(path), ttl_hours=24)
    cache.mark("uuid-1", "2026-05-13T15:36:15.873627+00:00")
    data = json.loads(path.read_text())
    assert "uuid-1" in data


def test_cache_ttl_expiry(tmp_path):
    path = tmp_path / "cache.json"
    # Hand-roll an expired entry, then load it.
    expired = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    path.write_text(json.dumps({"uuid-1": {"last_updated": "x", "cached_at": expired}}))
    cache = HuntCache(str(path), ttl_hours=1)
    assert cache.is_fresh("uuid-1", "x") is False
