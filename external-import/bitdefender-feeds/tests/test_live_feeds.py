"""Opt-in, read-only tests against the Bitdefender Threat Intelligence feeds.

These tests make REAL requests to Bitdefender, but NEVER connect to OpenCTI.
Set BITDEFENDER_TEST_API_KEY to enable them; otherwise all three are skipped.
Run with ``python -m pytest -s -v tests/test_live_feeds.py`` to see statistics.
"""

import json
import os
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture(scope="module")
def live_api_key():
    key = os.environ.get("BITDEFENDER_TEST_API_KEY", "").strip()
    if not key:
        pytest.skip("Set BITDEFENDER_TEST_API_KEY to run live Bitdefender feed tests")
    return key


def _positive_int_from_env(name, default, maximum):
    value = int(os.getenv(name, str(default)))
    if not 1 <= value <= maximum:
        raise ValueError(f"{name} must be between 1 and {maximum}")
    return value


@dataclass
class FeedStats:
    feed: str
    downloaded_bytes: int = 0
    total_lines: int = 0
    empty_lines: int = 0
    converted_entries: int = 0
    failed_entries: int = 0
    bundles: int = 0
    stix_objects: int = 0
    relationship_objects: int = 0
    indicator_objects: int = 0
    warnings: int = 0
    object_types: Counter = field(default_factory=Counter)
    failure_samples: list = field(default_factory=list)

    def print_summary(self, elapsed_seconds):
        print(
            f"\nBitdefender {self.feed} feed dry-run:"
            f"\n  Downloaded bytes:    {self.downloaded_bytes:,}"
            f"\n  Total lines:         {self.total_lines:,}"
            f"\n  Empty lines:         {self.empty_lines:,}"
            f"\n  Converted entries:   {self.converted_entries:,}"
            f"\n  Failed entries:      {self.failed_entries:,}"
            f"\n  STIX bundles:        {self.bundles:,}"
            f"\n  STIX objects:        {self.stix_objects:,}"
            f"\n  Indicators:          {self.indicator_objects:,}"
            f"\n  Relationships:       {self.relationship_objects:,}"
            f"\n  Parser warnings:     {self.warnings:,}"
            f"\n  Elapsed:             {elapsed_seconds:.1f}s"
            f"\n  Types:               {dict(self.object_types.most_common())}",
            flush=True,
        )
        for sample in self.failure_samples:
            print(f"  Conversion failure:  {sample}", flush=True)


class RecordingLogger:
    """Count parser warnings while avoiding credential/record logging."""

    def __init__(self, stats):
        self.stats = stats

    def info(self, *args, **kwargs):
        pass

    def debug(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        self.stats.warnings += 1

    def error(self, *args, **kwargs):
        pass


class OfflineWork:
    """Simulates OpenCTI work tracking without external operations."""

    def __init__(self):
        self.started = 0
        self.finished = []

    def initiate_work(self, *args, **kwargs):
        self.started += 1
        return "dry-run-work"

    def to_processed(self, *args, **kwargs):
        self.finished.append((args, kwargs))


class NoImportHelper:
    """Strict subset of the OpenCTI helper; NO network/API client exists."""

    def __init__(self, pycti, stats, feed, start_timestamp):
        self.stats = stats
        self.connect_name = "Bitdefender dry-run"
        self.connect_id = "test-connector"
        self.connector_logger = RecordingLogger(stats)
        self.state = {
            "last_update": {"ip": 0, "file": 0, "web": 0},
            "queue": [],
        }
        self.state["last_update"][feed] = start_timestamp
        self.work = OfflineWork()
        self.api = SimpleNamespace(
            work=self.work,
            indicator=SimpleNamespace(
                generate_id_from_data=lambda data: pycti.Indicator.generate_id(data["pattern"])
            ),
            malware=SimpleNamespace(
                generate_id_from_data=lambda data: pycti.Malware.generate_id(data["name"])
            ),
        )

    def get_state(self):
        return self.state

    def set_state(self, state):
        self.state = state

    def send_stix2_bundle(self, *, bundle, work_id, update):
        """Validate and count serialized bundles; do not submit anything."""
        assert work_id == "dry-run-work"
        assert update is True
        payload = json.loads(bundle)
        assert payload["type"] == "bundle"
        objects = payload["objects"]
        assert objects, "An empty STIX bundle was emitted"

        # OpenCTI is not contacted, so references must be bundle-local.
        object_ids = {obj["id"] for obj in objects}
        for obj in objects:
            if obj["type"] == "relationship":
                assert obj["source_ref"] in object_ids, obj
                assert obj["target_ref"] in object_ids, obj
            if "created_by_ref" in obj:
                assert obj["created_by_ref"] in object_ids, obj

        counts = Counter(obj["type"] for obj in objects)
        self.stats.bundles += 1
        self.stats.stix_objects += len(objects)
        self.stats.indicator_objects += counts["indicator"]
        self.stats.relationship_objects += counts["relationship"]
        self.stats.object_types.update(counts)
        return []


def _run_live_feed(feed, api_key, tmp_path, monkeypatch):
    """Run production download + production STIX conversion without OpenCTI."""
    # Import runtime dependencies only after the API-key fixture authorizes the test.
    import pycti
    from pydantic import SecretStr
    from src.bitdefender_import_feed.connector import BitdefenderFeedConnector
    from src.bitdefender_import_feed.stixmaker import StixMaker

    window = _positive_int_from_env("BITDEFENDER_TEST_LAST_SECONDS", 86400, 86400)
    max_bundle_entries = _positive_int_from_env(
        "BITDEFENDER_TEST_MAX_BUNDLE_ENTRIES", 10000, 1000000
    )
    stats = FeedStats(feed=feed)
    helper = NoImportHelper(pycti, stats, feed, int(time.time()) - window)
    config = SimpleNamespace(
        bitdefender=SimpleNamespace(
            api_key=SecretStr(api_key),
            feeds=[feed],
            http_timeout_seconds=600,
            verify_tls=True,
            min_confidence=75,
            min_severity=1,
            include_revoked="false",
            include_suspicious="false",
            exclude_related_indicators=False,
            exclude_similar_files=False,
            detection=False,
            create_malware_objects=True,
            max_lookback_interval=86400,
            tlp_level="clear",
        )
    )

    start = time.monotonic()
    monkeypatch.chdir(tmp_path)
    try:
        # The production method performs the real HTTPS download into tmp_path.
        # DO NOT call connector.import_downloaded_feeds(), which handles queue
        # checkpoints and deletes the file. This test requires strict conversion.
        connector = BitdefenderFeedConnector(config, helper)
        connector.download_feeds()
        assert len(connector.state["queue"]) == 1
        assert connector.state["queue"][0]["feed"] == feed

        downloaded_file = Path(connector.state["queue"][0]["file"])
        stats.downloaded_bytes = downloaded_file.stat().st_size

        # Create real STIX objects and serialize every bundle, but route send
        # calls into NoImportHelper.send_stix2_bundle(), never to OpenCTI.
        maker = StixMaker(
            config, helper, feedtype=feed, max_bundle_entries=max_bundle_entries
        )
        with downloaded_file.open("r", encoding="utf-8") as source:
            for line_number, line in enumerate(source, start=1):
                stats.total_lines += 1
                record = line.strip()
                if not record:
                    stats.empty_lines += 1
                    continue
                try:
                    maker.fromEntry(record)
                except Exception as exc:
                    stats.failed_entries += 1
                    if len(stats.failure_samples) < 10:
                        stats.failure_samples.append(
                            f"line {line_number}: {type(exc).__name__}: {exc}"
                        )
                    continue
                stats.converted_entries += 1

        maker.sendFinal()
        assert helper.work.started == 1
        assert len(helper.work.finished) == 1
        assert not helper.work.finished[0][1].get("in_error")

        assert stats.total_lines > 0, "Downloaded feed has no lines"
        assert stats.converted_entries > 0, (
            "No entries converted; try a longer test window or check feed access"
        )
        assert stats.failed_entries == 0, (
            f"{feed} feed: {stats.failed_entries:,} entry conversions failed; "
            f"first failures: {stats.failure_samples}"
        )
        assert stats.bundles > 0, "No STIX bundles were emitted"
        assert stats.indicator_objects == stats.converted_entries, (
            f"Expected one STIX Indicator per entry, got "
            f"{stats.indicator_objects} indicators for "
            f"{stats.converted_entries} converted entries"
        )
        assert stats.relationship_objects >= stats.converted_entries, (
            "Expected at least one relationship (indicator based-on observable) "
            "per entry"
        )
    finally:
        stats.print_summary(time.monotonic() - start)


def test_live_ip_feed(live_api_key, tmp_path, monkeypatch):
    _run_live_feed("ip", live_api_key, tmp_path, monkeypatch)


def test_live_file_feed(live_api_key, tmp_path, monkeypatch):
    _run_live_feed("file", live_api_key, tmp_path, monkeypatch)


def test_live_web_feed(live_api_key, tmp_path, monkeypatch):
    _run_live_feed("web", live_api_key, tmp_path, monkeypatch)
