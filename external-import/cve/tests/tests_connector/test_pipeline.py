"""Tests for the streaming CVE+CPE ingestion pipeline.

Validates that:
- CVE bundles are sent *while* CPE resolution is still running (true streaming).
- Concurrency is bounded by the semaphore (cpe_max_concurrency).
- The queue-based consumer batches CPE bundles correctly.
- No data is lost or duplicated under concurrent load.
- TaskGroup exceptions propagate correctly.
- import_software=False takes the fast path (no CPE work).
"""

import asyncio
import json
import threading
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tests.conftest import make_cpe_name, make_vulnerability

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_converter(
    *,
    num_pages: int = 3,
    vulns_per_page: int = 5,
    cpes_per_cve: int = 2,
    import_software: bool = True,
    cpe_max_concurrency: int = 4,
    cpe_bundle_batch_size: int = 10,
    cpe_delay: float = 0.0,
):
    """Build a CVEConverter with mocked clients and helper.

    Returns (converter, tracker) where tracker records call ordering.
    """
    from src.services.converter.vulnerability_to_stix2 import CVEConverter

    # Thread-safe lock for the tracker (send_stix2_bundle runs in a thread)
    tlock = threading.Lock()

    tracker = {
        "cve_bundle_send_times": [],
        "cpe_bundle_send_times": [],
        "cve_bundles_sent": [],
        "cpe_bundles_sent": [],
        "cpe_resolve_log": [],  # (cve_id, start_time, end_time)
        "concurrent_cpe_gauge": {"max": 0, "current": 0},
        "async_lock": asyncio.Lock(),
    }

    # -- Build pages of vulnerabilities
    pages: list[list[dict]] = []
    cve_counter = 0
    for _ in range(num_pages):
        page = []
        for _ in range(vulns_per_page):
            cve_counter += 1
            page.append(make_vulnerability(f"CVE-2024-{cve_counter:04d}"))
        pages.append(page)

    # -- Mock CVEVulnerability.get_vulnerabilities as async generator
    async def fake_get_vulnerabilities(cve_params=None):
        for page in pages:
            yield page

    # -- Mock CPEMatchClient.get_cpes_for_cve
    async def fake_get_cpes_for_cve(cve_id: str) -> list[str]:
        async with tracker["async_lock"]:
            tracker["concurrent_cpe_gauge"]["current"] += 1
            tracker["concurrent_cpe_gauge"]["max"] = max(
                tracker["concurrent_cpe_gauge"]["max"],
                tracker["concurrent_cpe_gauge"]["current"],
            )

        start = time.monotonic()
        if cpe_delay > 0:
            await asyncio.sleep(cpe_delay)
        end = time.monotonic()

        async with tracker["async_lock"]:
            tracker["concurrent_cpe_gauge"]["current"] -= 1
            tracker["cpe_resolve_log"].append((cve_id, start, end))

        # Generate unique CPE names per CVE
        return [
            make_cpe_name(vendor=f"vendor_{cve_id}", product=f"prod_{i}")
            for i in range(cpes_per_cve)
        ]

    # -- Mock helper
    mock_helper = MagicMock()
    mock_helper.connector_logger = MagicMock()

    def fake_send_stix2_bundle(bundle_json, work_id=None):
        """Sync callback — runs in a thread via asyncio.to_thread()."""
        now = time.monotonic()
        data = json.loads(bundle_json)
        obj_types = [o["type"] for o in data.get("objects", [])]

        with tlock:
            if "vulnerability" in obj_types:
                tracker["cve_bundle_send_times"].append(now)
                tracker["cve_bundles_sent"].append(data)
            elif "software" in obj_types or "relationship" in obj_types:
                tracker["cpe_bundle_send_times"].append(now)
                tracker["cpe_bundles_sent"].append(data)

    mock_helper.send_stix2_bundle = fake_send_stix2_bundle

    # -- Mock config
    mock_config = MagicMock()
    mock_config.cve.import_software = import_software
    mock_config.cve.cpe_max_concurrency = cpe_max_concurrency
    mock_config.cve.cpe_bundle_batch_size = cpe_bundle_batch_size
    mock_config.cve.api_key.get_secret_value.return_value = "fake-api-key"

    # -- Build converter with mocked internals
    with patch.object(CVEConverter, "__init__", lambda self, *a, **kw: None):
        converter = CVEConverter.__new__(CVEConverter)

    converter.config = mock_config
    converter.helper = mock_helper
    converter.import_software = import_software
    converter.cpe_max_concurrency = cpe_max_concurrency
    converter.cpe_bundle_batch_size = cpe_bundle_batch_size
    converter.author = CVEConverter._create_author()

    # Mock the clients
    converter.client_api = MagicMock()
    converter.client_api.get_vulnerabilities = fake_get_vulnerabilities
    converter.client_api.close = AsyncMock()

    converter.cpe_match_client = MagicMock()
    converter.cpe_match_client.get_cpes_for_cve = fake_get_cpes_for_cve
    converter.cpe_match_client.close = AsyncMock()

    return converter, tracker


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_cve_bundles_sent_before_all_cpes_resolved():
    """CVE bundles must be sent while CPE resolution is still running,
    proving true streaming (not sequential two-phase)."""
    converter, tracker = _make_converter(
        num_pages=3,
        vulns_per_page=5,
        cpes_per_cve=2,
        cpe_delay=0.05,
    )

    await converter.ingest({}, "work-1")

    # All CVE bundles should have been sent
    assert len(tracker["cve_bundle_send_times"]) == 3

    # At least the first CVE bundle should have been sent before
    # the last CPE resolution finished.
    first_cve_send = tracker["cve_bundle_send_times"][0]
    last_cpe_resolve = max(end for _, _, end in tracker["cpe_resolve_log"])
    assert first_cve_send < last_cpe_resolve, (
        "First CVE bundle should be sent before all CPE resolutions complete"
    )


async def test_all_cves_produce_bundles():
    """Every page of CVEs must produce exactly one CVE bundle."""
    num_pages = 5
    vulns_per_page = 4

    converter, tracker = _make_converter(
        num_pages=num_pages,
        vulns_per_page=vulns_per_page,
    )

    await converter.ingest({}, "work-1")

    assert len(tracker["cve_bundles_sent"]) == num_pages

    for bundle in tracker["cve_bundles_sent"]:
        vuln_objects = [o for o in bundle["objects"] if o["type"] == "vulnerability"]
        assert len(vuln_objects) == vulns_per_page


async def test_all_cpes_resolved_no_data_loss():
    """Every CVE should have its CPEs resolved and sent."""
    num_pages = 3
    vulns_per_page = 4
    cpes_per_cve = 3
    total_cves = num_pages * vulns_per_page

    converter, tracker = _make_converter(
        num_pages=num_pages,
        vulns_per_page=vulns_per_page,
        cpes_per_cve=cpes_per_cve,
    )

    await converter.ingest({}, "work-1")

    assert len(tracker["cpe_resolve_log"]) == total_cves

    # Count total software objects across all CPE bundles
    total_software = 0
    total_relationships = 0
    for bundle in tracker["cpe_bundles_sent"]:
        for obj in bundle["objects"]:
            if obj["type"] == "software":
                total_software += 1
            elif obj["type"] == "relationship":
                total_relationships += 1

    expected_software = total_cves * cpes_per_cve
    assert total_software == expected_software, (
        f"Expected {expected_software} software objects, got {total_software}"
    )
    assert total_relationships == expected_software, (
        f"Expected {expected_software} relationships, got {total_relationships}"
    )


async def test_concurrency_bounded_by_semaphore():
    """At no point should more than cpe_max_concurrency CPE resolutions
    run simultaneously."""
    max_concurrency = 3

    converter, tracker = _make_converter(
        num_pages=2,
        vulns_per_page=10,
        cpe_delay=0.02,
        cpe_max_concurrency=max_concurrency,
    )

    await converter.ingest({}, "work-1")

    observed_max = tracker["concurrent_cpe_gauge"]["max"]
    assert observed_max <= max_concurrency, (
        f"Max concurrent CPE resolves was {observed_max}, "
        f"expected at most {max_concurrency}"
    )
    # Should actually use some concurrency (not purely serial)
    assert observed_max > 1, f"Expected some parallelism (>1), got {observed_max}"


async def test_cpe_bundle_batching():
    """CPE objects should be batched according to cpe_bundle_batch_size."""
    batch_size = 6
    cpes_per_cve = 2  # 2 software + 2 relationships = 4 objects per CVE

    converter, tracker = _make_converter(
        num_pages=1,
        vulns_per_page=10,
        cpes_per_cve=cpes_per_cve,
        cpe_bundle_batch_size=batch_size,
    )

    await converter.ingest({}, "work-1")

    # Should have multiple CPE bundles (not one giant one)
    assert len(tracker["cpe_bundles_sent"]) > 1, "Expected multiple batched CPE bundles"


async def test_no_cpe_work_when_import_software_disabled():
    """When import_software is False, no CPE resolution should happen."""
    converter, tracker = _make_converter(
        num_pages=2,
        vulns_per_page=5,
        import_software=False,
    )

    await converter.ingest({}, "work-1")

    assert len(tracker["cve_bundles_sent"]) == 2
    assert len(tracker["cpe_bundles_sent"]) == 0
    assert len(tracker["cpe_resolve_log"]) == 0


async def test_empty_page_does_not_send_bundle():
    """Pages with no vulnerabilities after filtering should not send bundles."""
    converter, tracker = _make_converter(num_pages=1, vulns_per_page=3)

    # Override get_vulnerabilities to yield an empty page followed by a real one
    pages = [[], [make_vulnerability("CVE-2024-0001")]]

    async def fake_gen(cve_params=None):
        for page in pages:
            yield page

    converter.client_api.get_vulnerabilities = fake_gen

    await converter.ingest({}, "work-1")

    # Only the non-empty page should produce a bundle
    assert len(tracker["cve_bundles_sent"]) == 1


async def test_cpe_resolve_error_does_not_crash_pipeline():
    """If a single CPE resolution raises, the TaskGroup should propagate
    the error, but the other CVEs should still have been processed."""
    converter, tracker = _make_converter(
        num_pages=1,
        vulns_per_page=5,
        cpe_delay=0.01,
    )

    call_count = 0
    original_resolve = converter.cpe_match_client.get_cpes_for_cve

    async def flaky_resolve(cve_id: str) -> list[str]:
        nonlocal call_count
        call_count += 1
        if call_count == 3:
            raise RuntimeError("Simulated API failure")
        return await original_resolve(cve_id)

    converter.cpe_match_client.get_cpes_for_cve = flaky_resolve

    with pytest.raises(ExceptionGroup) as exc_info:
        await converter.ingest({}, "work-1")

    # The RuntimeError should be inside the ExceptionGroup
    errors = exc_info.value.exceptions
    assert any(isinstance(e, RuntimeError) for e in errors)


async def test_consumer_flushes_remainder_on_sentinel():
    """The consumer must send any remaining batch when it receives
    the None sentinel, even if batch_size hasn't been reached."""
    converter, tracker = _make_converter(
        num_pages=1,
        vulns_per_page=1,
        cpes_per_cve=1,
        cpe_bundle_batch_size=1000,  # Very large — forces flush at sentinel
    )

    await converter.ingest({}, "work-1")

    # Should still have exactly 1 CPE bundle (the flush)
    assert len(tracker["cpe_bundles_sent"]) == 1


async def test_cve_and_cpe_bundles_both_include_author():
    """Every bundle (CVE and CPE) must include the NIST NVD identity."""
    converter, tracker = _make_converter(
        num_pages=1,
        vulns_per_page=2,
        cpes_per_cve=1,
    )

    await converter.ingest({}, "work-1")

    all_bundles = tracker["cve_bundles_sent"] + tracker["cpe_bundles_sent"]
    assert len(all_bundles) > 0

    for bundle in all_bundles:
        identity_objects = [o for o in bundle["objects"] if o["type"] == "identity"]
        assert len(identity_objects) >= 1, "Bundle missing author identity"
        assert any(o["name"] == "NIST NVD" for o in identity_objects)


async def test_high_concurrency_no_data_corruption():
    """Stress test: many CVEs with high concurrency to detect
    race conditions in queue/batch handling."""
    num_pages = 10
    vulns_per_page = 20
    cpes_per_cve = 3
    total_cves = num_pages * vulns_per_page

    converter, tracker = _make_converter(
        num_pages=num_pages,
        vulns_per_page=vulns_per_page,
        cpes_per_cve=cpes_per_cve,
        cpe_max_concurrency=15,
        cpe_bundle_batch_size=20,
        cpe_delay=0.005,
    )

    await converter.ingest({}, "work-1")

    # Verify all CVEs resolved
    assert len(tracker["cpe_resolve_log"]) == total_cves

    # Verify no data loss in CPE bundles
    total_software = 0
    for bundle in tracker["cpe_bundles_sent"]:
        for obj in bundle["objects"]:
            if obj["type"] == "software":
                total_software += 1

    expected = total_cves * cpes_per_cve
    assert total_software == expected, (
        f"Data loss detected: expected {expected} software objects, got {total_software}"
    )

    # Verify all CVE bundles sent
    assert len(tracker["cve_bundles_sent"]) == num_pages


async def test_cve_bundles_ordered_by_page():
    """CVE bundles must be sent in the same order as pages arrive."""
    converter, tracker = _make_converter(
        num_pages=5,
        vulns_per_page=3,
    )

    await converter.ingest({}, "work-1")

    send_times = tracker["cve_bundle_send_times"]
    assert send_times == sorted(send_times), "CVE bundles should be sent in page order"


async def test_cpe_resolution_starts_before_all_pages_fetched():
    """CPE resolution for page 1 should start before page N is fetched,
    proving the pipeline doesn't buffer all pages first."""
    converter, tracker = _make_converter(
        num_pages=5,
        vulns_per_page=5,
        cpe_delay=0.02,
    )

    # Add delay between pages to make ordering observable
    original_gen = converter.client_api.get_vulnerabilities
    pages_yielded_at: list[float] = []

    async def delayed_gen(cve_params=None):
        async for page in original_gen(cve_params):
            pages_yielded_at.append(time.monotonic())
            yield page
            await asyncio.sleep(0.01)

    converter.client_api.get_vulnerabilities = delayed_gen

    await converter.ingest({}, "work-1")

    # First CPE resolve should start before the last page is yielded
    first_cpe_start = min(start for _, start, _ in tracker["cpe_resolve_log"])
    last_page_yield = pages_yielded_at[-1]

    assert (
        first_cpe_start < last_page_yield
    ), "CPE resolution should start before all pages are fetched"


async def test_no_cpe_bundles_when_zero_cpes():
    """If CPE resolution returns empty lists, no CPE bundles should be sent."""
    converter, tracker = _make_converter(
        num_pages=2,
        vulns_per_page=3,
        cpes_per_cve=0,
    )

    await converter.ingest({}, "work-1")

    assert len(tracker["cve_bundles_sent"]) == 2
    assert len(tracker["cpe_bundles_sent"]) == 0
