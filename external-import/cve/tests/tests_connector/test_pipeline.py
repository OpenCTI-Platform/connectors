"""Tests for the streaming CVE+CPE ingestion pipeline.

Validates that:
- Each CVE produces one self-contained bundle (Vulnerability + Software + Relationships).
- Concurrency is bounded for both overall CVE workers and CPE resolution.
- No data is lost or duplicated under concurrent load.
- TaskGroup exceptions propagate correctly.
- import_software=False sends CVE-only bundles (no CPE work).
- Bundles are consistent: every relationship target exists in the same bundle.
"""

import asyncio
import json
import threading
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from src.services.client.api import CVEClient
from src.services.utils.rate_limiter import AsyncRateLimiter

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
    cve_max_concurrency: int = 8,
    cpe_delay: float = 0.0,
    send_delay: float = 0.0,
):
    """Build a CVEConverter with mocked clients and helper.

    Returns (converter, tracker) where tracker records call ordering.
    """
    from src.services.converter.vulnerability_to_stix2 import CVEConverter

    # Thread-safe lock for the tracker (send_stix2_bundle runs in a thread)
    tlock = threading.Lock()

    tracker = {
        "bundles_sent": [],
        "bundle_send_times": [],
        "cpe_resolve_log": [],  # (cve_id, start_time, end_time)
        "concurrent_cpe_gauge": {"max": 0, "current": 0},
        "concurrent_send_gauge": {"max": 0, "current": 0},
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

        return [
            make_cpe_name(vendor=f"vendor_{cve_id}", product=f"prod_{i}")
            for i in range(cpes_per_cve)
        ]

    # -- Mock helper
    mock_helper = MagicMock()
    mock_helper.connector_logger = MagicMock()

    def fake_send_stix2_bundle(bundle_json, work_id=None):
        """Sync callback — runs in a thread via asyncio.to_thread()."""
        with tlock:
            tracker["concurrent_send_gauge"]["current"] += 1
            tracker["concurrent_send_gauge"]["max"] = max(
                tracker["concurrent_send_gauge"]["max"],
                tracker["concurrent_send_gauge"]["current"],
            )

        if send_delay > 0:
            time.sleep(send_delay)

        now = time.monotonic()
        data = json.loads(bundle_json)
        with tlock:
            tracker["bundles_sent"].append(data)
            tracker["bundle_send_times"].append(now)
            tracker["concurrent_send_gauge"]["current"] -= 1

    mock_helper.send_stix2_bundle = fake_send_stix2_bundle

    # -- Mock config
    mock_config = MagicMock()
    mock_config.cve.import_software = import_software
    mock_config.cve.cpe_max_concurrency = cpe_max_concurrency
    mock_config.cve.cve_max_concurrency = cve_max_concurrency
    mock_config.cve.api_key.get_secret_value.return_value = "fake-api-key"

    # -- Build converter with mocked internals
    with patch.object(CVEConverter, "__init__", lambda self, *a, **kw: None):
        converter = CVEConverter.__new__(CVEConverter)

    converter.config = mock_config
    converter.helper = mock_helper
    converter.import_software = import_software
    converter.cpe_max_concurrency = cpe_max_concurrency
    converter.cpe_history_interval = None
    converter.cve_max_concurrency = cve_max_concurrency
    converter.work_id = None
    converter.author = CVEConverter._create_author()

    # Mock work initiation so lazy _initiate_work succeeds
    mock_helper.api.work.initiate_work.return_value = "test-work-id"
    mock_helper.connect_id = "test-connector-id"
    mock_helper.connect_name = "CVE Test"

    # Mock the clients
    converter.client_api = MagicMock()
    converter.client_api.get_vulnerabilities = fake_get_vulnerabilities
    converter.client_api.close = AsyncMock()

    converter.cpe_match_client = MagicMock()
    converter.cpe_match_client.get_cpes_for_cve = fake_get_cpes_for_cve
    converter.cpe_match_client.close = AsyncMock()

    return converter, tracker


def _count_types(bundles: list[dict]) -> dict[str, int]:
    """Count STIX object types across all bundles."""
    counts: dict[str, int] = {}
    for bundle in bundles:
        for obj in bundle.get("objects", []):
            t = obj["type"]
            counts[t] = counts.get(t, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_one_bundle_per_cve():
    """Each CVE must produce exactly one bundle."""
    total_cves = 3 * 5

    converter, tracker = _make_converter(num_pages=3, vulns_per_page=5)
    await converter.ingest({})

    assert len(tracker["bundles_sent"]) == total_cves


async def test_bundle_is_self_contained():
    """Every bundle must contain the vulnerability referenced by its
    relationships, ensuring OpenCTI can resolve all refs in one bundle."""
    converter, tracker = _make_converter(num_pages=1, vulns_per_page=3, cpes_per_cve=2)
    await converter.ingest({})

    for bundle in tracker["bundles_sent"]:
        objects = bundle["objects"]
        obj_ids = {o["id"] for o in objects}
        relationships = [o for o in objects if o["type"] == "relationship"]

        for rel in relationships:
            assert (
                rel["source_ref"] in obj_ids
            ), f"Relationship source_ref {rel['source_ref']} missing from bundle"
            assert (
                rel["target_ref"] in obj_ids
            ), f"Relationship target_ref {rel['target_ref']} missing from bundle"


async def test_bundle_contains_vulnerability_software_and_relationships():
    """When import_software is enabled, each bundle must contain exactly
    one vulnerability, its software objects, and their relationships."""
    cpes_per_cve = 3

    converter, tracker = _make_converter(
        num_pages=1, vulns_per_page=2, cpes_per_cve=cpes_per_cve
    )
    await converter.ingest({})

    for bundle in tracker["bundles_sent"]:
        objects = bundle["objects"]
        vulns = [o for o in objects if o["type"] == "vulnerability"]
        software = [o for o in objects if o["type"] == "software"]
        rels = [o for o in objects if o["type"] == "relationship"]
        identities = [o for o in objects if o["type"] == "identity"]

        assert len(vulns) == 1
        assert len(software) == cpes_per_cve
        assert len(rels) == cpes_per_cve
        assert len(identities) == 1
        assert identities[0]["name"] == "NIST NVD"


async def test_all_cpes_resolved_no_data_loss():
    """Every CVE must have its CPEs resolved — no data loss under concurrency."""
    num_pages = 3
    vulns_per_page = 4
    cpes_per_cve = 3
    total_cves = num_pages * vulns_per_page

    converter, tracker = _make_converter(
        num_pages=num_pages,
        vulns_per_page=vulns_per_page,
        cpes_per_cve=cpes_per_cve,
    )
    await converter.ingest({})

    assert len(tracker["cpe_resolve_log"]) == total_cves

    counts = _count_types(tracker["bundles_sent"])
    expected = total_cves * cpes_per_cve
    assert (
        counts.get("software", 0) == expected
    ), f"Expected {expected} software objects, got {counts.get('software', 0)}"
    assert counts.get("relationship", 0) == expected


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
    await converter.ingest({})

    observed_max = tracker["concurrent_cpe_gauge"]["max"]
    assert observed_max <= max_concurrency, (
        f"Max concurrent CPE resolves was {observed_max}, "
        f"expected at most {max_concurrency}"
    )
    assert observed_max > 1, f"Expected some parallelism (>1), got {observed_max}"


async def test_cve_worker_concurrency_is_bounded():
    """Overall CVE processing should be capped by cve_max_concurrency."""
    max_workers = 2

    converter, tracker = _make_converter(
        num_pages=2,
        vulns_per_page=10,
        import_software=False,
        cve_max_concurrency=max_workers,
        send_delay=0.02,
    )
    await converter.ingest({})

    observed_max = tracker["concurrent_send_gauge"]["max"]
    assert (
        observed_max <= max_workers
    ), f"Max concurrent sends was {observed_max}, expected at most {max_workers}"
    assert observed_max > 1, f"Expected some parallelism (>1), got {observed_max}"


async def test_no_cpe_work_when_import_software_disabled():
    """When import_software is False, bundles contain only vulnerability + author."""
    converter, tracker = _make_converter(
        num_pages=2, vulns_per_page=5, import_software=False
    )
    await converter.ingest({})

    assert len(tracker["bundles_sent"]) == 2 * 5
    assert len(tracker["cpe_resolve_log"]) == 0

    counts = _count_types(tracker["bundles_sent"])
    assert counts.get("software", 0) == 0
    assert counts.get("relationship", 0) == 0


async def test_empty_page_does_not_send_bundle():
    """Pages with no vulnerabilities should not produce any bundles."""
    converter, tracker = _make_converter(num_pages=1, vulns_per_page=3)

    pages = [[], [make_vulnerability("CVE-2024-0001")]]

    async def fake_gen(cve_params=None):
        for page in pages:
            yield page

    converter.client_api.get_vulnerabilities = fake_gen

    await converter.ingest({})

    assert len(tracker["bundles_sent"]) == 1


async def test_cpe_resolve_error_propagates_via_exception_group():
    """If a single CPE resolution raises, the TaskGroup must propagate
    the error as an ExceptionGroup."""
    converter, tracker = _make_converter(num_pages=1, vulns_per_page=5, cpe_delay=0.01)

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
        await converter.ingest({})

    errors = exc_info.value.exceptions
    assert any(isinstance(e, RuntimeError) for e in errors)


async def test_every_bundle_includes_author():
    """Every bundle must include the NIST NVD identity object."""
    converter, tracker = _make_converter(num_pages=1, vulns_per_page=3, cpes_per_cve=1)
    await converter.ingest({})

    assert len(tracker["bundles_sent"]) > 0
    for bundle in tracker["bundles_sent"]:
        identities = [o for o in bundle["objects"] if o["type"] == "identity"]
        assert len(identities) >= 1, "Bundle missing author identity"
        assert any(o["name"] == "NIST NVD" for o in identities)


async def test_high_concurrency_no_data_corruption():
    """Stress test: many CVEs with high concurrency to detect
    race conditions."""
    num_pages = 10
    vulns_per_page = 20
    cpes_per_cve = 3
    total_cves = num_pages * vulns_per_page

    converter, tracker = _make_converter(
        num_pages=num_pages,
        vulns_per_page=vulns_per_page,
        cpes_per_cve=cpes_per_cve,
        cpe_max_concurrency=15,
        cpe_delay=0.005,
    )
    await converter.ingest({})

    assert len(tracker["cpe_resolve_log"]) == total_cves
    assert len(tracker["bundles_sent"]) == total_cves

    counts = _count_types(tracker["bundles_sent"])
    expected = total_cves * cpes_per_cve
    assert (
        counts["software"] == expected
    ), f"Data loss: expected {expected} software, got {counts['software']}"


async def test_cpe_resolution_starts_before_all_pages_fetched():
    """CPE resolution for page 1 should start before page N is fetched,
    proving the pipeline streams instead of buffering all pages."""
    converter, tracker = _make_converter(num_pages=5, vulns_per_page=5, cpe_delay=0.02)

    original_gen = converter.client_api.get_vulnerabilities
    pages_yielded_at: list[float] = []

    async def delayed_gen(cve_params=None):
        async for page in original_gen(cve_params):
            pages_yielded_at.append(time.monotonic())
            yield page
            await asyncio.sleep(0.01)

    converter.client_api.get_vulnerabilities = delayed_gen

    await converter.ingest({})

    first_cpe_start = min(start for _, start, _ in tracker["cpe_resolve_log"])
    last_page_yield = pages_yielded_at[-1]

    assert (
        first_cpe_start < last_page_yield
    ), "CPE resolution should start before all pages are fetched"


async def test_no_software_in_bundle_when_zero_cpes():
    """If CPE resolution returns empty, bundles should only contain
    vulnerability + author (no software/relationship)."""
    converter, tracker = _make_converter(num_pages=2, vulns_per_page=3, cpes_per_cve=0)
    await converter.ingest({})

    assert len(tracker["bundles_sent"]) == 6
    counts = _count_types(tracker["bundles_sent"])
    assert counts.get("software", 0) == 0
    assert counts.get("relationship", 0) == 0


async def test_bundles_sent_concurrently_not_sequentially():
    """With slow CPE resolution, bundles for different CVEs should
    overlap in time (not wait for each other sequentially)."""
    converter, tracker = _make_converter(
        num_pages=1,
        vulns_per_page=6,
        cpe_delay=0.05,
        cpe_max_concurrency=6,
    )
    await converter.ingest({})

    send_times = tracker["bundle_send_times"]
    assert len(send_times) == 6

    # If sequential, total time >= 6 * 0.05 = 0.3s.
    # If concurrent, total time ~ 0.05s (+ overhead).
    total_time = max(send_times) - min(send_times)
    assert (
        total_time < 0.2
    ), f"Bundles appear sequential (spread={total_time:.3f}s), expected concurrent"


async def test_no_duplicate_stix_objects_in_bundle():
    """Each bundle should not contain duplicate STIX objects (same ID)."""
    converter, tracker = _make_converter(num_pages=1, vulns_per_page=5, cpes_per_cve=3)
    await converter.ingest({})

    for i, bundle in enumerate(tracker["bundles_sent"]):
        ids = [o["id"] for o in bundle["objects"]]
        assert len(ids) == len(
            set(ids)
        ), f"Bundle {i} has duplicate STIX IDs: {[x for x in ids if ids.count(x) > 1]}"


async def test_timeout_error_is_retried_not_silenced():
    """TimeoutError from aiohttp must be retried by request(), not swallowed
    as None by get_complete_collection() which would crash the TaskGroup.

    We mock at the aiohttp session level so the real retry loop in request()
    runs and catches the TimeoutError.
    """

    mock_helper = MagicMock()
    mock_helper.connector_logger = MagicMock()

    rate_limiter = AsyncRateLimiter()
    client = CVEClient(
        api_key="fake-key",
        helper=mock_helper,
        header="test/1.0",
        rate_limiter=rate_limiter,
    )

    call_count = 0
    success_payload = {"vulnerabilities": [], "totalResults": 0, "resultsPerPage": 0}

    def make_response():
        """Build an async context manager that fakes aiohttp response."""
        nonlocal call_count
        call_count += 1

        if call_count < 3:
            # Simulate timeout while reading response body
            cm = MagicMock()
            cm.__aenter__ = AsyncMock(side_effect=TimeoutError("simulated timeout"))
            cm.__aexit__ = AsyncMock(return_value=False)
            return cm

        # Success on 3rd attempt
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.json = AsyncMock(return_value=success_payload)
        cm = MagicMock()
        cm.__aenter__ = AsyncMock(return_value=mock_resp)
        cm.__aexit__ = AsyncMock(return_value=False)
        return cm

    mock_session = MagicMock()
    mock_session.closed = False
    mock_session.get = MagicMock(side_effect=lambda *a, **kw: make_response())

    with patch.object(client, "_get_session", AsyncMock(return_value=mock_session)):
        with patch("src.services.client.api.asyncio.sleep", AsyncMock()):
            result = await client.get_complete_collection("https://fake.url")

    # Should have retried and eventually succeeded — not returned None
    assert result is not None, "TimeoutError should be retried, not silenced as None"
    assert result == success_payload
    assert call_count == 3
