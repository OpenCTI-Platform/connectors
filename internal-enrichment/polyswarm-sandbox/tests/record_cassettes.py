#!/usr/bin/env python3
"""Record VCR cassettes for the polyswarm-sandbox test suite.

Usage:
    POLYSWARM_API_KEY=<key> python tests/record_cassettes.py

Records real PolySwarm API interactions as YAML cassettes that tests
replay without needing an API key. Authorization headers are scrubbed.
"""

import io
import os
import sys
import time

import vcr

# Add src/ to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "src"))

from polyswarm_api.api import PolyswarmAPI  # noqa: E402

API_KEY = os.environ.get("POLYSWARM_API_KEY", "")
if not API_KEY:
    print("ERROR: POLYSWARM_API_KEY not set")
    sys.exit(1)

CASSETTE_DIR = os.path.join(os.path.dirname(__file__), "cassettes")
os.makedirs(CASSETTE_DIR, exist_ok=True)

# EICAR — universally detected, good for scan tests
EICAR_CONTENT = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

# Real malware hashes with known sandbox results
WANNACRY_SHA256 = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
SAMPLE_SHA256 = "1e87db50d26931e239ffc34b4a1f59cdbcbf11f1bbb7c2007741adad05c62643"
RHADAMANTHYS_SHA256 = "7c34cccd3f58c144f561493c511a1a96a227cba58d4e1a737c4cd1b3a8a407ff"


def _scrub_request(request):
    """Remove Authorization header from recorded requests."""
    if "Authorization" in request.headers:
        request.headers["Authorization"] = "SCRUBBED"
    return request


my_vcr = vcr.VCR(
    cassette_library_dir=CASSETTE_DIR,
    record_mode="all",
    before_record_request=_scrub_request,
    decode_compressed_response=True,
    match_on=["method", "scheme", "host", "port", "path"],
)


def record_sandbox_providers():
    """Record sandbox provider listing."""
    print("Recording: sandbox_providers.yaml")
    api = PolyswarmAPI(key=API_KEY)
    with my_vcr.use_cassette("sandbox_providers.yaml"):
        providers = api.sandbox_providers()
        for p in providers:
            print(f"  Provider: {p.slug} ({p.name}), VMs: {p.vms}")
    print("  Done.")


def record_hash_search(name, sha256):
    """Record hash lookup via search()."""
    cassette = f"hash_search_{name}.yaml"
    print(f"Recording: {cassette}")
    api = PolyswarmAPI(key=API_KEY)
    with my_vcr.use_cassette(cassette):
        try:
            results = api.search(sha256)
            for r in results:
                print(
                    f"  Found: polyscore={r.polyscore}, assertions={len(r.assertions)}, family={getattr(r, 'metadata', None) and r.metadata.polyunite and r.metadata.polyunite.get('malware_family', '?')}"
                )
                break
        except Exception as e:
            print(f"  Result: {e}")
    print("  Done.")


def record_scan_submit():
    """Record EICAR scan submission + polling."""
    print("Recording: scan_eicar_submit.yaml")
    api = PolyswarmAPI(key=API_KEY)

    with my_vcr.use_cassette("scan_eicar_submit.yaml"):
        instance = api.submit(io.BytesIO(EICAR_CONTENT), artifact_name="eicar.com")
        print(f"  Submitted, instance_id: {instance.id}")

    print("Recording: scan_eicar_poll.yaml")
    with my_vcr.use_cassette("scan_eicar_poll.yaml"):
        for attempt in range(60):
            result = api.lookup(instance.id)
            if result.failed or result.window_closed:
                print(
                    f"  Complete after {attempt + 1} polls. failed={result.failed}, window_closed={result.window_closed}"
                )
                break
            time.sleep(5)
        else:
            print("  WARNING: did not complete")
    print("  Done.")


def record_sandbox_latest(name, sha256, provider="cape"):
    """Record latest sandbox task for a hash (pre-existing results)."""
    cassette = f"sandbox_latest_{name}.yaml"
    print(f"Recording: {cassette}")
    api = PolyswarmAPI(key=API_KEY)
    with my_vcr.use_cassette(cassette):
        try:
            task = api.sandbox_task_latest(sha256, provider)
            print(f"  id={task.id}, status={task.status}, sandbox={task.sandbox}")
            report = task.report
            if report and isinstance(report, dict):
                print(f"  report keys: {list(report.keys())[:10]}")
        except Exception as e:
            print(f"  No result: {e}")
    print("  Done.")


def record_sandbox_status(name, task_id):
    """Record sandbox task status check."""
    cassette = f"sandbox_status_{name}.yaml"
    print(f"Recording: {cassette}")
    api = PolyswarmAPI(key=API_KEY)
    with my_vcr.use_cassette(cassette):
        try:
            task = api.sandbox_task_status(task_id)
            print(f"  id={task.id}, status={task.status}")
        except Exception as e:
            print(f"  Error: {e}")
    print("  Done.")


def record_sandbox_submit_eicar():
    """Record EICAR sandbox submission (may fail quickly — that's a valid cassette)."""
    print("Recording: sandbox_eicar_submit.yaml")
    api = PolyswarmAPI(key=API_KEY)
    with my_vcr.use_cassette("sandbox_eicar_submit.yaml"):
        task = api.sandbox_file(
            io.BytesIO(EICAR_CONTENT),
            artifact_name="eicar.com",
            provider_slug="cape",
            vm_slug="win-10-build-19041",
            network_enabled=False,
        )
        print(f"  task_id: {task.id}, status: {task.status}")
    print("  Done.")
    return task.id


if __name__ == "__main__":
    print(f"Recording cassettes to: {CASSETTE_DIR}")
    print(f"API key: ******{API_KEY[-4:]}")
    print()

    recordings = [
        ("sandbox_providers", record_sandbox_providers),
        ("hash_search_eicar", lambda: record_hash_search("eicar", EICAR_SHA256)),
        (
            "hash_search_wannacry",
            lambda: record_hash_search("wannacry", WANNACRY_SHA256),
        ),
        ("hash_search_sample", lambda: record_hash_search("sample", SAMPLE_SHA256)),
        (
            "hash_search_rhadamanthys",
            lambda: record_hash_search("rhadamanthys", RHADAMANTHYS_SHA256),
        ),
        ("scan_submit", record_scan_submit),
        ("sandbox_submit_eicar", record_sandbox_submit_eicar),
        (
            "sandbox_latest_wannacry_cape",
            lambda: record_sandbox_latest("wannacry_cape", WANNACRY_SHA256, "cape"),
        ),
        (
            "sandbox_latest_wannacry_triage",
            lambda: record_sandbox_latest("wannacry_triage", WANNACRY_SHA256, "triage"),
        ),
        (
            "sandbox_latest_sample_cape",
            lambda: record_sandbox_latest("sample_cape", SAMPLE_SHA256, "cape"),
        ),
        (
            "sandbox_latest_rhadamanthys_cape",
            lambda: record_sandbox_latest(
                "rhadamanthys_cape", RHADAMANTHYS_SHA256, "cape"
            ),
        ),
        (
            "sandbox_latest_eicar_cape",
            lambda: record_sandbox_latest("eicar_cape", EICAR_SHA256, "cape"),
        ),
    ]

    for name, func in recordings:
        try:
            func()
        except Exception as e:
            print(f"  SKIPPED {name}: {e}")
        print()

    print("Done. Recorded cassettes:")
    for f in sorted(os.listdir(CASSETTE_DIR)):
        if f.endswith(".yaml"):
            size = os.path.getsize(os.path.join(CASSETTE_DIR, f))
            print(f"  {f} ({size} bytes)")
