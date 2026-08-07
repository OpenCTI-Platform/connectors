import sys
from pathlib import Path

# Make src/ importable so test modules can use `from connector.* import ...`
_src_root = Path(__file__).resolve().parent.parent / "src"
if str(_src_root) not in sys.path:
    sys.path.insert(0, str(_src_root))


# ---------------------------------------------------------------------------
# Shared fixtures and sample data
# ---------------------------------------------------------------------------

SAMPLE_STIX_BUNDLE = {
    "id": "bundle--185f682b-486a-42e5-9860-203be3a1052f",
    "type": "bundle",
    "objects": [
        {
            "id": "report--3b6020a6-153f-4684-b25b-c5fe7381a903",
            "type": "report",
            "name": "Test Report",
            "spec_version": "2.1",
            "created": "2026-04-09T19:09:39.993767Z",
            "modified": "2026-04-09T19:09:39.993767Z",
            "published": "2026-04-09T19:09:39.993767Z",
            "report_types": ["threat-report"],
            "labels": ["threat-landscape-report"],
            "object_refs": ["threat-actor--9400cbac-7438-4957-b626-1e32c49a1d06"],
            "created_by_ref": "identity--2f63f8e1-a880-4e9f-89e6-bd86c1d5939e",
        },
        {
            "id": "threat-actor--9400cbac-7438-4957-b626-1e32c49a1d06",
            "type": "threat-actor",
            "name": "Storm-2755",
            "spec_version": "2.1",
            "created": "2026-04-09T19:05:03.760101Z",
            "modified": "2026-04-09T19:05:03.760101Z",
        },
        {
            "id": "identity--2f63f8e1-a880-4e9f-89e6-bd86c1d5939e",
            "type": "identity",
            "name": "threatlandscape.io",
            "spec_version": "2.1",
            "identity_class": "organization",
            "created": "2025-06-23T12:00:00.000Z",
            "modified": "2025-06-23T12:00:00.000Z",
        },
    ],
}

SAMPLE_API_ROWS = [
    {"seq_id": 1001, "stix_bundle": SAMPLE_STIX_BUNDLE},
    {
        "seq_id": 1002,
        "stix_bundle": {
            "id": "bundle--aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "type": "bundle",
            "objects": [
                {
                    "id": "malware--11111111-2222-3333-4444-555555555555",
                    "type": "malware",
                    "name": "TestMalware",
                    "spec_version": "2.1",
                    "is_family": True,
                    "created": "2026-04-10T00:00:00Z",
                    "modified": "2026-04-10T00:00:00Z",
                }
            ],
        },
    },
]
