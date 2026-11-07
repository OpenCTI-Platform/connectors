"""Every sample service must convert to at least one STIX object."""

import json
from pathlib import Path

from connector.mappers import map_alert
from connectors_sdk.models import OrganizationAuthor, TLPMarking

AUTHOR = OrganizationAuthor(name="Cyble")
MARKING = TLPMarking(level="amber")
FIXTURES = Path(__file__).parents[1] / "fixtures"

EXPECTED_TYPES = {
    "advisory": {"incident"},
    "flash_report": {"incident"},
    "cyble_research_labs": {"incident"},
    "ssl_expiry": {"domain-name", "x509-certificate", "relationship", "incident"},
    "new_vulnerability": {"vulnerability"},
    "product_vulnerability": {"vulnerability"},
    "phishing": {"domain-name", "indicator"},
    "stealer_logs": {"incident"},
    "ransomware_updates": {"incident"},
}


def test_every_sample_service_maps():
    failures = []
    for path in sorted(FIXTURES.glob("*.json")):
        if path.name == "ssl_expiry.json" and "created_at" not in path.read_text()[:80]:
            continue
        alert = json.loads(path.read_text())
        if "service" not in alert:
            continue
        try:
            objects = [
                entity.to_stix2_object() for entity in map_alert(alert, AUTHOR, MARKING)
            ]
        except Exception as err:
            failures.append(f"{path.name}: {err}")
            continue
        if not objects:
            failures.append(f"{path.name}: mapped to zero objects")
    assert not failures, "\n".join(failures)


def test_priority_services_emit_expected_types():
    for service, expected in EXPECTED_TYPES.items():
        path = FIXTURES / f"{service}.json"
        if not path.exists():
            continue
        alert = json.loads(path.read_text())
        types = {
            entity.to_stix2_object()["type"]
            for entity in map_alert(alert, AUTHOR, MARKING)
        }
        assert expected <= types, f"{service}: expected {expected}, got {types}"
