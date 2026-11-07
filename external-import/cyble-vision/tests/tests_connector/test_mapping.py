import copy
import json
from pathlib import Path

from connector.mappers import map_alert
from connectors_sdk.models import OrganizationAuthor, TLPMarking

AUTHOR = OrganizationAuthor(name="Cyble")
MARKING = TLPMarking(level="amber")
ALERT = json.loads(
    (Path(__file__).parents[1] / "fixtures" / "ssl_expiry.json").read_text()
)


def ids(alert):
    return [
        entity.to_stix2_object()["id"] for entity in map_alert(alert, AUTHOR, MARKING)
    ]


def test_ids_are_deterministic_across_runs():
    assert ids(copy.deepcopy(ALERT)) == ids(copy.deepcopy(ALERT))


def test_ids_survive_a_triage_change():
    triaged = copy.deepcopy(ALERT)
    triaged["status"] = "RESOLVED"
    triaged["assignee_id"] = "0b3d2f1e-0000-0000-0000-000000000000"
    triaged["updated_at"] = "2026-10-05T11:00:00.123+00:00"
    assert ids(triaged) == ids(copy.deepcopy(ALERT))


def test_unknown_service_falls_back_instead_of_failing():
    unknown = copy.deepcopy(ALERT)
    unknown["service"] = "some_future_module"
    unknown["data"] = {"data": {"title": "Something new", "unmapped_field": 123}}

    objects = [
        entity.to_stix2_object() for entity in map_alert(unknown, AUTHOR, MARKING)
    ]
    types = [obj["type"] for obj in objects]
    incident = next(obj for obj in objects if obj["type"] == "incident")
    note = next(obj for obj in objects if obj["type"] == "note")
    assert types == ["incident", "note"]
    assert "cyble:some_future_module" in incident["labels"]
    assert incident["external_references"][0]["external_id"] == unknown["id"]
    assert "unmapped_field" in note["content"]


def test_no_indicator_is_created_for_customer_owned_assets():
    types = {
        entity.to_stix2_object()["type"] for entity in map_alert(ALERT, AUTHOR, MARKING)
    }
    assert "indicator" not in types


def test_certificate_without_hashes_is_skipped():
    no_hash = copy.deepcopy(ALERT)
    no_hash["data"]["data"].pop("hash", None)
    no_hash["data"]["data"].pop("fingerprint_sha256", None)
    no_hash["data"]["data"].pop("detail", None)
    types = [
        entity.to_stix2_object()["type"]
        for entity in map_alert(no_hash, AUTHOR, MARKING)
    ]
    assert "x509-certificate" not in types
    assert "domain-name" in types


def test_hacktivism_includes_payload_and_relationships():
    alert = json.loads(
        (Path(__file__).parents[1] / "fixtures" / "hacktivism.json").read_text()
    )
    objects = [entity.to_stix2_object() for entity in map_alert(alert, AUTHOR, MARKING)]
    types = [obj["type"] for obj in objects]
    incident = next(obj for obj in objects if obj["type"] == "incident")

    assert "defacedWebsite" in incident["name"]
    assert "DimasHxR" in incident["description"]
    assert "203.0.113.13" in incident["description"]
    assert "url" in types
    assert "ipv4-addr" in types
    assert "intrusion-set" in types
    assert "note" in types
    assert types.count("relationship") >= 3
    note = next(obj for obj in objects if obj["type"] == "note")
    assert "DimasHxR" in note["content"]
    assert incident["id"] in note.get("object_refs", [])
