import json
from pathlib import Path

from connector.mappers import map_alert
from connector.mappers.engine_reports import map_advisory, map_newsfeed, map_newsflash
from connectors_sdk.models import OrganizationAuthor, TLPMarking
from cyble_client.engine_dates import next_page, parse_engine_datetime

AUTHOR = OrganizationAuthor(name="Cyble")
MARKING = TLPMarking(level="amber")
FIXTURES = Path(__file__).parents[1] / "fixtures"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def test_advisory_uses_numeric_id_and_document_tlp():
    objects = [
        entity.to_stix2_object()
        for entity in map_advisory(_load("engine_advisory.json"), AUTHOR, MARKING)
    ]
    report = next(obj for obj in objects if obj["type"] == "report")
    assert report["name"].startswith("Malicious Firefox")
    assert report["external_references"][0]["external_id"] == "advisory:8082"
    assert "cyble:engine:advisory" in report["labels"]
    assert report["object_marking_refs"][0] != MARKING.to_stix2_object()["id"]


def test_newsfeed_uses_post_url_and_actor():
    objects = [
        entity.to_stix2_object()
        for entity in map_newsfeed(_load("engine_newsfeed.json"), AUTHOR, MARKING)
    ]
    types = {obj["type"] for obj in objects}
    report = next(obj for obj in objects if obj["type"] == "report")
    assert "url" in types
    assert "intrusion-set" in types
    assert report["external_references"][0]["external_id"].startswith(
        "https://www.darkreading.com"
    )
    assert "cyble:engine:newsfeed" in report["labels"]


def test_newsflash_links_actor_org_and_domain():
    objects = [
        entity.to_stix2_object()
        for entity in map_newsflash(_load("engine_newsflash.json"), AUTHOR, MARKING)
    ]
    types = {obj["type"] for obj in objects}
    report = next(obj for obj in objects if obj["type"] == "report")
    assert "intrusion-set" in types
    assert "identity" in types
    assert "domain-name" in types
    assert "cyble:engine:newsflash" in report["labels"]
    assert any(
        ref.get("url", "").endswith(".pdf") for ref in report["external_references"]
    )


def test_alert_advisory_is_a_notice_incident_not_a_report():
    alert = json.loads((FIXTURES / "advisory.json").read_text())
    types = {
        entity.to_stix2_object()["type"] for entity in map_alert(alert, AUTHOR, MARKING)
    }
    assert "incident" in types
    assert "report" not in types


def test_mongo_date_and_pagination_helpers():
    parsed = parse_engine_datetime({"$date": {"$numberLong": "1752529395000"}})
    assert parsed is not None
    assert parsed.year == 2025
    assert next_page(1, 2, 6) == 2
    assert next_page(3, 2, 6) is None
    assert next_page(1, 10, 0) is None
