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


def _stix(name):
    alert = json.loads((Path(__file__).parents[1] / "fixtures" / name).read_text())
    return [entity.to_stix2_object() for entity in map_alert(alert, AUTHOR, MARKING)]


def _related_ids(objects, source_id):
    return {
        obj["target_ref"]
        for obj in objects
        if obj["type"] == "relationship" and obj["source_ref"] == source_id
    }


def test_phishing_alert_has_an_incident_linked_to_its_indicator():
    objects = _stix("phishing.json")
    incident = next(obj for obj in objects if obj["type"] == "incident")
    indicator = next(obj for obj in objects if obj["type"] == "indicator")
    domain = next(obj for obj in objects if obj["type"] == "domain-name")
    note = next(obj for obj in objects if obj["type"] == "note")

    assert incident["incident_type"] == "phishing"
    assert {indicator["id"], domain["id"]} <= _related_ids(objects, incident["id"])
    assert note["object_refs"] == [incident["id"]]


def test_ip_risk_score_alert_has_an_incident():
    objects = _stix("ip_risk_score.json")
    incident = next(obj for obj in objects if obj["type"] == "incident")
    ip = next(obj for obj in objects if obj["type"] == "ipv4-addr")
    assert ip["id"] in _related_ids(objects, incident["id"])


def test_cve_alert_keeps_an_incident_and_links_the_shared_vulnerability():
    objects = _stix("new_vulnerability.json")
    incident = next(obj for obj in objects if obj["type"] == "incident")
    vulnerability = next(obj for obj in objects if obj["type"] == "vulnerability")

    assert vulnerability["id"] in _related_ids(objects, incident["id"])
    assert "description" not in vulnerability


def test_note_id_survives_a_severity_change():
    def note_id(alert):
        return next(
            entity.to_stix2_object()["id"]
            for entity in map_alert(alert, AUTHOR, MARKING)
            if entity.to_stix2_object()["type"] == "note"
        )

    triaged = copy.deepcopy(ALERT)
    triaged["user_severity"] = "CRITICAL"
    triaged["true_positive"] = not ALERT.get("true_positive")
    assert note_id(triaged) == note_id(copy.deepcopy(ALERT))


def test_list_valued_ip_becomes_an_ip_observable():
    objects = _stix("web_applications.json")
    ips = [obj["value"] for obj in objects if obj["type"] == "ipv4-addr"]
    domains = [obj["value"] for obj in objects if obj["type"] == "domain-name"]
    assert ips == ["203.0.113.18"]
    assert not any("[" in value for value in domains)


def test_leaked_credentials_url_comes_from_the_payload():
    urls = [
        obj["value"] for obj in _stix("leaked_credentials.json") if obj["type"] == "url"
    ]
    assert urls == ["https://host29.example1.com/storage/manual-book/ss.php"]


def test_tor_exposure_url_is_extracted():
    urls = [obj["value"] for obj in _stix("tor_links.json") if obj["type"] == "url"]
    assert urls == [
        "http://grqwuipwwfuu5mkyyqfea32kbkvwvxm36hau6bvkzoozchf57moj6yqd.onion/sources"
    ]
