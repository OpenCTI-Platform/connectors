"""Tests against a de-identified sample of real CrowdStrike indicators.

``fixtures/indicators_sample.json`` holds one API page built from a month of
real indicators (2026-10-12 to 2026-11-13), keeping rows that cover every
case seen in that month. Timestamps and taxonomy values are real. Indicator
values, ids, marker suffixes, actor names, malware family names and CSD
report codes are replaced.
"""

import hashlib
import ipaddress
from datetime import datetime

import pytest
from conftest import ScriptedClient, build_extractor, load_fixture, ok
from crowdstrike_indicators.entities.models import CrowdStrikeIndicator

PAGE = load_fixture("indicators_sample.json")
ROWS = PAGE["resources"]
FROM = datetime.fromisoformat("2026-10-12T00:00:00+00:00")


@pytest.mark.parametrize(
    "raw", ROWS, ids=[f"{r['type']}-{i}" for i, r in enumerate(ROWS)]
)
def test_every_sample_row_validates(raw):
    model = CrowdStrikeIndicator.model_validate(raw)
    dumped = model.model_dump(mode="json", by_alias=True, exclude_unset=True)
    assert set(dumped) == set(raw)


def test_extractor_returns_the_whole_sample_in_order():
    client = ScriptedClient([ok(PAGE)])
    result = build_extractor(client).extract(FROM, 100)

    assert [indicator.id for _, indicator in result] == [r["id"] for r in ROWS]
    for dt, indicator in result:
        assert dt == indicator.last_updated  # marker second == last_updated
    datetimes = [dt for dt, _ in result]
    assert datetimes == sorted(datetimes)


def test_unverified_indicators_carry_no_confidence_label():
    unverified = [r for r in ROWS if r["malicious_confidence"] == "unverified"]
    assert unverified
    for row in unverified:
        assert not any(
            label["name"].startswith("MaliciousConfidence/") for label in row["labels"]
        )


# --- The sample must stay representative ------------------------------------


def test_sample_covers_the_cases_seen_in_real_data():
    values = lambda key: {v for r in ROWS for v in r[key]}  # noqa: E731
    label_prefixes = {lab["name"].split("/")[0] for r in ROWS for lab in r["labels"]}

    assert {r["type"] for r in ROWS} == {
        "url",
        "domain",
        "ip_address",
        "hash_md5",
        "hash_sha1",
        "hash_sha256",
    }
    assert {r["malicious_confidence"] for r in ROWS} == {
        "high",
        "medium",
        "low",
        "unverified",
    }
    assert values("kill_chains") == {
        "Reconnaissance",
        "Weaponization",
        "Delivery",
        "Exploitation",
        "Installation",
        "C2",
        "ActionOnObjectives",
    }
    assert values("domain_types") == {
        "Sinkholed",
        "LegitimateCompromised",
        "ActorControlled",
    }
    assert label_prefixes >= {
        "MaliciousConfidence",
        "Malware",
        "MitreATTCK",
        "ThreatType",
        "KillChain",
        "Status",
        "Actor",
        "DomainType",
        "CSD",
    }
    assert any(r["actors"] for r in ROWS)
    assert any(not r["malware_families"] for r in ROWS)
    seconds = [r["_marker"][:10] for r in ROWS]
    assert len(seconds) > len(set(seconds)), "two rows should share one second"


# --- The sample must never hold real intelligence ---------------------------

_HASHES = {
    "hash_md5": hashlib.md5,
    "hash_sha1": hashlib.sha1,
    "hash_sha256": hashlib.sha256,
}


def _is_synthetic_indicator(row: dict) -> bool:
    kind, value = row["type"], row["indicator"]
    if kind in _HASHES:
        return value in {
            _HASHES[kind](f"fixture-{n}".encode()).hexdigest() for n in range(1, 100)
        }
    if kind == "ip_address":
        return ipaddress.ip_address(value) in ipaddress.ip_network("192.0.2.0/24")
    if kind in ("url", "domain"):
        host = value.split("://", 1)[-1].split("/", 1)[0]
        return host.endswith(".example")
    return value.startswith("fixture-")


@pytest.mark.parametrize(
    "raw", ROWS, ids=[f"{r['type']}-{i}" for i, r in enumerate(ROWS)]
)
def test_sample_values_are_synthetic(raw):
    assert _is_synthetic_indicator(raw), raw["indicator"]
    assert raw["id"] == f"{raw['type']}_{raw['indicator']}"
    assert all(actor.startswith("EXAMPLE") for actor in raw["actors"])
    assert all(m.startswith("ExampleFamily") for m in raw["malware_families"])
    for label in raw["labels"]:
        prefix, _, value = label["name"].partition("/")
        if prefix == "Actor":
            assert value.startswith("EXAMPLE")
        elif prefix == "Malware":
            assert value.startswith("ExampleFamily")
        elif prefix == "CSD":
            assert value.startswith("CSA-0000")
