"""End-to-end tests of the generic CLI with the CrowdStrike connector factory."""

import json
import re
from typing import Any

import pytest
from conftest import (
    FIXTURES_DIR,
    FakeIndicatorsAPI,
    ScriptedClient,
    load_fixture,
    make_actor,
    make_indicator,
    ok,
)
from crowdstrike_indicators.factory import CrowdStrikeConnectorFactory

from shared.cli import main

FACTORY = "crowdstrike_indicators.factory:CrowdStrikeConnectorFactory"
SECRET = "s3cr3t-value-never-shown"
CLIENT_ID = "CROWDSTRIKE_CLIENT_ID"
CLIENT_SECRET = "CROWDSTRIKE_CLIENT_SECRET"
ATTACK_DATA = "CROWDSTRIKE_ATTACK_DATA"
CONFIGURATION_KEYS = (CLIENT_ID, CLIENT_SECRET, "CROWDSTRIKE_BASE_URL", ATTACK_DATA)
FROM = "2023-11-14T22:13:20Z"
ATTACK_FILE = FIXTURES_DIR / "attack_extract.json"
SAMPLE = load_fixture("indicators_sample.json")["resources"]
SAMPLE_DOMAIN = next(row for row in SAMPLE if row["type"] == "domain")
ATTACK_ROW = SAMPLE[0]
STEP_HEADER = re.compile(r"^Step (\d+) - (\w+)$", re.MULTILINE)


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    """Run each test in an empty directory with no configuration in the env."""
    monkeypatch.chdir(tmp_path)
    for key in CONFIGURATION_KEYS:
        monkeypatch.delenv(key, raising=False)
    return tmp_path


@pytest.fixture
def credentials(monkeypatch):
    monkeypatch.setenv(CLIENT_ID, "an-id")
    monkeypatch.setenv(CLIENT_SECRET, SECRET)


@pytest.fixture
def no_api(monkeypatch):
    """Set placeholder credentials, and fail the test if anything tries to
    build a CrowdStrike client."""
    monkeypatch.setenv(CLIENT_ID, "FAKE_CLIENT_ID")
    monkeypatch.setenv(CLIENT_SECRET, "FAKE_CLIENT_SECRET")

    def forbidden(factory: CrowdStrikeConnectorFactory) -> Any:
        raise AssertionError("transform must not build a CrowdStrike client")

    monkeypatch.setattr(CrowdStrikeConnectorFactory, "_create_client", forbidden)


def _install(monkeypatch, client: Any) -> None:
    monkeypatch.setattr(
        CrowdStrikeConnectorFactory, "_create_client", lambda self: client
    )


def run(*args: str) -> int:
    return main(["--factory", FACTORY, *args])


def extract(*args: str) -> int:
    return run(*args, "extract", "--from", FROM, "--max", "10")


def transform(isolated, row: dict[str, Any], *options: str) -> int:
    (isolated / "indicator.json").write_text(json.dumps(row))
    return run(*options, "transform", "indicator.json")


def steps(out: str) -> list[tuple[str, Any]]:
    """Split the ``transform`` output into ``(transformer, JSON value)`` pairs."""
    headers = list(STEP_HEADER.finditer(out))
    result = []
    for index, header in enumerate(headers, start=1):
        assert header.group(1) == str(index)
        end = headers[index].start() if index < len(headers) else len(out)
        result.append((header.group(2), json.loads(out[header.end() : end])))
    return result


# extract


def test_extract_prints_items_with_their_api_names(monkeypatch, credentials, capsys):
    salty = make_actor("SALTY SPIDER", actor_id=1, known_as="Salty")
    api = FakeIndicatorsAPI(
        [make_indicator(1, actors=["SALTYSPIDER"], foo="kept"), make_indicator(2)],
        actors=[salty],
    )
    _install(monkeypatch, api)

    assert extract() == 0

    first, second = json.loads(capsys.readouterr().out)
    assert set(first) == {"datetime", "item"}
    assert first["datetime"] == "2023-11-14T22:13:21+00:00"
    item = first["item"]
    assert item["id"] == "ioc-1"
    assert item["_marker"] == make_indicator(1)["_marker"]
    assert item["foo"] == "kept"
    assert "malware_families" in item  # unset fields are printed too
    assert [actor["name"] for actor in item["actor_objects_list"]] == ["SALTY SPIDER"]
    assert second["item"]["actor_objects_list"] == []


def test_api_error_shows_the_status(monkeypatch, credentials, capsys):
    response = {
        "status_code": 401,
        "body": {"errors": [{"code": 401, "message": "access denied"}]},
    }
    _install(monkeypatch, ScriptedClient([response]))

    assert extract() == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "401" in captured.err and "access denied" in captured.err


def test_invalid_indicator_names_the_indicator_and_the_field(
    monkeypatch, credentials, capsys
):
    bad = make_indicator(7, last_updated="never")
    _install(monkeypatch, ScriptedClient([ok({"resources": [bad]})]))

    assert extract() == 1

    err = capsys.readouterr().err
    assert "ioc-7" in err
    assert "last_updated" in err


def test_invalid_dataset_stops_extract(monkeypatch, credentials, capsys):
    monkeypatch.setenv(ATTACK_DATA, "missing.json")

    def forbidden(factory: CrowdStrikeConnectorFactory) -> Any:
        raise AssertionError("no request may be sent")

    monkeypatch.setattr(CrowdStrikeConnectorFactory, "_create_client", forbidden)

    assert extract() == 2
    assert ATTACK_DATA in capsys.readouterr().err


def test_secret_is_never_displayed_at_debug(monkeypatch, credentials, capsys):
    responses = [
        ok({"resources": [make_indicator(1)]}),
        {"status_code": 500, "body": {"errors": [{"message": "boom"}]}},
    ]
    _install(monkeypatch, ScriptedClient(responses))

    assert run("--log-level", "DEBUG", "extract", "--from", FROM, "--max", "5") == 1

    captured = capsys.readouterr()
    assert "Traceback" in captured.err
    assert SECRET not in captured.out
    assert SECRET not in captured.err


# Configuration


def test_missing_credentials_are_named(isolated, monkeypatch, capsys):
    monkeypatch.setattr(
        CrowdStrikeConnectorFactory,
        "_create_client",
        lambda self: pytest.fail("no client may be built"),
    )

    assert transform(isolated, SAMPLE_DOMAIN) == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert CLIENT_ID in captured.err and CLIENT_SECRET in captured.err


# transform


def test_transform_prints_the_three_steps(isolated, no_api, capsys):
    assert transform(isolated, SAMPLE_DOMAIN) == 0

    (first, stix), (second, bundle), (third, stix_bundle) = steps(
        capsys.readouterr().out
    )
    assert first == "CrowdStrikeIndicatorTransformer"
    assert stix["type"] == "indicator"
    assert stix["name"] == SAMPLE_DOMAIN["indicator"]
    assert stix["x_crowdstrike_marker"] == SAMPLE_DOMAIN["_marker"]
    assert second == "CrowdStrikeAddMalware"
    assert bundle["indicator"] == stix
    assert "ExampleFamily4" in [malware["name"] for malware in bundle["malware"]]
    assert bundle["attack_patterns"] == []
    assert {r["relationship_type"] for r in bundle["relationships"]} == {"indicates"}
    assert third == "MakeStixBundle"
    assert stix_bundle["type"] == "bundle"
    assert [o["id"] for o in stix_bundle["objects"]] == [
        stix["id"],
        *(m["id"] for m in bundle["malware"]),
        *(r["id"] for r in bundle["relationships"]),
    ]


def test_transform_without_malware(isolated, no_api, capsys):
    assert transform(isolated, {**SAMPLE_DOMAIN, "malware_families": []}) == 0

    printed = steps(capsys.readouterr().out)
    assert printed[1][1]["malware"] == []
    assert printed[1][1]["relationships"] == []
    assert [o["type"] for o in printed[-1][1]["objects"]] == ["indicator"]


def test_dataset_from_the_configuration_adds_a_step(
    isolated, monkeypatch, no_api, capsys
):
    monkeypatch.setenv(ATTACK_DATA, str(ATTACK_FILE))

    assert transform(isolated, ATTACK_ROW) == 0

    printed = steps(capsys.readouterr().out)
    assert [name for name, _ in printed] == [
        "CrowdStrikeIndicatorTransformer",
        "CrowdStrikeAddMalware",
        "CrowdStrikeAddAttackPatterns",
        "MakeStixBundle",
    ]
    patterns = printed[2][1]["attack_patterns"]
    assert patterns[0]["name"] == "Data from Local System"
    assert patterns[0]["id"] in [o["id"] for o in printed[3][1]["objects"]]


def test_unsupported_indicator_type_exits_1(isolated, no_api, capsys):
    raw = make_indicator(1, id="email_address_a@b.example", type="email_address")

    assert transform(isolated, raw) == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "email_address_a@b.example" in captured.err


def test_invalid_indicator_input_names_the_field(isolated, no_api, capsys):
    raw = {key: value for key, value in SAMPLE_DOMAIN.items() if key != "_marker"}

    assert transform(isolated, raw) == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "_marker" in captured.err


def test_extract_item_goes_through_transform(isolated, monkeypatch, capsys):
    monkeypatch.setenv(CLIENT_ID, "an-id")
    monkeypatch.setenv(CLIENT_SECRET, SECRET)
    _install(monkeypatch, FakeIndicatorsAPI([SAMPLE_DOMAIN]))
    assert extract() == 0
    item = json.loads(capsys.readouterr().out)[0]["item"]

    assert transform(isolated, item) == 0
    assert len(steps(capsys.readouterr().out)) == 3
