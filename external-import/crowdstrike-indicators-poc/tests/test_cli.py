"""Tests for the command-line entry point."""

import io
import json
from datetime import UTC, datetime
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
from crowdstrike_indicators.entities.errors import IndicatorConversionError
from crowdstrike_indicators.factory import (
    DEFAULT_BASE_URL,
    CrowdStrikeConnectorFactory,
)
from crowdstrike_indicators.transform.transformer import CrowdStrikeIndicatorTransformer
from crowdstrike_indicators_cli import cli

SECRET = "s3cr3t-value-never-shown"
CLIENT_ID = "CROWDSTRIKE_CLIENT_ID"
CLIENT_SECRET = "CROWDSTRIKE_CLIENT_SECRET"
BASE_URL = "CROWDSTRIKE_BASE_URL"
ATTACK_DATA = "CROWDSTRIKE_ATTACK_DATA"
CONFIGURATION_KEYS = (CLIENT_ID, CLIENT_SECRET, BASE_URL, ATTACK_DATA)
FROM = "2023-11-14T22:13:20Z"


class ClientFactory:
    """Stands in for the factory's API client creation and records the
    settings each client was built with."""

    def __init__(self, client: Any) -> None:
        self.client = client
        self.calls: list[tuple[str, str, str]] = []

    def __call__(self, client_id: str, client_secret: str, base_url: str) -> Any:
        self.calls.append((client_id, client_secret, base_url))
        return self.client


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    """Run each test in an empty directory with no configuration in the env."""
    monkeypatch.chdir(tmp_path)
    for key in CONFIGURATION_KEYS:
        monkeypatch.delenv(key, raising=False)
    return tmp_path


def _write_env(path, **values: str) -> None:
    path.write_text("".join(f"{k}={v}\n" for k, v in values.items()))


@pytest.fixture
def credentials(isolated):
    _write_env(
        isolated / ".env",
        CROWDSTRIKE_CLIENT_ID="file-id",
        CROWDSTRIKE_CLIENT_SECRET=SECRET,
    )


def _install(monkeypatch, client: Any) -> ClientFactory:
    recorder = ClientFactory(client)

    def create_client(factory: CrowdStrikeConnectorFactory) -> Any:
        settings = factory.settings
        return recorder(
            settings.client_id.get_secret_value(),
            settings.client_secret.get_secret_value(),
            settings.base_url,
        )

    monkeypatch.setattr(CrowdStrikeConnectorFactory, "_create_client", create_client)
    return recorder


def _forbid_client(monkeypatch) -> None:
    def forbidden(factory: CrowdStrikeConnectorFactory) -> Any:
        raise AssertionError("transform must not build a CrowdStrike client")

    monkeypatch.setattr(CrowdStrikeConnectorFactory, "_create_client", forbidden)


def _run(*args: str) -> int:
    return cli.main(list(args))


def _extract(*args: str) -> int:
    return _run("extract", *args)


# --- Configuration -----------------------------------------------------------


def test_credentials_come_from_the_env_file(monkeypatch, credentials):
    factory = _install(monkeypatch, FakeIndicatorsAPI([]))
    assert _extract("--from", FROM, "--max", "5") == 0
    assert factory.calls == [("file-id", SECRET, DEFAULT_BASE_URL)]


def test_environment_overrides_the_env_file(monkeypatch, credentials):
    monkeypatch.setenv(CLIENT_ID, "env-id")
    monkeypatch.setenv(BASE_URL, "https://api.eu-1.crowdstrike.com")
    factory = _install(monkeypatch, FakeIndicatorsAPI([]))

    assert _extract("--from", FROM, "--max", "5") == 0
    assert factory.calls == [("env-id", SECRET, "https://api.eu-1.crowdstrike.com")]


def test_explicit_env_file(monkeypatch, isolated):
    _write_env(
        isolated / "custom.env",
        CROWDSTRIKE_CLIENT_ID="custom-id",
        CROWDSTRIKE_CLIENT_SECRET=SECRET,
        CROWDSTRIKE_BASE_URL="us2",
    )
    factory = _install(monkeypatch, FakeIndicatorsAPI([]))

    assert _extract("--from", FROM, "--max", "5", "--env-file", "custom.env") == 0
    assert factory.calls == [("custom-id", SECRET, "us2")]


def test_credentials_from_environment_only(monkeypatch):
    monkeypatch.setenv(CLIENT_ID, "env-id")
    monkeypatch.setenv(CLIENT_SECRET, SECRET)
    factory = _install(monkeypatch, FakeIndicatorsAPI([]))
    assert _extract("--from", FROM, "--max", "5") == 0
    assert factory.calls == [("env-id", SECRET, DEFAULT_BASE_URL)]


def test_missing_secret_exits_2_without_building_a_client(monkeypatch, capsys):
    monkeypatch.setenv(CLIENT_ID, "env-id")
    factory = _install(monkeypatch, FakeIndicatorsAPI([]))

    assert _extract("--from", FROM, "--max", "5") == 2

    assert factory.calls == []
    captured = capsys.readouterr()
    assert "CROWDSTRIKE_CLIENT_SECRET" in captured.err
    assert captured.out == ""


def test_missing_explicit_env_file_is_a_usage_error(monkeypatch, capsys):
    factory = _install(monkeypatch, FakeIndicatorsAPI([]))
    with pytest.raises(SystemExit) as caught:
        _extract("--from", FROM, "--max", "5", "--env-file", "nope.env")
    assert caught.value.code == 2
    assert factory.calls == []
    assert "nope.env" in capsys.readouterr().err


def test_invalid_dataset_path_stops_extract(monkeypatch, credentials, capsys):
    monkeypatch.setenv(ATTACK_DATA, "missing.json")
    factory = _install(monkeypatch, FakeIndicatorsAPI([]))

    assert _extract("--from", FROM, "--max", "5") == 2

    assert factory.calls == []
    captured = capsys.readouterr()
    assert ATTACK_DATA in captured.err
    assert captured.out == ""


def test_configuration_errors_name_every_parameter(monkeypatch, capsys):
    factory = _install(monkeypatch, FakeIndicatorsAPI([]))

    assert _extract("--from", FROM, "--max", "5") == 2

    assert factory.calls == []
    err = capsys.readouterr().err
    assert CLIENT_ID in err and CLIENT_SECRET in err


# --- Arguments ---------------------------------------------------------------


@pytest.mark.parametrize("value", ["0", "-3", "ten"])
def test_invalid_max_exits_2_without_contacting_crowdstrike(
    monkeypatch, credentials, value
):
    factory = _install(monkeypatch, FakeIndicatorsAPI([]))
    with pytest.raises(SystemExit) as caught:
        _extract("--from", FROM, "--max", value)
    assert caught.value.code == 2
    assert factory.calls == []


def test_invalid_from_exits_2(monkeypatch, credentials):
    factory = _install(monkeypatch, FakeIndicatorsAPI([]))
    with pytest.raises(SystemExit) as caught:
        _extract("--from", "yesterday", "--max", "5")
    assert caught.value.code == 2
    assert factory.calls == []


@pytest.mark.parametrize("missing", ["--from", "--max"])
def test_required_arguments(monkeypatch, credentials, missing):
    _install(monkeypatch, FakeIndicatorsAPI([]))
    args = {"--from": FROM, "--max": "5"}
    del args[missing]
    with pytest.raises(SystemExit) as caught:
        _extract(*[part for item in args.items() for part in item])
    assert caught.value.code == 2


def test_naive_from_is_read_as_utc(monkeypatch, credentials):
    api = FakeIndicatorsAPI([])
    _install(monkeypatch, api)

    assert _extract("--from", "2026-11-01T00:00:00", "--max", "5") == 0

    expected = int(datetime(2026, 11, 1, tzinfo=UTC).timestamp())
    assert api.calls[0]["filter"] == f"_marker:>='{expected}'"


def test_from_with_an_offset_is_kept(monkeypatch, credentials):
    api = FakeIndicatorsAPI([])
    _install(monkeypatch, api)

    assert _extract("--from", "2023-11-14T23:13:25+01:00", "--max", "5") == 0
    assert api.calls[0]["filter"] == "_marker:>='1700000005'"


# --- Output ------------------------------------------------------------------


def test_successful_run_prints_a_json_array(monkeypatch, credentials, capsys):
    api = FakeIndicatorsAPI(
        [make_indicator(1, foo="kept"), make_indicator(2), make_indicator(3)]
    )
    _install(monkeypatch, api)

    assert _extract("--from", FROM, "--max", "2") == 0

    output = json.loads(capsys.readouterr().out)
    assert [set(item) for item in output] == [{"datetime", "indicator"}] * 2
    assert [item["indicator"]["id"] for item in output] == ["ioc-1", "ioc-2"]
    first = output[0]
    assert first["datetime"] == "2023-11-14T22:13:21+00:00"
    assert first["indicator"]["_marker"] == make_indicator(1)["_marker"]
    assert first["indicator"]["foo"] == "kept"
    assert "marker" not in first["indicator"]
    assert "malware_families" not in first["indicator"]


def test_nothing_new_prints_an_empty_array(monkeypatch, credentials, capsys):
    _install(monkeypatch, FakeIndicatorsAPI([]))
    assert _extract("--from", FROM, "--max", "5") == 0
    assert json.loads(capsys.readouterr().out) == []


def test_logs_go_to_standard_error_only(monkeypatch, credentials, capsys):
    _install(monkeypatch, FakeIndicatorsAPI([make_indicator(1)]))
    assert _extract("--from", FROM, "--max", "5", "--log-level", "DEBUG") == 0
    captured = capsys.readouterr()
    json.loads(captured.out)  # standard output is pure JSON
    assert "Fetched indicator page" in captured.err


# --- Output file -------------------------------------------------------------


def test_output_file_holds_what_standard_output_would(
    monkeypatch, credentials, isolated, capsys
):
    indicators = [make_indicator(i) for i in range(2)]
    _install(monkeypatch, FakeIndicatorsAPI(indicators))
    assert _extract("--from", FROM, "--max", "10") == 0
    printed = capsys.readouterr().out

    _install(monkeypatch, FakeIndicatorsAPI(indicators))
    output = isolated / "out" / "result.json"
    assert _extract("--from", FROM, "--max", "10", "--output", str(output)) == 0

    assert capsys.readouterr().out == ""
    assert output.read_text() == printed
    assert [item["indicator"]["id"] for item in json.loads(printed)] == [
        "ioc-0",
        "ioc-1",
    ]


def test_no_output_file_on_failure(monkeypatch, credentials, isolated, capsys):
    page_1 = {"resources": [make_indicator(1)]}
    page_2 = {"resources": [make_indicator(1), make_indicator(2, _marker="bad")]}
    _install(monkeypatch, ScriptedClient([ok(page_1), ok(page_2)]))

    output = isolated / "result.json"
    assert _extract("--from", FROM, "--max", "10", "--output", str(output)) == 1

    assert not output.exists()
    assert capsys.readouterr().out == ""


def test_no_file_without_the_option(monkeypatch, credentials, isolated):
    _install(monkeypatch, FakeIndicatorsAPI([make_indicator(1)]))
    assert _extract("--from", FROM, "--max", "10") == 0
    assert [p.name for p in isolated.iterdir()] == [".env"]


# --- Failures ----------------------------------------------------------------


def test_api_error_exits_1_and_shows_the_status(monkeypatch, credentials, capsys):
    response = {
        "status_code": 401,
        "body": {"errors": [{"code": 401, "message": "access denied"}]},
    }
    _install(monkeypatch, ScriptedClient([response]))

    assert _extract("--from", FROM, "--max", "5") == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "401" in captured.err and "access denied" in captured.err


def test_validation_error_exits_1_with_id_errors_and_raw(
    monkeypatch, credentials, capsys
):
    bad = make_indicator(7, last_updated="never")
    _install(monkeypatch, ScriptedClient([ok({"resources": [bad]})]))

    assert _extract("--from", FROM, "--max", "5") == 1

    err = capsys.readouterr().err
    assert "ioc-7" in err
    assert "last_updated" in err
    assert '"never"' in err  # the raw indicator, as JSON


def test_secret_is_never_displayed(monkeypatch, credentials, capsys, isolated):
    responses = [
        ok({"resources": [make_indicator(1)]}),
        {"status_code": 500, "body": {"errors": [{"message": "boom"}]}},
    ]
    _install(monkeypatch, ScriptedClient(responses))

    args = ["--from", FROM, "--max", "5", "--log-level", "DEBUG"]
    assert _extract(*args) == 1

    captured = capsys.readouterr()
    assert SECRET not in captured.out
    assert SECRET not in captured.err


# --- Subcommands -------------------------------------------------------------


def test_no_subcommand_exits_2_with_the_usage(capsys):
    with pytest.raises(SystemExit) as caught:
        _run("--from", FROM, "--max", "5")

    assert caught.value.code == 2
    assert "usage:" in capsys.readouterr().err


def test_unknown_subcommand_exits_2_with_the_usage(capsys):
    with pytest.raises(SystemExit) as caught:
        _run("load")

    assert caught.value.code == 2
    assert "usage:" in capsys.readouterr().err


def test_help_names_the_console_command(capsys):
    with pytest.raises(SystemExit) as caught:
        _run("--help")

    assert caught.value.code == 0
    assert capsys.readouterr().out.startswith("usage: crowdstrike-indicators-cli")


# --- transform ---------------------------------------------------------------

SAMPLE_DOMAIN = next(
    row
    for row in load_fixture("indicators_sample.json")["resources"]
    if row["type"] == "domain"
)


@pytest.fixture
def no_api(monkeypatch):
    """Set placeholder credentials, and fail the test if anything tries to
    build a CrowdStrike client."""
    monkeypatch.setenv(CLIENT_ID, "FAKE_CLIENT_ID")
    monkeypatch.setenv(CLIENT_SECRET, "FAKE_CLIENT_SECRET")
    _forbid_client(monkeypatch)


def _transform_steps(capsys) -> list[dict[str, Any]]:
    return json.loads(capsys.readouterr().out)


def _transform_output(capsys) -> dict[str, Any]:
    """Output of step 1, the STIX indicator."""
    return _transform_steps(capsys)[0]["output"]


def _assert_stix_of_sample(stix: dict[str, Any]) -> None:
    assert stix["type"] == "indicator"
    assert stix["name"] == SAMPLE_DOMAIN["indicator"]
    assert stix["external_references"] == [
        {"source_name": "CrowdStrike", "external_id": SAMPLE_DOMAIN["id"]}
    ]
    assert "x_crowdstrike_id" not in stix
    assert stix["x_crowdstrike_marker"] == SAMPLE_DOMAIN["_marker"]


def test_transform_reads_a_file(isolated, no_api, capsys):
    (isolated / "indicator.json").write_text(json.dumps(SAMPLE_DOMAIN))

    assert _run("transform", "indicator.json") == 0

    _assert_stix_of_sample(_transform_output(capsys))


def test_transform_reads_standard_input(monkeypatch, no_api, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(SAMPLE_DOMAIN)))

    assert _run("transform") == 0

    _assert_stix_of_sample(_transform_output(capsys))


def test_transform_with_placeholder_credentials(isolated, no_api, capsys):
    assert not (isolated / ".env").exists()
    (isolated / "indicator.json").write_text(json.dumps(SAMPLE_DOMAIN))

    assert _run("transform", "indicator.json") == 0


def test_transform_without_credentials_exits_2(monkeypatch, isolated, capsys):
    _forbid_client(monkeypatch)
    (isolated / "indicator.json").write_text(json.dumps(SAMPLE_DOMAIN))

    assert _run("transform", "indicator.json") == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert CLIENT_ID in captured.err and CLIENT_SECRET in captured.err


def test_transform_reads_the_env_file(monkeypatch, credentials, isolated, capsys):
    _forbid_client(monkeypatch)
    (isolated / "indicator.json").write_text(json.dumps(SAMPLE_DOMAIN))

    assert _run("transform", "indicator.json") == 0


def test_transform_missing_env_file_is_a_usage_error(isolated, no_api, capsys):
    (isolated / "indicator.json").write_text(json.dumps(SAMPLE_DOMAIN))

    with pytest.raises(SystemExit) as caught:
        _run("transform", "indicator.json", "--env-file", "nope.env")

    assert caught.value.code == 2
    assert "nope.env" in capsys.readouterr().err


def test_transform_logs_go_to_standard_error_only(isolated, no_api, capsys):
    (isolated / "indicator.json").write_text(json.dumps(SAMPLE_DOMAIN))

    assert _run("transform", "indicator.json", "--log-level", "DEBUG") == 0

    captured = capsys.readouterr()
    json.loads(captured.out)
    assert "Transformed indicator" in captured.err


def test_transform_missing_file_exits_2(no_api, capsys):
    with pytest.raises(SystemExit) as caught:
        _run("transform", "missing.json")

    assert caught.value.code == 2
    assert "missing.json" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("{not json", "input is not valid JSON"),
        (json.dumps([SAMPLE_DOMAIN]), "expected one JSON object, got array"),
    ],
)
def test_transform_unreadable_input_exits_1(isolated, no_api, capsys, content, message):
    (isolated / "indicator.json").write_text(content)

    assert _run("transform", "indicator.json") == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert message in captured.err


def test_transform_invalid_indicator_exits_1_with_id_errors_and_raw(
    isolated, no_api, capsys
):
    raw = {key: value for key, value in SAMPLE_DOMAIN.items() if key != "_marker"}
    (isolated / "indicator.json").write_text(json.dumps(raw))

    assert _run("transform", "indicator.json") == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert SAMPLE_DOMAIN["id"] in captured.err
    assert "_marker" in captured.err
    assert "raw indicator:" in captured.err


def test_transform_unsupported_type_exits_1(isolated, no_api, capsys):
    raw = make_indicator(1, id="email_address_a@b.example", type="email_address")
    (isolated / "indicator.json").write_text(json.dumps(raw))

    assert _run("transform", "indicator.json") == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "email_address_a@b.example" in captured.err
    assert "'email_address'" in captured.err


# --- transform runs the chain ------------------------------------------------


def test_transform_prints_every_step(isolated, no_api, capsys):
    (isolated / "indicator.json").write_text(json.dumps(SAMPLE_DOMAIN))

    assert _run("transform", "indicator.json") == 0

    first, second, third = _transform_steps(capsys)
    assert first["step"] == 1
    assert first["transformer"] == "CrowdStrikeIndicatorTransformer"
    _assert_stix_of_sample(first["output"])
    assert second["step"] == 2
    assert second["transformer"] == "CrowdStrikeAddMalware"
    bundle = second["output"]
    assert bundle["indicator"] == first["output"]
    assert [m["name"] for m in bundle["malware"]] == SAMPLE_DOMAIN["malware_families"]
    assert bundle["attack_patterns"] == []
    assert [r["relationship_type"] for r in bundle["relationships"]] == [
        "indicates"
    ] * len(SAMPLE_DOMAIN["malware_families"])
    assert [r["target_ref"] for r in bundle["relationships"]] == [
        m["id"] for m in bundle["malware"]
    ]
    assert third["step"] == 3
    assert third["transformer"] == "MakeStixBundle"
    stix_bundle = third["output"]
    assert stix_bundle["type"] == "bundle"
    assert [o["id"] for o in stix_bundle["objects"]] == [
        bundle["indicator"]["id"],
        *(m["id"] for m in bundle["malware"]),
        *(r["id"] for r in bundle["relationships"]),
    ]


def test_transform_without_malware_prints_empty_lists(isolated, no_api, capsys):
    raw = {**SAMPLE_DOMAIN, "malware_families": []}
    (isolated / "indicator.json").write_text(json.dumps(raw))

    assert _run("transform", "indicator.json") == 0

    steps = _transform_steps(capsys)
    bundle = steps[1]["output"]
    assert bundle["malware"] == []
    assert bundle["relationships"] == []
    assert [o["type"] for o in steps[-1]["output"]["objects"]] == ["indicator"]


def test_transform_later_step_failure_prints_nothing(
    monkeypatch, isolated, no_api, capsys
):
    class FailingStep:
        def convert(self, item: Any) -> Any:
            raise IndicatorConversionError(SAMPLE_DOMAIN["id"], "forced failure")

    monkeypatch.setattr(
        CrowdStrikeConnectorFactory,
        "create_transformers",
        lambda self: [CrowdStrikeIndicatorTransformer(), FailingStep()],
    )
    (isolated / "indicator.json").write_text(json.dumps(SAMPLE_DOMAIN))

    assert _run("transform", "indicator.json") == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "forced failure" in captured.err
    assert SAMPLE_DOMAIN["id"] in captured.err


# --- transform --attack-data -------------------------------------------------

ATTACK_FILE = FIXTURES_DIR / "attack_extract.json"
ATTACK_ROW = load_fixture("indicators_sample.json")["resources"][0]


def test_transform_with_attack_data_runs_four_steps(isolated, no_api, capsys):
    (isolated / "indicator.json").write_text(json.dumps(ATTACK_ROW))

    code = _run("transform", "indicator.json", "--attack-data", str(ATTACK_FILE))

    assert code == 0
    steps = _transform_steps(capsys)
    assert [s["transformer"] for s in steps] == [
        "CrowdStrikeIndicatorTransformer",
        "CrowdStrikeAddMalware",
        "CrowdStrikeAddAttackPatterns",
        "MakeStixBundle",
    ]
    third = steps[2]
    assert third["step"] == 3
    patterns = third["output"]["attack_patterns"]
    assert patterns[0]["id"] == "attack-pattern--3c4a2599-71ee-4405-ba1e-0e28414b4bc5"
    assert patterns[0]["name"] == "Data from Local System"
    assert all(
        set(pattern)
        <= {"type", "spec_version", "id", "created", "modified", "name"}
        | {"external_references"}
        for pattern in patterns
    )
    relationships = third["output"]["relationships"]
    assert relationships[-len(patterns) :][0]["target_ref"] == patterns[0]["id"]
    assert steps[1]["output"]["attack_patterns"] == []
    fourth = steps[3]
    assert fourth["step"] == 4
    assert patterns[0]["id"] in [o["id"] for o in fourth["output"]["objects"]]


def test_transform_without_attack_data_runs_three_steps(isolated, no_api, capsys):
    (isolated / "indicator.json").write_text(json.dumps(ATTACK_ROW))

    assert _run("transform", "indicator.json") == 0

    steps = _transform_steps(capsys)
    assert [s["transformer"] for s in steps] == [
        "CrowdStrikeIndicatorTransformer",
        "CrowdStrikeAddMalware",
        "MakeStixBundle",
    ]


def test_transform_takes_the_dataset_from_the_configuration(
    monkeypatch, isolated, no_api, capsys
):
    monkeypatch.setenv(ATTACK_DATA, str(ATTACK_FILE))
    (isolated / "indicator.json").write_text(json.dumps(ATTACK_ROW))

    assert _run("transform", "indicator.json") == 0

    steps = _transform_steps(capsys)
    assert steps[2]["transformer"] == "CrowdStrikeAddAttackPatterns"
    assert steps[2]["output"]["attack_patterns"] != []


def test_attack_data_option_overrides_the_configuration(
    monkeypatch, isolated, no_api, capsys
):
    (isolated / "empty-attack.json").write_text(
        json.dumps({"type": "bundle", "id": "bundle--0", "objects": []})
    )
    monkeypatch.setenv(ATTACK_DATA, "empty-attack.json")
    (isolated / "indicator.json").write_text(json.dumps(ATTACK_ROW))

    code = _run("transform", "indicator.json", "--attack-data", str(ATTACK_FILE))

    assert code == 0
    steps = _transform_steps(capsys)
    assert steps[2]["transformer"] == "CrowdStrikeAddAttackPatterns"
    assert steps[2]["output"]["attack_patterns"] != []


def test_transform_missing_attack_data_exits_2(isolated, no_api, capsys):
    (isolated / "indicator.json").write_text(json.dumps(ATTACK_ROW))

    with pytest.raises(SystemExit) as caught:
        _run("transform", "indicator.json", "--attack-data", "missing.json")

    assert caught.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "missing.json" in captured.err


def test_transform_invalid_attack_data_exits_2(isolated, no_api, capsys):
    (isolated / "indicator.json").write_text(json.dumps(ATTACK_ROW))
    (isolated / "attack.json").write_text("[]")

    assert _run("transform", "indicator.json", "--attack-data", "attack.json") == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "attack.json" in captured.err


# --- Resolved actors ---------------------------------------------------------

SALTY = make_actor("SALTY SPIDER", actor_id=1, known_as="Salty")


def _salty_api() -> FakeIndicatorsAPI:
    return FakeIndicatorsAPI(
        [make_indicator(1, actors=["SALTYSPIDER"]), make_indicator(2)], actors=[SALTY]
    )


def test_extract_output_holds_the_resolved_actors(monkeypatch, credentials, capsys):
    api = _salty_api()
    _install(monkeypatch, api)

    assert _extract("--from", FROM, "--max", "10") == 0

    first, second = json.loads(capsys.readouterr().out)
    assert first["indicator"]["actor_objects_list"] == [SALTY]
    assert second["indicator"]["actor_objects_list"] == []
    assert api.tokens == ["SALTYSPIDER"]


def test_transform_takes_an_element_of_the_extract_output(
    monkeypatch, credentials, isolated, capsys
):
    _install(monkeypatch, _salty_api())
    assert _extract("--from", FROM, "--max", "1") == 0
    [element] = json.loads(capsys.readouterr().out)
    (isolated / "indicator.json").write_text(json.dumps(element["indicator"]))

    _forbid_client(monkeypatch)
    assert _run("transform", "indicator.json") == 0

    stix = _transform_output(capsys)
    assert stix["x_crowdstrike_actor_objects_list"] == [SALTY]
    assert "x_crowdstrike_extra" not in stix


def test_transform_takes_a_raw_row_without_actor_objects(isolated, no_api, capsys):
    raw = make_indicator(1, actors=["SALTYSPIDER"])
    (isolated / "indicator.json").write_text(json.dumps(raw))

    assert _run("transform", "indicator.json") == 0

    stix = _transform_output(capsys)
    assert stix["x_crowdstrike_actors"] == ["SALTYSPIDER"]
    assert "x_crowdstrike_actor_objects_list" not in stix


def test_transform_rejects_an_invalid_actor_object(isolated, no_api, capsys):
    raw = {**make_indicator(1), "actor_objects_list": [{"id": 1}]}
    (isolated / "indicator.json").write_text(json.dumps(raw))

    assert _run("transform", "indicator.json") == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "ioc-1" in captured.err and "actor_objects_list" in captured.err
