"""Tests for the command-line entry point."""

import io
import json
from datetime import UTC, datetime
from typing import Any

import pytest
from conftest import (
    FakeIndicatorsAPI,
    ScriptedClient,
    load_fixture,
    make_indicator,
    ok,
)
from crowdstrike_indicators import cli

SECRET = "s3cr3t-value-never-shown"
CREDENTIAL_KEYS = (cli.CLIENT_ID, cli.CLIENT_SECRET, cli.BASE_URL)
FROM = "2023-11-14T22:13:20Z"


class ClientFactory:
    """Stands in for ``cli.build_client`` and records how it was called."""

    def __init__(self, client: Any) -> None:
        self.client = client
        self.calls: list[tuple[str, str, str]] = []

    def __call__(self, client_id: str, client_secret: str, base_url: str) -> Any:
        self.calls.append((client_id, client_secret, base_url))
        return self.client


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    """Run each test in an empty directory with no credential in the env."""
    monkeypatch.chdir(tmp_path)
    for key in CREDENTIAL_KEYS:
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
    factory = ClientFactory(client)
    monkeypatch.setattr(cli, "build_client", factory)
    return factory


def _run(*args: str) -> int:
    return cli.main(list(args))


def _extract(*args: str) -> int:
    return _run("extract", *args)


# --- Configuration -----------------------------------------------------------


def test_credentials_come_from_the_env_file(monkeypatch, credentials):
    factory = _install(monkeypatch, FakeIndicatorsAPI([]))
    assert _extract("--from", FROM, "--max", "5") == 0
    assert factory.calls == [("file-id", SECRET, cli.DEFAULT_BASE_URL)]


def test_environment_overrides_the_env_file(monkeypatch, credentials):
    monkeypatch.setenv(cli.CLIENT_ID, "env-id")
    monkeypatch.setenv(cli.BASE_URL, "https://api.eu-1.crowdstrike.com")
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
    monkeypatch.setenv(cli.CLIENT_ID, "env-id")
    monkeypatch.setenv(cli.CLIENT_SECRET, SECRET)
    factory = _install(monkeypatch, FakeIndicatorsAPI([]))
    assert _extract("--from", FROM, "--max", "5") == 0
    assert factory.calls == [("env-id", SECRET, cli.DEFAULT_BASE_URL)]


def test_missing_secret_exits_2_without_building_a_client(monkeypatch, capsys):
    monkeypatch.setenv(cli.CLIENT_ID, "env-id")
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


# --- Raw dump ----------------------------------------------------------------


def test_dump_raw_on_success(monkeypatch, credentials, isolated):
    api = FakeIndicatorsAPI([make_indicator(i) for i in range(3)])
    _install(monkeypatch, api)

    dump = isolated / "dumps" / "pages.json"
    assert _extract("--from", FROM, "--max", "10", "--dump-raw", str(dump)) == 0

    pages = json.loads(dump.read_text())
    # One page with the 3 rows, then the page repeating the last one.
    assert len(pages) == len(api.calls) == 2
    assert [raw["id"] for raw in pages[0]["resources"]] == ["ioc-0", "ioc-1", "ioc-2"]


def test_dump_raw_on_validation_failure(monkeypatch, credentials, isolated, capsys):
    page_1 = {"resources": [make_indicator(1)]}
    page_2 = {"resources": [make_indicator(1), make_indicator(2, _marker="bad")]}
    _install(monkeypatch, ScriptedClient([ok(page_1), ok(page_2)]))

    dump = isolated / "pages.json"
    assert _extract("--from", FROM, "--max", "10", "--dump-raw", str(dump)) == 1

    assert json.loads(dump.read_text()) == [page_1, page_2]
    assert capsys.readouterr().out == ""


def test_no_dump_without_the_option(monkeypatch, credentials, isolated):
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
    dump = isolated / "pages.json"

    args = ["--from", FROM, "--max", "5", "--log-level", "DEBUG"]
    assert _extract(*args, "--dump-raw", str(dump)) == 1

    captured = capsys.readouterr()
    assert SECRET not in captured.out
    assert SECRET not in captured.err
    assert SECRET not in dump.read_text()


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


# --- transform ---------------------------------------------------------------

SAMPLE_DOMAIN = next(
    row
    for row in load_fixture("indicators_sample.json")["resources"]
    if row["type"] == "domain"
)


@pytest.fixture
def no_api(monkeypatch):
    """Fail the test if anything tries to build a CrowdStrike client."""

    def forbidden(*args: Any) -> Any:
        raise AssertionError("transform must not build a CrowdStrike client")

    monkeypatch.setattr(cli, "build_client", forbidden)


def _transform_output(capsys) -> dict[str, Any]:
    captured = capsys.readouterr()
    return json.loads(captured.out)


def _assert_stix_of_sample(stix: dict[str, Any]) -> None:
    assert stix["type"] == "indicator"
    assert stix["name"] == SAMPLE_DOMAIN["indicator"]
    assert stix["x_crowdstrike_id"] == SAMPLE_DOMAIN["id"]
    assert stix["x_crowdstrike_marker"] == SAMPLE_DOMAIN["_marker"]


def test_transform_reads_a_file(isolated, no_api, capsys):
    (isolated / "indicator.json").write_text(json.dumps(SAMPLE_DOMAIN))

    assert _run("transform", "indicator.json") == 0

    _assert_stix_of_sample(_transform_output(capsys))


def test_transform_reads_standard_input(monkeypatch, no_api, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(SAMPLE_DOMAIN)))

    assert _run("transform") == 0

    _assert_stix_of_sample(_transform_output(capsys))


def test_transform_needs_no_configuration(isolated, no_api, capsys):
    assert not (isolated / ".env").exists()
    (isolated / "indicator.json").write_text(json.dumps(SAMPLE_DOMAIN))

    assert _run("transform", "indicator.json") == 0


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
