"""Tests for the source-independent connector CLI."""

import io
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from crowdstrike_indicators.entities.stix import CrowdStrikeStix2Indicator
from pydantic import BaseModel, Field
from stix2.v21 import Bundle, Indicator, Malware

from shared.cli import main, to_json
from shared.transformer import AbstractTransformer

CREATED = datetime(2023, 11, 14, 22, 13, 21, tzinfo=UTC)
FACTORY = "example_factory:ExampleFactory"
TOKEN = "the-example-token-value"
FROM = "2026-01-01T00:00:00Z"


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    """Run each test in an empty directory, without ``EXAMPLE_*`` variables."""
    monkeypatch.chdir(tmp_path)
    for key in ("EXAMPLE_TOKEN", "EXAMPLE_COUNT"):
        monkeypatch.delenv(key, raising=False)
    return tmp_path


@pytest.fixture
def token(monkeypatch):
    monkeypatch.setenv("EXAMPLE_TOKEN", TOKEN)


def run(*args: str, factory: str = FACTORY) -> int:
    """Run the CLI with ``--factory factory`` followed by ``args``."""
    return main(["--factory", factory, *args])


def exit_code(*args: str) -> int:
    """Run the CLI with raw ``args``; return the exit code, even from argparse."""
    try:
        return main(list(args))
    except SystemExit as error:
        return error.code


def extract(*args: str) -> int:
    return run(*args, "extract", "--from", FROM, "--max", "10")


def _dump(value: Any) -> Any:
    return json.loads(json.dumps(value, default=to_json))


# JSON form of returned values


def _indicator() -> Indicator:
    return Indicator(
        pattern="[domain-name:value = 'host.example']",
        pattern_type="stix",
        created=CREATED,
        modified=CREATED,
        valid_from=CREATED,
    )


def test_stix_object_is_its_stix_json():
    indicator = _indicator()

    dumped = _dump(indicator)

    assert dumped["type"] == "indicator"
    assert dumped["id"] == indicator.id
    assert dumped["created"] == "2023-11-14T22:13:21.000Z"


def test_custom_stix_object_and_bundle_are_stix_json():
    custom = CrowdStrikeStix2Indicator(
        pattern="[domain-name:value = 'host.example']",
        pattern_type="stix",
        valid_from=CREATED,
        x_crowdstrike_extra={"source": "test"},
    )
    bundle = Bundle(objects=[custom], allow_custom=True)

    assert _dump(custom)["x_crowdstrike_extra"] == {"source": "test"}
    dumped = _dump(bundle)
    assert dumped["type"] == "bundle"
    assert dumped["objects"][0]["id"] == custom.id


class Aliased(BaseModel):
    marker: str = Field(alias="_marker")
    tags: list[str] = Field(default_factory=list)


def test_model_is_dumped_by_alias_with_its_defaults():
    assert _dump(Aliased(_marker="m-1")) == {"_marker": "m-1", "tags": []}


@dataclass(frozen=True)
class Holder:
    indicator: Indicator
    malware: list[Malware]


def test_dataclass_is_its_fields_with_nested_values_converted():
    indicator = _indicator()
    malware = Malware(name="ExampleFamily4", is_family=True)

    dumped = _dump(Holder(indicator, [malware]))

    assert list(dumped) == ["indicator", "malware"]
    assert dumped["indicator"]["id"] == indicator.id
    assert dumped["malware"][0]["name"] == "ExampleFamily4"


def test_datetime_keeps_its_offset():
    paris = timezone(timedelta(hours=1))

    assert _dump(datetime(2026, 11, 1, 12, tzinfo=paris)) == "2026-11-01T12:00:00+01:00"


def test_unsupported_value_raises_naming_its_type():
    with pytest.raises(TypeError, match="object"):
        json.dumps(object(), default=to_json)


def test_dataclass_class_itself_is_not_converted():
    with pytest.raises(TypeError, match="type"):
        json.dumps(Holder, default=to_json)


# Example factory


def test_example_factory_honours_the_contracts(monkeypatch, tmp_path):
    from example_factory import ExampleFactory

    from shared.connector import Connector
    from shared.record_to_file import RecordToFile

    monkeypatch.setenv("EXAMPLE_TOKEN", "example-token")
    factory = ExampleFactory(env_file=None)
    connector = Connector(
        factory.create_extractor(),
        factory.create_transformers(),
        RecordToFile(tmp_path / "bundles"),
    )

    result = connector.run_once(datetime(2026, 1, 1, tzinfo=UTC), 10)

    assert result.loaded == 2


# Choosing the factory


def test_factory_path_resolves(token, capsys):
    assert run("extract", "--from", FROM, "--max", "1") == 0
    assert json.loads(capsys.readouterr().out)[0]["item"]["name"] == "item-0"


@pytest.mark.parametrize(
    ("factory", "message"),
    [
        ("example_factory", "expected MODULE:CLASS"),
        ("no_such_module:Factory", "no_such_module"),
        ("example_factory:Missing", "has no attribute Missing"),
        ("example_factory:ExampleItem", "is not a connector factory"),
        ("example_factory:T0", "is not a connector factory"),
        ("shared.factory:AbstractConnectorFactory", "abstract"),
    ],
)
def test_unusable_factory_is_a_usage_error(token, capsys, factory, message):
    code = exit_code("--factory", factory, "extract", "--from", FROM, "--max", "1")

    captured = capsys.readouterr()
    assert code == 2
    assert message in captured.err
    assert captured.out == ""


def test_missing_factory_option_is_a_usage_error(token, capsys):
    assert exit_code("extract", "--from", FROM, "--max", "1") == 2
    captured = capsys.readouterr()
    assert "--factory" in captured.err
    assert captured.out == ""


@pytest.mark.parametrize("command", [[], ["load"]])
def test_no_or_unknown_subcommand_shows_the_usage(capsys, command):
    assert exit_code("--factory", FACTORY, *command) == 2
    assert capsys.readouterr().err.startswith("usage: connector-cli")


def test_help_names_the_console_command(capsys):
    assert exit_code("--help") == 0
    assert capsys.readouterr().out.startswith("usage: connector-cli")


# Configuration


def _count(capsys) -> int:
    return len(json.loads(capsys.readouterr().out))


def test_configuration_from_the_env_file(isolated, capsys):
    (isolated / ".env").write_text(f"EXAMPLE_TOKEN={TOKEN}\nEXAMPLE_COUNT=1\n")

    assert extract() == 0
    assert _count(capsys) == 1


def test_environment_overrides_the_env_file(isolated, monkeypatch, capsys):
    (isolated / ".env").write_text(f"EXAMPLE_TOKEN={TOKEN}\nEXAMPLE_COUNT=1\n")
    monkeypatch.setenv("EXAMPLE_COUNT", "3")

    assert extract() == 0
    assert _count(capsys) == 3


def test_another_env_file_replaces_the_default_one(isolated, capsys):
    (isolated / ".env").write_text(f"EXAMPLE_TOKEN={TOKEN}\nEXAMPLE_COUNT=1\n")
    (isolated / "test.env").write_text(f"EXAMPLE_TOKEN={TOKEN}\nEXAMPLE_COUNT=3\n")

    assert extract("--env-file", "test.env") == 0
    assert _count(capsys) == 3


def test_missing_env_file_is_a_usage_error(token, capsys):
    assert (
        exit_code(
            "--factory",
            FACTORY,
            "--env-file",
            "missing.env",
            "extract",
            "--from",
            FROM,
            "--max",
            "1",
        )
        == 2
    )
    assert "missing.env" in capsys.readouterr().err


def test_configuration_error_names_the_parameter(capsys):
    assert extract() == 2

    captured = capsys.readouterr()
    assert "EXAMPLE_TOKEN" in captured.err
    assert "read from the environment, then from .env" in captured.err
    assert captured.out == ""


# Failures


def _failing_extraction(monkeypatch) -> None:
    from example_factory import ExampleExtractor

    def fail(self, from_date, max_element_count):
        try:
            raise KeyError("the root cause")
        except KeyError as error:
            raise RuntimeError("the extraction failed") from error

    monkeypatch.setattr(ExampleExtractor, "extract", fail)


def test_failure_prints_its_message_without_traceback(token, monkeypatch, capsys):
    _failing_extraction(monkeypatch)

    assert extract() == 1

    captured = capsys.readouterr()
    assert "error: the extraction failed" in captured.err
    assert "Traceback" not in captured.err
    assert captured.out == ""


def test_traceback_with_its_chained_error_at_debug(token, monkeypatch, capsys):
    _failing_extraction(monkeypatch)

    assert run("--log-level", "DEBUG", "extract", "--from", FROM, "--max", "1") == 1

    err = capsys.readouterr().err
    assert "Traceback" in err
    assert "KeyError: 'the root cause'" in err
    assert "RuntimeError: the extraction failed" in err


def test_empty_message_is_replaced_by_the_type_name(token, monkeypatch, capsys):
    from example_factory import ExampleExtractor

    def fail(self, from_date, max_element_count):
        raise RuntimeError()

    monkeypatch.setattr(ExampleExtractor, "extract", fail)

    assert extract() == 1
    assert "error: RuntimeError" in capsys.readouterr().err


def test_token_is_never_displayed_at_debug(token, monkeypatch, isolated, capsys):
    _failing_extraction(monkeypatch)
    (isolated / "invalid.json").write_text("{}")

    run("--log-level", "DEBUG", "extract", "--from", FROM, "--max", "1")
    run("--log-level", "DEBUG", "transform", "invalid.json")

    captured = capsys.readouterr()
    assert TOKEN not in captured.out
    assert TOKEN not in captured.err


# extract


def _extract_calls(monkeypatch) -> list:
    from example_factory import ExampleExtractor

    calls: list = []
    original = ExampleExtractor.extract

    def recording(self, from_date, max_element_count):
        calls.append((from_date, max_element_count))
        return original(self, from_date, max_element_count)

    monkeypatch.setattr(ExampleExtractor, "extract", recording)
    return calls


def test_naive_from_is_utc(token, monkeypatch, capsys):
    calls = _extract_calls(monkeypatch)

    assert run("extract", "--from", "2026-11-01T00:00:00", "--max", "10") == 0
    assert calls == [(datetime(2026, 11, 1, tzinfo=UTC), 10)]


@pytest.mark.parametrize(
    "arguments", [["--max", "0"], ["--max", "x"], ["--from", "yesterday"]]
)
def test_invalid_arguments_exit_2_before_extracting(
    token, monkeypatch, capsys, arguments
):
    calls = _extract_calls(monkeypatch)
    values = {"--from": FROM, "--max": "10"}
    values.update(dict(zip(arguments[::2], arguments[1::2], strict=True)))
    argv = [item for pair in values.items() for item in pair]

    assert exit_code("--factory", FACTORY, "extract", *argv) == 2
    assert calls == []
    assert capsys.readouterr().out == ""


def test_extract_prints_datetime_and_item_pairs(token, capsys):
    assert extract() == 0

    captured = capsys.readouterr()
    assert json.loads(captured.out) == [
        {
            "datetime": "2026-01-01T00:00:00+00:00",
            "item": {"name": "item-0", "_marker": "m-0", "tags": []},
        },
        {
            "datetime": "2026-01-01T01:00:00+00:00",
            "item": {"name": "item-1", "_marker": "m-1", "tags": []},
        },
    ]
    assert "Extracted 2 item(s)" in captured.err


def test_nothing_extracted_prints_an_empty_array(token, monkeypatch, capsys):
    monkeypatch.setenv("EXAMPLE_COUNT", "0")

    assert extract() == 0
    assert json.loads(capsys.readouterr().out) == []


def test_output_file_holds_what_standard_output_would(token, isolated, capsys):
    assert extract() == 0
    printed = capsys.readouterr().out

    (isolated / "out").mkdir()
    (isolated / "out" / "result.json").write_text("old")
    assert (
        run(
            "extract",
            "--from",
            FROM,
            "--max",
            "10",
            "--output",
            "out/deeper/result.json",
        )
        == 0
    )

    assert capsys.readouterr().out == ""
    assert (isolated / "out" / "deeper" / "result.json").read_text() == printed


def test_output_file_is_replaced(token, isolated, capsys):
    (isolated / "result.json").write_text("old")

    assert run("extract", "--from", FROM, "--max", "10", "--output", "result.json") == 0
    assert json.loads((isolated / "result.json").read_text())[0]["item"]


def test_no_output_file_on_failure(token, monkeypatch, isolated, capsys):
    _failing_extraction(monkeypatch)

    assert run("extract", "--from", FROM, "--max", "10", "--output", "result.json") == 1
    assert not (isolated / "result.json").exists()


# transform

STEP_HEADER = re.compile(r"^Step (\d+) - (\w+)$", re.MULTILINE)
ITEM = {"name": "item-0", "_marker": "m-0", "tags": ["a"]}


def steps(out: str) -> list[tuple[str, Any]]:
    """Split the ``transform`` output into ``(header, JSON value)`` pairs."""
    headers = list(STEP_HEADER.finditer(out))
    result = []
    for header, following in zip(headers, [*headers[1:], None], strict=True):
        end = following.start() if following else len(out)
        result.append((header.group(0), json.loads(out[header.end() : end])))
    return result


@pytest.fixture
def item_file(isolated):
    path = isolated / "item.json"
    path.write_text(json.dumps(ITEM))
    return path


def test_transform_prints_each_step(token, item_file, capsys):
    assert run("transform", "item.json") == 0

    captured = capsys.readouterr()
    (first, note), (second, bundle) = steps(captured.out)
    assert first == "Step 1 - ItemToNote"
    assert note == {"name": "item-0", "tags": ["a"]}
    assert second == "Step 2 - NoteToBundle"
    assert bundle["type"] == "bundle"
    assert bundle["objects"][0]["value"] == "item-0.example"
    assert captured.out.endswith("}\n\n")
    assert "Ran 2 step(s)" in captured.err


def test_transform_reads_standard_input(token, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(ITEM)))

    assert run("transform") == 0
    assert len(steps(capsys.readouterr().out)) == 2


def test_missing_input_file_is_a_usage_error(token, capsys):
    assert exit_code("--factory", FACTORY, "transform", "missing.json") == 2
    assert capsys.readouterr().out == ""


def test_input_that_is_not_json(token, isolated, capsys):
    (isolated / "item.json").write_text("{not json")

    assert run("transform", "item.json") == 1

    captured = capsys.readouterr()
    assert "not valid JSON" in captured.err
    assert captured.out == ""


def test_invalid_item_names_the_field(token, isolated, capsys):
    (isolated / "item.json").write_text(json.dumps({"name": "item-0"}))

    assert run("transform", "item.json") == 1

    captured = capsys.readouterr()
    assert "_marker" in captured.err
    assert captured.out == ""


def test_extract_item_is_accepted_by_transform(token, isolated, capsys):
    assert extract() == 0
    item = json.loads(capsys.readouterr().out)[0]["item"]
    (isolated / "item.json").write_text(json.dumps(item))

    assert run("transform", "item.json") == 0


def test_failing_step_keeps_the_earlier_ones(token, item_file, monkeypatch, capsys):
    from example_factory import NoteToBundle

    def fail(self, item):
        raise ValueError(f"cannot bundle {item.name}")

    monkeypatch.setattr(NoteToBundle, "convert", fail)

    assert run("transform", "item.json") == 1

    captured = capsys.readouterr()
    assert [header for header, _ in steps(captured.out)] == ["Step 1 - ItemToNote"]
    assert "error: cannot bundle item-0" in captured.err


def test_unsupported_output_type_prints_no_header(
    token, item_file, monkeypatch, capsys
):
    from example_factory import NoteToBundle

    monkeypatch.setattr(NoteToBundle, "convert", lambda self, item: object())

    assert run("transform", "item.json") == 1

    captured = capsys.readouterr()
    assert [header for header, _ in steps(captured.out)] == ["Step 1 - ItemToNote"]
    assert "object" in captured.err


def test_empty_chain_fails(token, item_file, monkeypatch, capsys):
    from example_factory import ExampleFactory

    monkeypatch.setattr(ExampleFactory, "create_transformers", lambda self: [])

    assert run("transform", "item.json") == 1
    assert "returned no transformer" in capsys.readouterr().err


class BundleToBundle(AbstractTransformer[Bundle, Bundle]):
    def convert(self, item: Bundle) -> Bundle:
        return item


def test_input_type_that_cannot_be_validated(token, item_file, monkeypatch, capsys):
    from example_factory import ExampleFactory

    monkeypatch.setattr(
        ExampleFactory, "create_transformers", lambda self: [BundleToBundle()]
    )

    assert run("transform", "item.json") == 1

    captured = capsys.readouterr()
    assert "cannot read an input of type Bundle for BundleToBundle" in captured.err
    assert captured.out == ""
