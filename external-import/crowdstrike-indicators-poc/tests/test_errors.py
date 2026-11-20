"""Tests for the source-independent errors."""

import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import pytest
from pydantic import BaseModel, ValidationError

from shared.errors import ItemConversionError, ItemValidationError, SourceAPIError

SRC_DIR = Path(__file__).resolve().parent.parent / "src"


class Record(BaseModel):
    id: str
    last_updated: datetime


def validation_failure(raw: object) -> ValidationError:
    with pytest.raises(ValidationError) as caught:
        Record.model_validate(raw)
    return caught.value


def test_shared_errors_import_without_any_source_package():
    code = (
        "import sys\n"
        "sys.modules['crowdstrike_indicators'] = None\n"
        "import shared.errors\n"
    )

    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=SRC_DIR,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


# --- SourceAPIError ----------------------------------------------------------


def test_source_api_error_carries_source_status_and_message():
    error = SourceAPIError("CrowdStrike", 403, "access denied")

    assert error.source == "CrowdStrike"
    assert error.status_code == 403
    assert error.message == "access denied"
    assert str(error) == "CrowdStrike API error 403: access denied"


# --- ItemValidationError -----------------------------------------------------


def test_item_validation_error_message_names_the_item_and_each_error():
    raw = {"id": "abc", "last_updated": "never"}
    error = ItemValidationError(
        "abc", [{"loc": ["last_updated"], "msg": "invalid datetime"}], raw
    )

    assert str(error) == (
        "Item abc failed validation (1 error(s)): last_updated: invalid datetime"
    )
    assert error.item_id == "abc"
    assert error.raw is raw


def test_item_validation_error_without_id():
    error = ItemValidationError(None, [{"loc": ["id"], "msg": "missing"}], {})

    assert str(error).startswith("Item <no id> failed validation")


def test_item_validation_error_without_location():
    error = ItemValidationError("abc", [{"loc": [], "msg": "not a dict"}], [])

    assert str(error).endswith(": <root>: not a dict")


def test_item_validation_error_location_parts_are_joined_with_dots():
    error = ItemValidationError(
        "abc",
        [
            {"loc": ["actors", 0, "name"], "msg": "missing"},
            {"loc": ["id"], "msg": "not a string"},
        ],
        {},
    )

    assert str(error) == (
        "Item abc failed validation (2 error(s)): "
        "actors.0.name: missing; id: not a string"
    )


def test_item_validation_error_built_from_a_validation_failure():
    raw = {"id": "abc", "last_updated": "never"}
    failure = validation_failure(raw)

    error = ItemValidationError.from_validation_error(failure, raw, item_id="abc")

    assert error.item_id == "abc"
    assert error.raw is raw
    assert [(entry["loc"], entry["msg"]) for entry in error.errors] == [
        (list(detail["loc"]), detail["msg"]) for detail in failure.errors()
    ]
    assert [entry["loc"] for entry in error.errors] == [["last_updated"]]
    json.dumps(error.errors)
    assert all("url" not in entry for entry in error.errors)
    assert error.__cause__ is failure


def test_item_validation_error_does_not_read_the_id_from_the_raw_record():
    raw = {"id": "abc", "last_updated": "never"}

    error = ItemValidationError.from_validation_error(validation_failure(raw), raw)

    assert error.item_id is None
    assert str(error).startswith("Item <no id> failed validation")


def test_item_validation_error_cause_survives_a_raise_without_from():
    raw = {"id": "abc", "last_updated": "never"}
    failure = validation_failure(raw)

    with pytest.raises(ItemValidationError) as caught:
        raise ItemValidationError.from_validation_error(failure, raw, item_id="abc")

    assert caught.value.__cause__ is failure


# --- ItemConversionError -----------------------------------------------------


def test_item_conversion_error_carries_id_and_reason():
    error = ItemConversionError("abc", "unsupported type email_address")

    assert error.item_id == "abc"
    assert error.reason == "unsupported type email_address"
    assert str(error) == (
        "Item abc could not be converted: unsupported type email_address"
    )
