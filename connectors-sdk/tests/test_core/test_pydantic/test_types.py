import json

from connectors_sdk.core.pydantic import ListFromString
from pydantic import BaseModel


class Model(BaseModel):
    tags: ListFromString


def test_model_validation_from_string() -> None:
    m = Model.model_validate({"tags": "a,b,c"})
    assert m.tags == ["a", "b", "c"]


def test_model_validation_from_list() -> None:
    m = Model.model_validate({"tags": ["x", "y"]})
    assert m.tags == ["x", "y"]


def test_model_serialization_default_json() -> None:
    m = Model.model_validate({"tags": ["e1", "e2"]})
    data = json.loads(m.model_dump_json())
    assert data == {"tags": ["e1", "e2"]}


def test_model_serialization_pycti_mode_json() -> None:
    m = Model.model_validate({"tags": ["e1", "e2"]})
    data = json.loads(m.model_dump_json(context={"mode": "pycti"}))
    assert data == {"tags": "e1,e2"}


def test_model_serialization_pycti_mode_empty_list() -> None:
    m = Model.model_validate({"tags": ""})  # -> []
    assert m.tags == []
    data = json.loads(m.model_dump_json(context={"mode": "pycti"}))
    assert data == {"tags": ""}  # join([]) -> ""
