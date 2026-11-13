"""Tests for the source-independent transformation contract."""

import copy
import typing

import pytest
import stix2
from pydantic import BaseModel

from shared.transformer import AbstractTransformer


class Item(BaseModel):
    name: str
    tags: list[str] = []


class ItemToDomain(AbstractTransformer[Item, stix2.DomainName]):
    """Model in, stix2 object out."""

    def convert(self, item: Item) -> stix2.DomainName:
        if not item.name.endswith(".example"):
            raise ValueError(f"{item.name}: not an example domain")
        return stix2.DomainName(value=item.name)


class DomainToObjects(AbstractTransformer[stix2.DomainName, list[stix2.Note]]):
    """stix2 object in, a collection of stix2 objects out."""

    def convert(self, item: stix2.DomainName) -> list[stix2.Note]:
        return [
            stix2.Note(content=f"note {n} on {item.value}", object_refs=[item.id])
            for n in range(3)
        ]


def test_abstract_transformer_cannot_be_instantiated():
    with pytest.raises(TypeError):
        AbstractTransformer()  # type: ignore[abstract]


def test_one_item_gives_one_value():
    result = ItemToDomain().convert(Item(name="a.example"))
    assert isinstance(result, stix2.DomainName)
    assert result.value == "a.example"


def test_collection_output_holds_every_object_of_one_item():
    result = DomainToObjects().convert(stix2.DomainName(value="a.example"))
    assert isinstance(result, list)
    assert len(result) == 3


def test_non_model_output_feeds_the_next_transformer():
    domain = ItemToDomain().convert(Item(name="a.example"))
    assert not isinstance(domain, BaseModel)

    notes = DomainToObjects().convert(domain)

    assert all(note.object_refs == [domain.id] for note in notes)


def test_declared_types_can_be_read_back_to_check_a_chain():
    def type_args(transformer_class: type) -> tuple[type, type]:
        (base,) = transformer_class.__orig_bases__
        return typing.get_args(base)

    first_input, first_output = type_args(ItemToDomain)
    second_input, second_output = type_args(DomainToObjects)

    assert first_input is Item
    assert first_output is second_input is stix2.DomainName
    assert second_output == list[stix2.Note]


def test_failure_is_raised_and_names_the_item():
    with pytest.raises(ValueError, match=r"a\.invalid: not an example domain"):
        ItemToDomain().convert(Item(name="a.invalid"))


def test_input_is_left_unchanged():
    item = Item(name="a.example", tags=["x"])
    before = copy.deepcopy(item)

    ItemToDomain().convert(item)

    assert item == before
