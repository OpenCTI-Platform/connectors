"""A source-independent example connector factory, for the generic CLI tests.

Run it with ``--factory example_factory:ExampleFactory`` (``tests/`` on the
import path, as pytest puts it).
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
from stix2.v21 import Bundle, DomainName

from shared.extractor import AbstractExtractor
from shared.factory import AbstractConnectorFactory
from shared.transformer import AbstractTransformer

T0 = datetime(2026, 1, 1, tzinfo=UTC)


class ExampleSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="EXAMPLE_", extra="ignore")

    token: SecretStr = Field(min_length=1)
    count: int = Field(default=2, ge=0)


class ExampleItem(BaseModel):
    """An item with an aliased field and a defaulted one."""

    name: str
    marker: str = Field(alias="_marker")
    tags: list[str] = Field(default_factory=list)


class ExampleExtractor(AbstractExtractor[ExampleItem]):
    """Return ``count`` items, one hour apart from ``T0``."""

    def __init__(self, count: int) -> None:
        self.count = count
        self.calls: list[tuple[datetime, int]] = []

    def extract(
        self, from_date: datetime, max_element_count: int
    ) -> list[tuple[datetime, ExampleItem]]:
        self.check_arguments(from_date, max_element_count)
        self.calls.append((from_date, max_element_count))
        pairs = [
            (T0 + timedelta(hours=i), ExampleItem(name=f"item-{i}", _marker=f"m-{i}"))
            for i in range(self.count)
        ]
        return pairs[:max_element_count]


@dataclass(frozen=True)
class Note:
    name: str
    tags: list[str]


class ItemToNote(AbstractTransformer[ExampleItem, Note]):
    def convert(self, item: ExampleItem) -> Note:
        return Note(name=item.name, tags=list(item.tags))


class NoteToBundle(AbstractTransformer[Note, Bundle]):
    def convert(self, item: Note) -> Bundle:
        domain = DomainName(value=f"{item.name}.example")
        bundle_uuid = uuid.uuid5(uuid.NAMESPACE_URL, domain.value)
        return Bundle(id=f"bundle--{bundle_uuid}", objects=[domain])


class ExampleFactory(AbstractConnectorFactory[ExampleSettings]):
    def create_extractor(self) -> ExampleExtractor:
        return ExampleExtractor(self.settings.count)

    def create_transformers(self) -> list[AbstractTransformer]:
        return [ItemToNote(), NoteToBundle()]
