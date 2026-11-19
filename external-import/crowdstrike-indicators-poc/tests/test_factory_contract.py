"""Tests for the source-independent connector factory contract."""

import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import BaseModel, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
from stix2.v21 import Bundle, DomainName

from shared.connector import Connector
from shared.extractor import AbstractExtractor
from shared.factory import AbstractConnectorFactory, ConnectorConfigurationError
from shared.loader import AbstractLoader
from shared.transformer import AbstractTransformer

T0 = datetime(2026, 1, 1, tzinfo=UTC)
SECRET = "s3cr3t-value"


class ExampleSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="EXAMPLE_", extra="ignore")

    token: SecretStr = Field(min_length=20)
    host: str
    count: int = 3


class Item(BaseModel):
    name: str


class ListExtractor(AbstractExtractor[Item]):
    def __init__(self, names: list[str]) -> None:
        self.names = names

    def extract(
        self, from_date: datetime, max_element_count: int
    ) -> list[tuple[datetime, Item]]:
        self.check_arguments(from_date, max_element_count)
        return [(T0, Item(name=name)) for name in self.names][:max_element_count]


class ItemToBundle(AbstractTransformer[Item, Bundle]):
    def convert(self, item: Item) -> Bundle:
        domain = DomainName(value=f"{item.name}.example")
        bundle_uuid = uuid.uuid5(uuid.NAMESPACE_URL, domain.value)
        return Bundle(id=f"bundle--{bundle_uuid}", objects=[domain])


class RecordingLoader(AbstractLoader):
    def __init__(self) -> None:
        self.loaded: list[Bundle] = []

    def load(self, bundle: Bundle) -> None:
        self.loaded.append(bundle)


class ExampleFactory(AbstractConnectorFactory[ExampleSettings]):
    def create_extractor(self) -> ListExtractor:
        return ListExtractor([f"{self.settings.host}-{i}" for i in range(3)])

    def create_transformers(self) -> list[AbstractTransformer]:
        return [ItemToBundle()]


VALID = {"token": "t" * 20, "host": "example"}


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    """Run each test in an empty directory, without ``EXAMPLE_*`` variables."""
    monkeypatch.chdir(tmp_path)
    for key in ("EXAMPLE_TOKEN", "EXAMPLE_HOST", "EXAMPLE_COUNT"):
        monkeypatch.delenv(key, raising=False)
    return tmp_path


def write_env(path: Path, **values: str) -> Path:
    path.write_text("".join(f"EXAMPLE_{k.upper()}={v}\n" for k, v in values.items()))
    return path


# Settings type


def test_abstract_factory_cannot_be_instantiated():
    with pytest.raises(TypeError):
        AbstractConnectorFactory()  # type: ignore[abstract]


def test_settings_type_is_read_from_the_declaration():
    factory = ExampleFactory(**VALID)

    assert isinstance(factory.settings, ExampleSettings)
    assert factory.settings.host == "example"
    assert factory.settings.count == 3


def test_factory_without_a_settings_type_is_rejected():
    class Undeclared(AbstractConnectorFactory):  # type: ignore[type-arg]
        def create_extractor(self):
            raise NotImplementedError

        def create_transformers(self):
            raise NotImplementedError

    with pytest.raises(TypeError, match="Undeclared"):
        Undeclared()


def test_settings_type_must_be_a_settings_model():
    class NotSettings(BaseModel):
        host: str

    class WrongSettings(AbstractConnectorFactory[NotSettings]):  # type: ignore[type-var]
        def create_extractor(self):
            raise NotImplementedError

        def create_transformers(self):
            raise NotImplementedError

    with pytest.raises(TypeError, match="WrongSettings"):
        WrongSettings()


# Loading


def test_value_given_to_the_factory_wins(monkeypatch, isolated):
    write_env(isolated / ".env", token="f" * 20, host="from-file")
    monkeypatch.setenv("EXAMPLE_HOST", "from-env")

    factory = ExampleFactory(host="given")

    assert factory.settings.host == "given"


def test_environment_wins_over_the_file(monkeypatch, isolated):
    write_env(isolated / ".env", token="f" * 20, host="from-file")
    monkeypatch.setenv("EXAMPLE_HOST", "from-env")

    factory = ExampleFactory()

    assert factory.settings.host == "from-env"
    assert factory.settings.token.get_secret_value() == "f" * 20


def test_values_come_from_the_default_env_file(isolated):
    write_env(isolated / ".env", token="f" * 20, host="from-file", count="7")

    factory = ExampleFactory()

    assert factory.settings.host == "from-file"
    assert factory.settings.count == 7


def test_explicit_env_file(isolated):
    path = write_env(isolated / "other.env", token="f" * 20, host="from-other")
    write_env(isolated / ".env", token="d" * 20, host="from-default")

    factory = ExampleFactory(env_file=path)

    assert factory.settings.host == "from-other"


def test_no_env_file_is_not_an_error(monkeypatch):
    monkeypatch.setenv("EXAMPLE_TOKEN", "e" * 20)
    monkeypatch.setenv("EXAMPLE_HOST", "from-env")

    factory = ExampleFactory()

    assert factory.settings.host == "from-env"


def test_env_file_none_reads_no_file(isolated):
    write_env(isolated / ".env", token="f" * 20, host="from-file")

    with pytest.raises(ConnectorConfigurationError):
        ExampleFactory(env_file=None)


# Validation


def test_missing_parameters_are_all_named_in_one_error():
    with pytest.raises(ConnectorConfigurationError) as caught:
        ExampleFactory()

    error = caught.value
    assert error.problems == [
        ("EXAMPLE_TOKEN", "missing"),
        ("EXAMPLE_HOST", "missing"),
    ]
    assert "EXAMPLE_TOKEN" in str(error)
    assert "EXAMPLE_HOST" in str(error)


def test_invalid_value_is_named_with_its_reason():
    with pytest.raises(ConnectorConfigurationError) as caught:
        ExampleFactory(**VALID, count="many")

    ((name, reason),) = caught.value.problems
    assert name == "EXAMPLE_COUNT"
    assert "integer" in reason


def test_rejected_secret_is_never_displayed():
    with pytest.raises(ConnectorConfigurationError) as caught:
        ExampleFactory(token=SECRET, host="example")

    error = caught.value
    assert error.problems[0][0] == "EXAMPLE_TOKEN"
    assert SECRET not in str(error)
    assert SECRET not in repr(error.problems)
    assert error.__cause__ is None
    assert error.__suppress_context__


def test_configuration_error_is_a_value_error():
    assert issubclass(ConnectorConfigurationError, ValueError)


def test_complete_configuration_builds_the_factory():
    factory = ExampleFactory(**VALID, count=5)

    assert factory.settings.count == 5
    assert factory.settings.token.get_secret_value() == "t" * 20


# Components


def test_components_assemble_into_a_connector():
    factory = ExampleFactory(**VALID)
    loader = RecordingLoader()

    connector = Connector(
        factory.create_extractor(), factory.create_transformers(), loader
    )
    result = connector.run_once(T0, 10)

    assert result.loaded == 3
    assert len(loader.loaded) == 3


def test_same_factory_with_two_destinations():
    factory = ExampleFactory(**VALID)
    first, second = RecordingLoader(), RecordingLoader()

    for loader in (first, second):
        Connector(
            factory.create_extractor(), factory.create_transformers(), loader
        ).run_once(T0, 10)

    assert len(first.loaded) == len(second.loaded) == 3
    assert [b.id for b in first.loaded] == [b.id for b in second.loaded]
