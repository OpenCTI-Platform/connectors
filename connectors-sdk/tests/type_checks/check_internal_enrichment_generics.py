"""Static type checks for the generic `BaseEnrichmentProcessor` and `InternalEnrichmentConnector`.

This module is checked by strict `mypy` in `tests/test_type_checks.py`, which runs it
as a subprocess and compares the reported errors with the `# E:` markers below. It is
excluded from the main `mypy .` run (see the `exclude` option of `[tool.mypy]` in
`pyproject.toml`), and is never imported nor collected by pytest: its name does not
match `python_files`.

Positive cases use `assert_type` and must produce no error.
Negative cases carry a `# E: <code>` marker, on the line `mypy` reports the error on,
with the expected `mypy` error code. An error without a marker, or a marker without
an error, makes the test fail.

Pydantic classes are never instantiated here (the pydantic `mypy` plugin synthesizes
a field-keyword `__init__`): instances are taken as function parameters.
"""

from typing import Any, assert_type

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseEnrichmentProcessor,
    BaseInternalEnrichmentConnectorSettings,
    EnrichmentMessage,
    InternalEnrichmentConnector,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import Field


class MySection(BaseConfigModel):
    """Connector specific section."""

    api_url: str = Field(default="https://example.test")


class MySettings(BaseInternalEnrichmentConnectorSettings):
    """Settings with their own section."""

    my_section: MySection = Field(default_factory=MySection)


class OtherSettings(BaseInternalEnrichmentConnectorSettings):
    """Another settings class, unrelated to `MySettings`."""

    other_section: MySection = Field(default_factory=MySection)


class LegacySettings(BaseConnectorSettings):
    """Settings that only inherit `BaseConnectorSettings` (no `max_tlp`)."""

    my_section: MySection = Field(default_factory=MySection)


class TypedProcessor(BaseEnrichmentProcessor[MySettings]):
    """Parameterized processor: `settings` is not redeclared."""

    handled_entity_types = frozenset({"IPv4-Addr"})

    def collect(self, message: EnrichmentMessage) -> Any:
        """Check the types seen through `self`."""
        assert_type(self.settings, MySettings)
        assert_type(self.settings.my_section.api_url, str)
        assert_type(self.settings.connector.max_tlp, TLPLevel)
        return None

    def transform(self, data: Any, message: EnrichmentMessage) -> list[Any]:
        """Do nothing."""
        return []


class OtherProcessor(BaseEnrichmentProcessor[OtherSettings]):
    """Parameterized processor with another settings class."""

    handled_entity_types = frozenset({"Domain-Name"})

    def collect(self, message: EnrichmentMessage) -> Any:
        """Do nothing."""
        return None

    def transform(self, data: Any, message: EnrichmentMessage) -> list[Any]:
        """Do nothing."""
        return []


class DefaultProcessor(BaseEnrichmentProcessor):
    """Unparameterized processor: the type variable uses its default."""

    handled_entity_types = frozenset({"Url"})

    def collect(self, message: EnrichmentMessage) -> Any:
        """Check the default types seen through `self`."""
        assert_type(self.settings, BaseInternalEnrichmentConnectorSettings)
        assert_type(self.settings.connector.max_tlp, TLPLevel)
        return None

    def transform(self, data: Any, message: EnrichmentMessage) -> list[Any]:
        """Do nothing."""
        return []


def check_connector_inference(settings: MySettings, processor: TypedProcessor) -> None:
    """The connector parameter is inferred from the arguments."""
    connector = InternalEnrichmentConnector(
        settings=settings, enrichment_processors=[processor]
    )
    assert_type(connector, InternalEnrichmentConnector[MySettings])
    assert_type(connector.settings, MySettings)
    assert_type(
        connector.enrichment_processors, list[BaseEnrichmentProcessor[MySettings]]
    )


def check_connector_defaults(
    settings: BaseInternalEnrichmentConnectorSettings, processor: DefaultProcessor
) -> None:
    """Unparameterized processors give the default connector parameter."""
    connector = InternalEnrichmentConnector(
        settings=settings, enrichment_processors=[processor]
    )
    assert_type(
        connector, InternalEnrichmentConnector[BaseInternalEnrichmentConnectorSettings]
    )


def check_negative_mismatching_settings(
    settings: MySettings, other: OtherProcessor
) -> None:
    """A processor parameterized with other settings is rejected."""
    InternalEnrichmentConnector(  # E: misc
        settings=settings,
        enrichment_processors=[other],
    )


def check_negative_mixed_processors(
    settings: MySettings, typed: TypedProcessor, default: DefaultProcessor
) -> None:
    """A list mixing parameterized and unparameterized processors is rejected."""
    InternalEnrichmentConnector(
        settings=settings,
        enrichment_processors=[typed, default],  # E: list-item
    )


def check_negative_legacy_settings(legacy: LegacySettings) -> None:
    """Settings that only inherit `BaseConnectorSettings` are rejected."""
    InternalEnrichmentConnector(  # E: type-var
        settings=legacy,
        enrichment_processors=[],
    )


class LegacyProcessor(BaseEnrichmentProcessor[LegacySettings]):  # E: type-var
    """Parameterizing with settings that lack `max_tlp` is rejected."""
