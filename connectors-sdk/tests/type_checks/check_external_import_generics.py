"""Static type checks for the generic `BaseDataProcessor` and `ExternalImportConnector`.

This module is checked by strict `mypy` (run by `tests/conftest.py` at the end of the
pytest session, see the `exclude` option of `[tool.mypy]` in `pyproject.toml`). It is
never imported nor collected by pytest: its name does not match `python_files`.

Positive cases use `assert_type`: a wrong type makes `mypy` fail.
Negative cases carry a `# type: ignore[<code>]` with the exact error code `mypy`
reports. Under strict `warn_unused_ignores`, a rejection that is lost (the line
type-checks again) makes `mypy` fail with `unused-ignore`.

Pydantic classes are never instantiated here (the pydantic `mypy` plugin synthesizes
a field-keyword `__init__`): instances are taken as function parameters.
"""

from datetime import datetime, timedelta
from typing import Any, assert_type

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseDataProcessor,
    BaseExternalImportConnectorSettings,
    ExternalImportConnector,
    ExternalImportConnectorState,
)
from pydantic import Field


class MySection(BaseConfigModel):
    """Connector specific section."""

    api_url: str = Field(default="https://example.test")
    page_size: int = Field(default=10)


class MySettings(BaseExternalImportConnectorSettings):
    """Settings with their own section."""

    my_section: MySection = Field(default_factory=MySection)


class OtherSettings(BaseExternalImportConnectorSettings):
    """Another settings class, unrelated to `MySettings`."""

    other_section: MySection = Field(default_factory=MySection)


class LegacySettings(BaseConnectorSettings):
    """Settings that only inherit `BaseConnectorSettings` (no `duration_period`)."""

    my_section: MySection = Field(default_factory=MySection)


class MyState(ExternalImportConnectorState):
    """State with a checkpoint."""

    cursor: datetime | None = Field(default=None)


class TypedProcessor(BaseDataProcessor[MySettings, MyState]):
    """Parameterized processor: no attribute is redeclared."""

    work_name = "typed"

    def collect(self) -> list[str]:
        """Check the types seen through `self`."""
        assert_type(self.settings, MySettings)
        assert_type(self.settings.my_section, MySection)
        assert_type(self.settings.my_section.api_url, str)
        assert_type(self.settings.connector.duration_period, timedelta)
        assert_type(self.state, MyState)
        assert_type(self.state.cursor, datetime | None)
        assert_type(self.state.last_run, datetime | None)
        return []

    def transform(self, data: Any) -> list[Any]:
        """Do nothing."""
        return []


class OtherProcessor(BaseDataProcessor[OtherSettings, MyState]):
    """Parameterized processor with another settings class."""

    work_name = "other"

    def collect(self) -> list[str]:
        """Do nothing."""
        return []

    def transform(self, data: Any) -> list[Any]:
        """Do nothing."""
        return []


class DefaultProcessor(BaseDataProcessor):
    """Unparameterized processor: the type variables use their defaults."""

    work_name = "default"

    def collect(self) -> list[str]:
        """Check the default types seen through `self`."""
        assert_type(self.settings, BaseExternalImportConnectorSettings)
        assert_type(self.settings.connector.duration_period, timedelta)
        assert_type(self.state, ExternalImportConnectorState)
        assert_type(self.state.last_run, datetime | None)
        return []

    def transform(self, data: Any) -> list[Any]:
        """Do nothing."""
        return []


class RedeclaringProcessor(BaseDataProcessor):
    """Existing connector pattern: unparameterized, attributes redeclared."""

    work_name = "redeclaring"
    settings: MySettings
    state: MyState

    def collect(self) -> list[str]:
        """Check the redeclared types."""
        assert_type(self.settings, MySettings)
        assert_type(self.state, MyState)
        return []

    def transform(self, data: Any) -> list[Any]:
        """Do nothing."""
        return []


class LegacyRedeclaringProcessor(BaseDataProcessor):
    """Redeclared settings that only inherit `BaseConnectorSettings`."""

    work_name = "legacy"
    settings: LegacySettings  # type: ignore[assignment]

    def collect(self) -> list[str]:
        """Do nothing."""
        return []

    def transform(self, data: Any) -> list[Any]:
        """Do nothing."""
        return []


class MyConnector(ExternalImportConnector[MySettings, MyState]):
    """Connector subclass parameterized like its processors."""


def check_connector_inference(
    settings: MySettings, state: MyState, processor: TypedProcessor
) -> None:
    """The connector parameters are inferred from the arguments."""
    connector = ExternalImportConnector(
        settings=settings, data_processors=[processor], state=state
    )
    assert_type(connector, ExternalImportConnector[MySettings, MyState])
    assert_type(connector.settings, MySettings)
    assert_type(connector.state, MyState)
    assert_type(connector.data_processors, list[BaseDataProcessor[MySettings, MyState]])

    explicit = ExternalImportConnector[MySettings, MyState](
        settings=settings, data_processors=[processor]
    )
    assert_type(explicit, ExternalImportConnector[MySettings, MyState])

    # No `state` is passed, yet the type is `MyState`: this records the accepted
    # `cast` hole documented in the TDR
    # `2026-11-03-Generic_data_processor_and_external_import_connector.md`.
    # An `@overload` fix would legitimately change this assertion.
    subclass = MyConnector(settings=settings, data_processors=[processor])
    assert_type(subclass.state, MyState)


def check_connector_defaults(
    settings: BaseExternalImportConnectorSettings, processor: DefaultProcessor
) -> None:
    """Unparameterized processors give the default connector parameters."""
    connector = ExternalImportConnector(settings=settings, data_processors=[processor])
    assert_type(
        connector,
        ExternalImportConnector[
            BaseExternalImportConnectorSettings, ExternalImportConnectorState
        ],
    )


def check_negative_mismatching_settings(
    settings: MySettings, state: MyState, other: OtherProcessor
) -> None:
    """A processor parameterized with other settings is rejected."""
    ExternalImportConnector(  # type: ignore[misc]
        settings=settings,
        data_processors=[other],
        state=state,
    )


def check_negative_mixed_processors(
    settings: MySettings,
    state: MyState,
    typed: TypedProcessor,
    default: DefaultProcessor,
) -> None:
    """A list mixing parameterized and unparameterized processors is rejected."""
    ExternalImportConnector(
        settings=settings,
        data_processors=[typed, default],  # type: ignore[list-item]
        state=state,
    )


def check_redeclaring_processor(
    settings: MySettings, state: MyState, processor: RedeclaringProcessor
) -> None:
    """The existing pattern (redeclared attributes) is accepted, but not narrowed.

    The processor is a `BaseDataProcessor` with the default parameters, so the
    connector parameters fall back to the defaults: `settings` and `state` are
    upcast silently.
    """
    connector = ExternalImportConnector(
        settings=settings,
        data_processors=[processor],
        state=state,
    )
    assert_type(
        connector,
        ExternalImportConnector[
            BaseExternalImportConnectorSettings, ExternalImportConnectorState
        ],
    )


def check_negative_legacy_settings(legacy: LegacySettings) -> None:
    """Settings that only inherit `BaseConnectorSettings` are rejected."""
    ExternalImportConnector(  # type: ignore[type-var]
        settings=legacy,
        data_processors=[],
    )


class LegacyParameterizedProcessor(BaseDataProcessor[LegacySettings, MyState]):  # type: ignore[type-var]
    """Parameterizing with settings that lack `duration_period` is rejected."""


def check_negative_state_mismatch(
    settings: MySettings,
    processor: TypedProcessor,
    plain_state: ExternalImportConnectorState,
) -> None:
    """A state that is not the processors' state type is rejected."""
    ExternalImportConnector(  # type: ignore[misc]
        settings=settings,
        data_processors=[processor],
        state=plain_state,
    )
