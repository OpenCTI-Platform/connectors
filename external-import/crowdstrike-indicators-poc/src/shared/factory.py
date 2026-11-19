"""Factory contract: build a source's components from validated settings."""

from abc import ABC, abstractmethod
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from pydantic_settings import BaseSettings

from shared.extractor import AbstractExtractor
from shared.transformer import AbstractTransformer
from shared.type_arguments import declared_types

DEFAULT_ENV_FILE = Path(".env")


class ConnectorConfigurationError(ValueError):
    """The configuration of a connector is missing parameters or holds invalid ones.

    :attr:`problems` holds one ``(parameter, reason)`` pair per parameter at
    fault, the parameter named as the user sets it (its environment variable).
    The message lists them all. Neither ever holds a rejected value, so that a
    secret given with a wrong shape is not displayed.
    """

    def __init__(self, problems: Iterable[tuple[str, str]]) -> None:
        self.problems = list(problems)
        lines = "".join(f"\n  {name}: {reason}" for name, reason in self.problems)
        super().__init__(f"invalid configuration:{lines}")

    @classmethod
    def from_validation_error(
        cls, error: ValidationError, settings_class: type[BaseSettings]
    ) -> "ConnectorConfigurationError":
        """Describe the validation failure of ``settings_class``.

        Each parameter is named by its environment variable: the settings'
        ``env_prefix`` followed by the field name, upper-cased unless the
        settings are case-sensitive.
        """
        config = settings_class.model_config
        prefix = config.get("env_prefix", "")
        case_sensitive = config.get("case_sensitive", False)
        problems = []
        for detail in error.errors(
            include_url=False, include_input=False, include_context=False
        ):
            name = prefix + ".".join(str(part) for part in detail["loc"])
            if not case_sensitive:
                name = name.upper()
            reason = "missing" if detail["type"] == "missing" else detail["msg"]
            problems.append((name, reason))
        return cls(problems)


class AbstractConnectorFactory[S: BaseSettings](ABC):
    """Build a source's extractor and chain of transformers from its settings.

    Contract every implementation honours:

    * The implementation declares its settings model as the type argument,
      ``class MyFactory(AbstractConnectorFactory[MySettings])``; the contract
      reads it from there.
    * Building the factory loads the settings, in decreasing precedence, from
      the values given to the factory, the process environment, then the
      ``.env`` file (``./.env`` unless ``env_file`` names another one; a
      missing file is not an error), and validates all of them. Any missing
      or invalid parameter raises one :class:`ConnectorConfigurationError`
      naming them all. An implementation that prepares resources in its own
      ``__init__`` (reading a dataset, for example) reports their failures
      the same way. A factory that was built holds a complete, valid
      configuration.
    * :meth:`create_extractor` and :meth:`create_transformers` build the
      components from the settings, without contacting the source.
    * The factory builds neither the loader nor the connector: the caller
      chooses the destination and assembles the connector, which checks that
      the chain fits.
    """

    def __init__(
        self, *, env_file: Path | None = DEFAULT_ENV_FILE, **overrides: Any
    ) -> None:
        """Load and validate the settings.

        :param env_file: the ``.env`` file to read, ``None`` for none.
        :param overrides: settings values, by field name, taking precedence
            over the environment and the file.
        :raises ConnectorConfigurationError: if a parameter is missing or
            invalid. The pydantic error is not chained to it, so that a
            traceback does not display the rejected values.
        :raises TypeError: if the class does not declare a settings model.
        """
        (settings_class,) = declared_types(self, AbstractConnectorFactory)
        if not (
            isinstance(settings_class, type)
            and issubclass(settings_class, BaseSettings)
        ):
            raise TypeError(
                f"{type(self).__name__} declares {settings_class!r} as its settings, "
                f"which is not a pydantic-settings BaseSettings model"
            )
        try:
            self.settings: S = settings_class(_env_file=env_file, **overrides)
        except ValidationError as error:
            raise ConnectorConfigurationError.from_validation_error(
                error, settings_class
            ) from None

    @abstractmethod
    def create_extractor(self) -> AbstractExtractor[Any]:
        """Return the source's extractor, built from the settings."""

    @abstractmethod
    def create_transformers(self) -> Sequence[AbstractTransformer[Any, Any]]:
        """Return the source's chain of transformers, in order."""
